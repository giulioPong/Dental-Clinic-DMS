//! Database cifrato (SQLCipher): schema, migrazioni, ricerca FTS5, cestino,
//! audit log a catena HMAC, backup cifrato.
//!
//! Cargo.toml:
//! ```toml
//! rusqlite = { version = "0.32", features = ["bundled-sqlcipher-vendored-openssl", "backup"] }
//! uuid     = { version = "1", features = ["v4"] }
//! hmac     = "0.12"
//! ```
//! La chiave del DB arriva da `crypto::Keys` (derivata dalla master key): il
//! salt Argon2 e i parametri stanno in `vault.meta`, non qui.
//!
//! NOTA: finché l'app non è in produzione, MIGRATION_V1 si può modificare
//! (cancella il .db di sviluppo e riparti). Dal primo dato reale in poi ogni
//! cambio schema = nuova voce in MIGRATIONS. Per non dimenticarlo, imposta
//! `FROZEN_V1_SHA256` (il test `migration_v1_congelata` stampa l'hash corrente).

use crate::crypto::{hex, Keys};
use hmac::{Hmac, Mac};
use rusqlite::{
    params, params_from_iter, types::Value, Connection, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};
use sha2::Sha256;
use std::{io, path::Path, time::Duration};
use zeroize::Zeroizing;

mod error;
mod schema;
mod audit;
mod patients;
mod documents;

pub use error::*;
pub use schema::*;
pub use audit::*;
pub use patients::PatientMatch;

// ───────── Utilità ─────────

pub fn new_uuid() -> String { uuid::Uuid::new_v4().to_string() }

/// Trim + maiuscolo + niente spazi interni; stringa vuota → None.
pub fn normalize_fiscal_code(raw: Option<&str>) -> Option<String> {
    raw.map(|s| s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
}

fn now(conn: &Connection) -> Result<String> {
    Ok(conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| r.get(0))?)
}

/// Data reale, >= 1900-01-01 e non futura (ora locale).
fn check_birth_date(conn: &Connection, birth: &str) -> Result<()> {
    let ok: bool = conn.query_row(
        "SELECT date(?1, '+0 days') IS NOT NULL AND date(?1, '+0 days') = ?1
                AND ?1 >= '1900-01-01' AND ?1 <= date('now','localtime')",
        params![birth],
        |r| r.get(0),
    )?;
    if ok { Ok(()) } else { Err(DbError::InvalidInput("data di nascita non valida")) }
}

fn active_patient_by_cf(conn: &Connection, cf: &str, except_id: Option<&str>) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT id FROM patients WHERE fiscal_code = ?1 AND deleted_at IS NULL AND id IS NOT ?2",
            params![cf, except_id],
            |r| r.get(0),
        )
        .optional()?)
}

// ───────── Connessione ─────────

fn apply_key(conn: &Connection, keys: &Keys) -> Result<()> {
    let k = keys.sqlcipher_key_pragma_value();
    conn.pragma_update(None, "key", k.as_str())?;
    // Senza SQLCipher `PRAGMA key` non fa nulla e il DB resterebbe in chiaro.
    let v: Option<String> = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0)).optional()?;
    if v.map_or(true, |s| s.is_empty()) {
        return Err(DbError::SqlcipherMissing);
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|_| DbError::WrongKeyOrNotDatabase)?;
    Ok(())
}

#[derive(Debug, PartialEq)]
pub struct PatientHit {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRecord {
    pub id: String,
    pub patient_id: String,
    pub original_filename: String,
    pub mime_type: String,
    pub category_tag: String,
    /// Dimensione del file in chiaro.
    pub size_bytes: u64,
    pub sha256: String,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatientRecord {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
    pub fiscal_code: Option<String>,
    pub notes: String,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashedPatient {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
    pub deleted_at: String,
    /// Documenti collegati al paziente (tornano con lui al ripristino se erano stati cestinati insieme).
    pub documents: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trash {
    pub patients: Vec<TrashedPatient>,
    /// Documenti cestinati singolarmente (non insieme a un paziente).
    pub documents: Vec<DocumentRecord>,
}

const DOC_COLS: &str =
    "id, patient_id, original_filename, mime_type, category_tag, size_bytes, sha256, created_at, deleted_at";

fn doc_from_row(r: &rusqlite::Row) -> rusqlite::Result<DocumentRecord> {
    let size: i64 = r.get(5)?;
    Ok(DocumentRecord {
        id: r.get(0)?, patient_id: r.get(1)?, original_filename: r.get(2)?, mime_type: r.get(3)?,
        category_tag: r.get(4)?, size_bytes: size as u64, sha256: r.get(6)?, created_at: r.get(7)?,
        deleted_at: r.get(8)?,
    })
}

/// Normalizza e valida nome, cognome e codice fiscale.
fn clean_patient_fields(first: &str, last: &str, fiscal_code: Option<&str>) -> Result<(String, String, Option<String>)> {
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() || last.is_empty() {
        return Err(DbError::InvalidInput("nome e cognome obbligatori"));
    }
    let cf = normalize_fiscal_code(fiscal_code);
    if let Some(cf) = &cf {
        if cf.len() != 16 || !cf.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(DbError::InvalidInput("codice fiscale non valido"));
        }
    }
    Ok((first.to_string(), last.to_string(), cf))
}

pub struct NewDocument<'a> {
    pub id: &'a str,
    pub patient_id: &'a str,
    pub original_filename: &'a str,
    pub mime_type: &'a str,
    pub category_tag: &'a str,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub documents: u32,
    pub patients: u32,
    /// File che non si sono riusciti a rimuovere: la riga resta e verrà ritentata.
    pub failed_files: u32,
}

/// Database aperto, con chiave audit e operatore corrente.
/// Non è `Sync`: mettilo in un `Mutex<Db>` nello stato di Tauri.
pub struct Db {
    conn: Connection,
    audit_key: Zeroizing<[u8; 32]>,
    actor: String,
}

impl Db {
    /// Apre un database ESISTENTE. Non lo crea mai: con un percorso sbagliato (o un
    /// file vuoto) SQLite ne creerebbe uno nuovo e vuoto, e i documenti registrati
    /// sembrerebbero spariti mentre i `.enc` restano sul disco senza record.
    pub fn open(path: &Path, keys: &Keys, actor: &str) -> Result<Db> {
        match std::fs::metadata(path) {
            Ok(m) if m.is_file() && m.len() > 0 => {}
            Ok(_) => return Err(DbError::DatabaseMissing),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(DbError::DatabaseMissing),
            Err(e) => return Err(e.into()),
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        Self::setup(conn, keys, actor, true)
    }

    /// Crea un database NUOVO (errore se il file esiste). Da usare solo al primo avvio,
    /// insieme alla creazione di `vault.meta`; il chiamante deve rifiutarsi di farlo se
    /// la cartella dei documenti contiene già file `.enc`.
    pub fn create(path: &Path, keys: &Keys, actor: &str) -> Result<Db> {
        if path.exists() {
            return Err(DbError::AlreadyExists);
        }
        let result = Connection::open(path).map_err(DbError::from).and_then(|c| Self::setup(c, keys, actor, true));
        if result.is_err() {
            for suffix in ["", "-wal", "-shm"] {
                let mut name = path.as_os_str().to_owned();
                name.push(suffix);
                let _ = std::fs::remove_file(std::path::PathBuf::from(name));
            }
        }
        result
    }

    pub fn open_in_memory(keys: &Keys, actor: &str) -> Result<Db> {
        Self::setup(Connection::open_in_memory()?, keys, actor, false)
    }

    fn setup(mut conn: Connection, keys: &Keys, actor: &str, wal: bool) -> Result<Db> {
        apply_key(&conn, keys)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        if wal {
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
            // FULL, non NORMAL: con WAL+NORMAL un blackout può perdere transazioni già
            // confermate. Qui le scritture sono poche (un paio al minuto): il costo di un
            // fsync per commit è irrilevante, e così "confermato" significa "su disco".
            conn.pragma_update(None, "synchronous", "FULL")?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Db { conn, audit_key: Zeroizing::new(*keys.audit_key()), actor: actor.to_string() })
    }

    pub fn set_actor(&mut self, actor: &str) { self.actor = actor.to_string(); }
    pub fn conn(&self) -> &Connection { &self.conn }

    /// Esegue `f` in una transazione IMMEDIATE: o tutto o niente, audit incluso.
    fn tx<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let out = f(&self.conn)?; // su Err la transazione viene annullata alla drop
        tx.commit()?;
        Ok(out)
    }

    // ───── backup ─────

    /// Copia consistente e CIFRATA con la stessa chiave (API di backup di SQLite,
    /// niente `VACUUM INTO`). `dest` non deve esistere. Non richiede di fermare l'app.
    pub fn backup_to(&self, dest: &Path, keys: &Keys) -> Result<()> {
        if dest.exists() {
            return Err(DbError::InvalidInput("la destinazione del backup esiste già"));
        }
        let result = (|| -> Result<()> {
            let mut dst = Connection::open(dest)?;
            apply_key(&dst, keys)?;
            let b = rusqlite::backup::Backup::new(&self.conn, &mut dst)?;
            b.run_to_completion(64, Duration::from_millis(5), None)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        result
    }
}

#[cfg(test)]
mod tests;
