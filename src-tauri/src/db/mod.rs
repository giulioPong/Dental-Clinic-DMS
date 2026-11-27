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

// ───────── Errori ─────────

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    /// La build non include SQLCipher: `PRAGMA key` sarebbe ignorato in silenzio
    /// e il database resterebbe in chiaro. Si rifiuta di aprirlo.
    SqlcipherMissing,
    WrongKeyOrNotDatabase,
    /// Il file del database manca o è vuoto: `open` non lo crea mai.
    DatabaseMissing,
    AlreadyExists,
    InvalidInput(&'static str),
    NotFound,
    InvalidState(&'static str),
    DuplicateFiscalCode { existing_id: String },
    PatientInTrash,
    AuditTampered(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "errore database: {e}"),
            Self::Io(e) => write!(f, "errore I/O: {e}"),
            Self::SqlcipherMissing => write!(f, "SQLCipher non disponibile in questa build"),
            Self::WrongKeyOrNotDatabase => write!(f, "chiave errata o file non è un database cifrato"),
            Self::DatabaseMissing => write!(f, "database mancante o vuoto: non viene creato automaticamente"),
            Self::AlreadyExists => write!(f, "il database esiste già"),
            Self::InvalidInput(m) => write!(f, "dato non valido: {m}"),
            Self::NotFound => write!(f, "elemento non trovato"),
            Self::InvalidState(m) => write!(f, "operazione non consentita: {m}"),
            Self::DuplicateFiscalCode { existing_id } => {
                write!(f, "esiste già una scheda con questo codice fiscale ({existing_id})")
            }
            Self::PatientInTrash => write!(f, "il paziente è nel cestino"),
            Self::AuditTampered(m) => write!(f, "audit log manomesso: {m}"),
        }
    }
}
impl std::error::Error for DbError {}
impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self { Self::Sqlite(e) }
}
impl From<io::Error> for DbError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}
pub type Result<T> = std::result::Result<T, DbError>;

// ───────── Schema ─────────

const MIGRATIONS: &[&str] = &[MIGRATION_V1];

/// Se `Some(hash)`, il test `migration_v1_congelata` fallisce quando MIGRATION_V1 cambia.
const FROZEN_V1_SHA256: Option<&str> = None;

pub const CATEGORY_TAGS: [&str; 6] = ["Panoramica", "Endorale", "Scan 3D", "Consenso", "Preventivo", "Altro"];

const MIGRATION_V1: &str = r#"
-- ───────── PAZIENTI ─────────
CREATE TABLE patients (
    id           TEXT PRIMARY KEY NOT NULL CHECK (id GLOB
        '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
    first_name   TEXT NOT NULL CHECK (length(trim(first_name)) > 0),
    last_name    TEXT NOT NULL CHECK (length(trim(last_name)) > 0),
    -- Data reale del calendario (rifiuta 30 febbraio, 29/02 di anni non bisestili,
    -- 1900-02-29...). ATTENZIONE: `date('2023-02-30')` da sola restituisce la stringa
    -- invariata (SQLite controlla solo giorno <= 31); il modificatore '+0 days' forza il
    -- ricalcolo e normalizza (-> 2023-03-02), così il confronto la scarta.
    -- `IS NOT NULL` è indispensabile: un CHECK che vale NULL passa.
    -- "Non nel futuro" si controlla in Rust (dipenderebbe dall'orologio).
    birth_date   TEXT NOT NULL CHECK (
        date(birth_date, '+0 days') IS NOT NULL AND date(birth_date, '+0 days') = birth_date
        AND birth_date >= '1900-01-01'),
    fiscal_code  TEXT CHECK (
        fiscal_code IS NULL
        OR (length(fiscal_code) = 16 AND fiscal_code = upper(fiscal_code))
    ),
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deleted_at   TEXT
);
CREATE INDEX idx_patients_deleted ON patients(deleted_at);
CREATE INDEX idx_patients_name_birth ON patients(last_name, first_name, birth_date);
CREATE UNIQUE INDEX idx_patients_cf ON patients(fiscal_code)
    WHERE fiscal_code IS NOT NULL AND deleted_at IS NULL;

-- ───────── FTS5 (external content, tokenizer trigram) ─────────
CREATE VIRTUAL TABLE patients_fts USING fts5(
    first_name, last_name, fiscal_code,
    content='patients', content_rowid='rowid',
    tokenize='trigram'
);

CREATE TRIGGER patients_ai AFTER INSERT ON patients BEGIN
    INSERT INTO patients_fts(rowid, first_name, last_name, fiscal_code)
    VALUES (new.rowid, new.first_name, new.last_name, COALESCE(new.fiscal_code,''));
END;

CREATE TRIGGER patients_ad AFTER DELETE ON patients BEGIN
    INSERT INTO patients_fts(patients_fts, rowid, first_name, last_name, fiscal_code)
    VALUES ('delete', old.rowid, old.first_name, old.last_name, COALESCE(old.fiscal_code,''));
END;

CREATE TRIGGER patients_au AFTER UPDATE OF first_name, last_name, fiscal_code ON patients BEGIN
    INSERT INTO patients_fts(patients_fts, rowid, first_name, last_name, fiscal_code)
    VALUES ('delete', old.rowid, old.first_name, old.last_name, COALESCE(old.fiscal_code,''));
    INSERT INTO patients_fts(rowid, first_name, last_name, fiscal_code)
    VALUES (new.rowid, new.first_name, new.last_name, COALESCE(new.fiscal_code,''));
END;

-- ───────── DOCUMENTI ─────────
-- Salt e nonce NON stanno qui: sono nell'header del file .enc (unica fonte di verità).
CREATE TABLE documents (
    id                TEXT PRIMARY KEY NOT NULL CHECK (id GLOB
        '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
    patient_id        TEXT NOT NULL REFERENCES patients(id) ON DELETE RESTRICT,
    original_filename TEXT NOT NULL CHECK (length(trim(original_filename)) > 0),
    mime_type         TEXT NOT NULL,
    category_tag      TEXT NOT NULL DEFAULT 'Altro'
        CHECK (category_tag IN ('Panoramica','Endorale','Scan 3D','Consenso','Preventivo','Altro')),
    -- Sempre "<id>.enc": niente percorsi arbitrari, quindi niente path traversal.
    encrypted_path    TEXT NOT NULL CHECK (encrypted_path = id || '.enc'),
    size_bytes        INTEGER NOT NULL CHECK (size_bytes >= 0),     -- file in chiaro
    sha256            TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deleted_at        TEXT,
    -- 1 = cestinato insieme al paziente (il ripristino del paziente lo riporta indietro);
    -- 0 = cestinato singolarmente (resta nel cestino anche dopo il ripristino del paziente).
    trashed_with_patient INTEGER NOT NULL DEFAULT 0
        CHECK (trashed_with_patient IN (0,1) AND (trashed_with_patient = 0 OR deleted_at IS NOT NULL))
);
CREATE INDEX idx_documents_patient ON documents(patient_id, deleted_at, created_at);

-- ───────── AUDIT LOG (append-only + catena HMAC) ─────────
-- row_hash = HMAC-SHA256(chiave audit, id | campi con lunghezza | prev_hash).
-- I trigger bloccano UPDATE/DELETE da codice; la catena rende visibili le
-- modifiche fatte aggirando i trigger (vedi verify_audit_chain).
-- details: solo ID e conteggi, mai nomi o dati clinici.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL CHECK (action IN (
        'CREATE_PATIENT','UPDATE_PATIENT','VIEW_PATIENT','DELETE_PATIENT','RESTORE_PATIENT','PURGE_PATIENT',
        'UPLOAD_FILE','OPEN_FILE','EXPORT_ZIP','DELETE_FILE','RESTORE_FILE','PURGE_FILE','REASSIGN_DOCUMENT')),
    target_id  TEXT,
    details    TEXT,
    prev_hash  TEXT NOT NULL CHECK (length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*'),
    row_hash   TEXT NOT NULL CHECK (length(row_hash) = 64 AND row_hash NOT GLOB '*[^0-9a-f]*')
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log è append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log è append-only'); END;
"#;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ───────── Audit: HMAC e checkpoint ─────────

type HmacSha256 = Hmac<Sha256>;

fn mac_field(m: &mut HmacSha256, s: &str) {
    m.update(&(s.len() as u32).to_be_bytes());
    m.update(s.as_bytes());
}

fn mac_opt(m: &mut HmacSha256, s: Option<&str>) {
    match s {
        Some(v) => { m.update(&[1]); mac_field(m, v); }
        None => m.update(&[0]),
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_mac(
    key: &[u8; 32], id: i64, ts: &str, actor: &str, action: &str,
    target: Option<&str>, details: Option<&str>, prev_hash: &str,
) -> String {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accetta chiavi di qualsiasi lunghezza");
    m.update(b"gestionale-audit-v1");
    m.update(&id.to_be_bytes());
    mac_field(&mut m, ts);
    mac_field(&mut m, actor);
    mac_field(&mut m, action);
    mac_opt(&mut m, target);
    mac_opt(&mut m, details);
    mac_field(&mut m, prev_hash);
    hex(&m.finalize().into_bytes())
}

fn checkpoint_mac(key: &[u8; 32], last_id: i64, last_hash: &str) -> String {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accetta chiavi di qualsiasi lunghezza");
    m.update(b"gestionale-audit-checkpoint-v1");
    m.update(&last_id.to_be_bytes());
    m.update(last_hash.as_bytes());
    hex(&m.finalize().into_bytes())
}

/// Punto di controllo dell'audit da conservare FUORI dal database (es. in
/// `vault/audit.checkpoint`): senza di esso un troncamento in coda al log non
/// è rilevabile. Aggiornalo al logout, ai backup e periodicamente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheckpoint {
    pub last_id: i64,
    pub last_hash: String,
    pub mac: String,
}

impl AuditCheckpoint {
    pub fn to_line(&self) -> String { format!("{}:{}:{}", self.last_id, self.last_hash, self.mac) }
    pub fn from_line(s: &str) -> Option<Self> {
        let mut it = s.trim().split(':');
        let last_id = it.next()?.parse().ok()?;
        let last_hash = it.next()?.to_string();
        let mac = it.next()?.to_string();
        if it.next().is_some() { return None; }
        Some(Self { last_id, last_hash, mac })
    }
}

type AuditRow = (i64, String, String, String, Option<String>, Option<String>, String, String);

fn verify_chain(conn: &Connection, key: &[u8; 32], cp: Option<&AuditCheckpoint>) -> Result<u64> {
    let bad = |m: String| Err(DbError::AuditTampered(m));
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, actor, action, target_id, details, prev_hash, row_hash
         FROM audit_log ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        })?
        .collect::<rusqlite::Result<Vec<AuditRow>>>()?;

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut prev_id = 0i64;
    for (id, ts, actor, action, target, details, prev_hash, row_hash) in &rows {
        if *id != prev_id + 1 {
            return bad(format!("numerazione interrotta prima della riga {id}"));
        }
        if *prev_hash != expected_prev {
            return bad(format!("catena spezzata alla riga {id}"));
        }
        let m = audit_mac(key, *id, ts, actor, action, target.as_deref(), details.as_deref(), prev_hash);
        if m != *row_hash {
            return bad(format!("contenuto della riga {id} alterato"));
        }
        expected_prev = row_hash.clone();
        prev_id = *id;
    }

    if let Some(cp) = cp {
        if checkpoint_mac(key, cp.last_id, &cp.last_hash) != cp.mac {
            return bad("checkpoint non valido".into());
        }
        if cp.last_id > prev_id {
            return bad(format!("log troncato: il checkpoint arriva alla riga {}, il log alla {prev_id}", cp.last_id));
        }
        if cp.last_id > 0 {
            let h = &rows[(cp.last_id - 1) as usize].7;
            if *h != cp.last_hash {
                return bad("il log non coincide con il checkpoint".into());
            }
        }
    }
    Ok(rows.len() as u64)
}

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

    /// Da chiamare dentro una transazione.
    fn audit_append(&self, c: &Connection, action: &str, target: Option<&str>, details: Option<&str>) -> Result<()> {
        let last: Option<String> = c
            .query_row("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .optional()?;
        // Il contatore AUTOINCREMENT sopravvive alle cancellazioni in coda: un
        // troncamento diventa un "buco" nella numerazione alla scrittura successiva.
        let seq: Option<i64> = c
            .query_row("SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'", [], |r| r.get(0))
            .optional()?;
        let id = seq.unwrap_or(0) + 1;
        let prev = last.unwrap_or_else(|| GENESIS_HASH.to_string());
        let ts = now(c)?;
        let h = audit_mac(&self.audit_key, id, &ts, &self.actor, action, target, details, &prev);
        c.execute(
            "INSERT INTO audit_log (id, timestamp, actor, action, target_id, details, prev_hash, row_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, ts, self.actor, action, target, details, prev, h],
        )?;
        Ok(())
    }

    /// Per azioni di sola lettura (VIEW_PATIENT, OPEN_FILE, EXPORT_ZIP...). `details`: solo ID/conteggi.
    pub fn log_audit(&self, action: &str, target_id: Option<&str>, details: Option<&str>) -> Result<()> {
        self.tx(|c| self.audit_append(c, action, target_id, details))
    }

    pub fn verify_audit_chain(&self, checkpoint: Option<&AuditCheckpoint>) -> Result<u64> {
        verify_chain(&self.conn, &self.audit_key, checkpoint)
    }

    pub fn audit_checkpoint(&self) -> Result<AuditCheckpoint> {
        let last: Option<(i64, String)> = self
            .conn
            .query_row("SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (last_id, last_hash) = last.unwrap_or((0, GENESIS_HASH.to_string()));
        let mac = checkpoint_mac(&self.audit_key, last_id, &last_hash);
        Ok(AuditCheckpoint { last_id, last_hash, mac })
    }

    // ───── pazienti ─────

    pub fn create_patient(&self, first: &str, last: &str, birth: &str, fiscal_code: Option<&str>) -> Result<String> {
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
        self.tx(|c| {
            check_birth_date(c, birth)?;
            if let Some(cf) = &cf {
                if let Some(existing_id) = active_patient_by_cf(c, cf, None)? {
                    return Err(DbError::DuplicateFiscalCode { existing_id });
                }
            }
            let id = new_uuid();
            c.execute(
                "INSERT INTO patients (id, first_name, last_name, birth_date, fiscal_code)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, first, last, birth, cf],
            )?;
            self.audit_append(c, "CREATE_PATIENT", Some(&id), None)?;
            Ok(id)
        })
    }

    /// Sposta nel cestino il paziente e tutti i suoi documenti attivi (stesso timestamp,
    /// così il ripristino riporta indietro solo quelli).
    pub fn soft_delete_patient(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?;
            match st {
                None => Err(DbError::NotFound),
                Some(Some(_)) => Err(DbError::InvalidState("paziente già nel cestino")),
                Some(None) => {
                    let ts = now(c)?;
                    let n = c.execute(
                        "UPDATE documents SET deleted_at = ?1, trashed_with_patient = 1
                         WHERE patient_id = ?2 AND deleted_at IS NULL",
                        params![ts, id],
                    )?;
                    c.execute("UPDATE patients SET deleted_at = ?1 WHERE id = ?2", params![ts, id])?;
                    self.audit_append(c, "DELETE_PATIENT", Some(id), Some(&format!("documents={n}")))
                }
            }
        })
    }

    /// Fallisce se nel frattempo il codice fiscale è stato usato da un altro paziente attivo.
    pub fn restore_patient(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let row: Option<(Option<String>, Option<String>)> = c
                .query_row("SELECT deleted_at, fiscal_code FROM patients WHERE id = ?1", params![id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let (ts, cf) = row.ok_or(DbError::NotFound)?;
            ts.ok_or(DbError::InvalidState("il paziente non è nel cestino"))?;
            if let Some(cf) = cf {
                if let Some(existing_id) = active_patient_by_cf(c, &cf, Some(id))? {
                    return Err(DbError::DuplicateFiscalCode { existing_id });
                }
            }
            let n = c.execute(
                "UPDATE documents SET deleted_at = NULL, trashed_with_patient = 0
                 WHERE patient_id = ?1 AND trashed_with_patient = 1",
                params![id],
            )?;
            c.execute("UPDATE patients SET deleted_at = NULL WHERE id = ?1", params![id])?;
            self.audit_append(c, "RESTORE_PATIENT", Some(id), Some(&format!("documents={n}")))
        })
    }

    /// Modifica l'anagrafica di un paziente attivo (stessi controlli della creazione).
    pub fn update_patient(
        &self, id: &str, first: &str, last: &str, birth: &str, fiscal_code: Option<&str>, notes: &str,
    ) -> Result<()> {
        let (first, last, cf) = clean_patient_fields(first, last, fiscal_code)?;
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?;
            match st {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::PatientInTrash),
                Some(None) => {}
            }
            check_birth_date(c, birth)?;
            if let Some(cf) = &cf {
                if let Some(existing_id) = active_patient_by_cf(c, cf, Some(id))? {
                    return Err(DbError::DuplicateFiscalCode { existing_id });
                }
            }
            c.execute(
                "UPDATE patients SET first_name = ?1, last_name = ?2, birth_date = ?3, fiscal_code = ?4, notes = ?5
                 WHERE id = ?6",
                params![first, last, birth, cf, notes, id],
            )?;
            self.audit_append(c, "UPDATE_PATIENT", Some(id), None)
        })
    }

    /// `Ok(true)` se il paziente esiste ed è attivo, `Ok(false)` se è nel cestino,
    /// `Err(NotFound)` se non esiste.
    pub fn patient_active(&self, id: &str) -> Result<bool> {
        let st: Option<Option<String>> = self
            .conn
            .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        st.map(|d| d.is_none()).ok_or(DbError::NotFound)
    }

    // ───── ricerca ─────

    /// - Termini >= 3 caratteri: FTS5 (sottostringa, ordinati per rank).
    /// - Termini di 1–2 caratteri: prefisso su cognome O nome (LIKE).
    /// - Più termini: tutti devono corrispondere (AND).
    pub fn search_patients(&self, input: &str, limit: u32) -> Result<Vec<PatientHit>> {
        let (long, short) = split_terms(input);
        if long.is_empty() && short.is_empty() {
            return Ok(vec![]);
        }
        let mut args: Vec<Value> = Vec::new();
        let mut sql = String::from("SELECT p.id, p.first_name, p.last_name, p.birth_date ");
        let order;
        if long.is_empty() {
            sql.push_str("FROM patients p WHERE p.deleted_at IS NULL");
            order = "ORDER BY p.last_name COLLATE NOCASE, p.first_name COLLATE NOCASE";
        } else {
            sql.push_str(
                "FROM patients_fts JOIN patients p ON p.rowid = patients_fts.rowid
                 WHERE patients_fts MATCH ? AND p.deleted_at IS NULL",
            );
            args.push(Value::Text(long.join(" ")));
            order = "ORDER BY rank";
        }
        for t in &short {
            sql.push_str(" AND (p.last_name LIKE ? OR p.first_name LIKE ?)");
            let pat = format!("{t}%");
            args.push(Value::Text(pat.clone()));
            args.push(Value::Text(pat));
        }
        sql.push_str(&format!(" {order} LIMIT ?"));
        args.push(Value::Integer(limit as i64));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            Ok(PatientHit { id: r.get(0)?, first_name: r.get(1)?, last_name: r.get(2)?, birth_date: r.get(3)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ───── documenti ─────

    /// Va chiamata DOPO che il file `<id>.enc` è stato scritto e sincronizzato su disco:
    /// il caso peggiore in un blackout è un `.enc` orfano, non una riga senza file.
    pub fn add_document(&self, d: &NewDocument) -> Result<()> {
        let name = d.original_filename.trim();
        if name.is_empty() || name.len() > 255 {
            return Err(DbError::InvalidInput("nome file non valido"));
        }
        if !CATEGORY_TAGS.contains(&d.category_tag) {
            return Err(DbError::InvalidInput("categoria non valida"));
        }
        let size = i64::try_from(d.size_bytes).map_err(|_| DbError::InvalidInput("dimensione non valida"))?;
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![d.patient_id], |r| r.get(0))
                .optional()?;
            match st {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::PatientInTrash),
                Some(None) => {}
            }
            c.execute(
                "INSERT INTO documents (id, patient_id, original_filename, mime_type, category_tag,
                                        encrypted_path, size_bytes, sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?1 || '.enc', ?6, ?7)",
                params![d.id, d.patient_id, name, d.mime_type, d.category_tag, size, hex(&d.sha256)],
            )?;
            self.audit_append(c, "UPLOAD_FILE", Some(d.id), None)
        })
    }

    pub fn soft_delete_document(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM documents WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?;
            match st {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::InvalidState("documento già nel cestino")),
                Some(None) => {}
            }
            c.execute("UPDATE documents SET deleted_at = ?1 WHERE id = ?2", params![now(c)?, id])?;
            self.audit_append(c, "DELETE_FILE", Some(id), None)
        })
    }

    /// Rifiutato se il paziente è nel cestino: va ripristinato prima il paziente.
    pub fn restore_document(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let row: Option<(Option<String>, Option<String>)> = c
                .query_row(
                    "SELECT d.deleted_at, p.deleted_at FROM documents d JOIN patients p ON p.id = d.patient_id
                     WHERE d.id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (doc_del, pat_del) = row.ok_or(DbError::NotFound)?;
            if doc_del.is_none() {
                return Err(DbError::InvalidState("il documento non è nel cestino"));
            }
            if pat_del.is_some() {
                return Err(DbError::PatientInTrash);
            }
            c.execute(
                "UPDATE documents SET deleted_at = NULL, trashed_with_patient = 0 WHERE id = ?1",
                params![id],
            )?;
            self.audit_append(c, "RESTORE_FILE", Some(id), None)
        })
    }

    /// Elimina definitivamente ciò che è nel cestino da più di `retention_days`.
    /// Ripetibile: per ogni documento prima si rimuove il file (`remove_file` riceve
    /// solo `<uuid>.enc`; "non trovato" conta come riuscito), poi la riga. Se la
    /// rimozione fallisce la riga resta e si riprova alla prossima esecuzione. I
    /// pazienti si eliminano solo quando non hanno più documenti. L'audit non si tocca.
    pub fn purge_expired(
        &self,
        retention_days: u32,
        mut remove_file: impl FnMut(&str) -> io::Result<()>,
    ) -> Result<PurgeReport> {
        let modifier = format!("-{retention_days} days");
        let mut report = PurgeReport::default();

        let docs: Vec<(String, String)> = {
            let mut st = self.conn.prepare(
                "SELECT d.id, d.encrypted_path FROM documents d JOIN patients p ON p.id = d.patient_id
                 WHERE (d.deleted_at IS NOT NULL AND d.deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?1))
                    OR (p.deleted_at IS NOT NULL AND p.deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?1))",
            )?;
            let rows = st.query_map(params![modifier], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, path) in docs {
            match remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => { report.failed_files += 1; continue; }
            }
            self.tx(|c| {
                c.execute("DELETE FROM documents WHERE id = ?1", params![id])?;
                self.audit_append(c, "PURGE_FILE", Some(&id), None)
            })?;
            report.documents += 1;
        }

        let pats: Vec<String> = {
            let mut st = self.conn.prepare(
                "SELECT id FROM patients p
                 WHERE deleted_at IS NOT NULL AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?1)
                   AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.patient_id = p.id)",
            )?;
            let rows = st.query_map(params![modifier], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for id in pats {
            self.tx(|c| {
                c.execute("DELETE FROM patients WHERE id = ?1", params![id])?;
                self.audit_append(c, "PURGE_PATIENT", Some(&id), None)
            })?;
            report.patients += 1;
        }
        Ok(report)
    }

    /// Legge un paziente (anche se nel cestino: `deleted_at` lo dice). Non scrive l'audit:
    /// per VIEW_PATIENT usa `log_audit` dal chiamante quando la scheda viene davvero aperta.
    pub fn get_patient(&self, id: &str) -> Result<PatientRecord> {
        self.conn
            .query_row(
                "SELECT id, first_name, last_name, birth_date, fiscal_code, notes, created_at, deleted_at
                 FROM patients WHERE id = ?1",
                params![id],
                |r| {
                    Ok(PatientRecord {
                        id: r.get(0)?, first_name: r.get(1)?, last_name: r.get(2)?, birth_date: r.get(3)?,
                        fiscal_code: r.get(4)?, notes: r.get(5)?, created_at: r.get(6)?, deleted_at: r.get(7)?,
                    })
                },
            )
            .optional()?
            .ok_or(DbError::NotFound)
    }

    /// Contenuto del cestino, dal più recente.
    pub fn list_trash(&self) -> Result<Trash> {
        let mut st = self.conn.prepare(
            "SELECT p.id, p.first_name, p.last_name, p.birth_date, p.deleted_at,
                    (SELECT count(*) FROM documents d WHERE d.patient_id = p.id)
             FROM patients p WHERE p.deleted_at IS NOT NULL ORDER BY p.deleted_at DESC, p.id",
        )?;
        let patients = st
            .query_map([], |r| {
                let n: i64 = r.get(5)?;
                Ok(TrashedPatient {
                    id: r.get(0)?, first_name: r.get(1)?, last_name: r.get(2)?, birth_date: r.get(3)?,
                    deleted_at: r.get(4)?, documents: n as u32,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut st = self.conn.prepare(&format!(
            "SELECT {DOC_COLS} FROM documents
             WHERE deleted_at IS NOT NULL AND trashed_with_patient = 0 ORDER BY deleted_at DESC, id"
        ))?;
        let documents = st.query_map([], doc_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Trash { patients, documents })
    }

    pub fn get_document(&self, id: &str) -> Result<DocumentRecord> {
        self.conn
            .query_row(&format!("SELECT {DOC_COLS} FROM documents WHERE id = ?1"), params![id], doc_from_row)
            .optional()?
            .ok_or(DbError::NotFound)
    }

    /// Documenti ATTIVI di un paziente, dal più recente; `tag` filtra per categoria.
    pub fn list_documents(&self, patient_id: &str, tag: Option<&str>) -> Result<Vec<DocumentRecord>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {DOC_COLS} FROM documents
             WHERE patient_id = ?1 AND deleted_at IS NULL AND (?2 IS NULL OR category_tag = ?2)
             ORDER BY created_at DESC, id"
        ))?;
        let rows = st.query_map(params![patient_id, tag], doc_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Tutti i documenti, cestinati compresi (controlli di coerenza con la cartella).
    pub fn all_documents(&self) -> Result<Vec<DocumentRecord>> {
        let mut st = self.conn.prepare(&format!("SELECT {DOC_COLS} FROM documents ORDER BY created_at, id"))?;
        let rows = st.query_map([], doc_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Sposta un documento attivo a un altro paziente attivo. Il file `.enc` non si
    /// tocca: `patient_id` non fa parte dell'AAD. In `details` solo gli id.
    pub fn reassign_document(&self, doc_id: &str, new_patient_id: &str) -> Result<()> {
        self.tx(|c| {
            let row: Option<(String, Option<String>)> = c
                .query_row("SELECT patient_id, deleted_at FROM documents WHERE id = ?1", params![doc_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let (old, deleted) = row.ok_or(DbError::NotFound)?;
            if deleted.is_some() {
                return Err(DbError::InvalidState("il documento è nel cestino"));
            }
            if old == new_patient_id {
                return Err(DbError::InvalidState("il documento è già associato a questo paziente"));
            }
            let target: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![new_patient_id], |r| r.get(0))
                .optional()?;
            match target {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::PatientInTrash),
                Some(None) => {}
            }
            c.execute("UPDATE documents SET patient_id = ?1 WHERE id = ?2", params![new_patient_id, doc_id])?;
            self.audit_append(c, "REASSIGN_DOCUMENT", Some(doc_id), Some(&format!("from={old};to={new_patient_id}")))
        })
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

fn migrate(conn: &mut Connection) -> Result<()> {
    let current: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

/// Divide l'input in termini "lunghi" (>= 3 caratteri → FTS5 trigram, già
/// racchiusi tra virgolette) e "corti" (1–2 caratteri → prefisso con LIKE,
/// dove i wildcard % e _ vengono rimossi).
fn split_terms(input: &str) -> (Vec<String>, Vec<String>) {
    let (mut long, mut short) = (Vec::new(), Vec::new());
    for t in input.split_whitespace() {
        if t.chars().count() >= 3 {
            long.push(format!("\"{}\"", t.replace('"', "\"\"")));
        } else {
            let clean: String = t.chars().filter(|c| *c != '%' && *c != '_').collect();
            if !clean.is_empty() {
                short.push(clean);
            }
        }
    }
    (long, short)
}

// ───────── TEST ─────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_vault_with_params, KdfParams};
    use sha2::Digest;
    use std::path::PathBuf;

    const CF: &str = "RSSMRA80E12A944X";

    fn keys() -> Keys {
        create_vault_with_params("password di prova", KdfParams { m_kib: 8, t: 2, p: 1 }).unwrap().keys
    }
    fn db() -> Db { Db::open_in_memory(&keys(), "admin").unwrap() }
    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("gestionale-db-{}", new_uuid()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn patient(d: &Db, first: &str, last: &str, birth: &str) -> String {
        d.create_patient(first, last, birth, None).unwrap()
    }
    fn doc(d: &Db, patient_id: &str, tag: &str) -> String {
        let id = new_uuid();
        d.add_document(&NewDocument {
            id: &id, patient_id, original_filename: "rx.jpg", mime_type: "image/jpeg",
            category_tag: tag, size_bytes: 1234, sha256: [0xAB; 32],
        })
        .unwrap();
        id
    }
    fn backdate(d: &Db, table: &str, id: &str, days: u32) {
        d.conn
            .execute(
                &format!("UPDATE {table} SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now',?1) WHERE id = ?2"),
                params![format!("-{days} days"), id],
            )
            .unwrap();
    }

    // ── SQLCipher ──

    #[test]
    fn sqlcipher_presente_e_fts5_trigram_disponibile() {
        let d = db();
        let v: String = d.conn.query_row("PRAGMA cipher_version", [], |r| r.get(0)).unwrap();
        assert!(!v.is_empty());
        patient(&d, "Mario", "Rossi", "1980-05-12");
        assert_eq!(d.search_patients("ross", 10).unwrap().len(), 1);
    }

    #[test]
    fn file_su_disco_e_cifrato_wal_compreso() {
        let dir = tmpdir();
        let k = keys();
        {
            let d = Db::create(&dir.join("t.db"), &k, "admin").unwrap();
            patient(&d, "Zxqvwk", "Qwxzvj", "1980-05-12");
            // ancora aperto: i dati possono stare nel file -wal
            let all: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
            assert!(all.iter().any(|p| p.to_string_lossy().ends_with("-wal")));
            for p in &all {
                let bytes = std::fs::read(p).unwrap();
                assert!(!bytes.windows(6).any(|w| w == b"Zxqvwk" || w == b"Qwxzvj" || w == b"zxqvwk"), "{p:?}");
                assert!(!bytes.starts_with(b"SQLite format 3"), "{p:?}");
            }
        }
        let main = std::fs::read(dir.join("t.db")).unwrap();
        assert!(!main.starts_with(b"SQLite format 3"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn riapertura_con_chiave_giusta_e_rifiuto_con_chiave_sbagliata() {
        let dir = tmpdir();
        let k = keys();
        let path = dir.join("t.db");
        {
            let d = Db::create(&path, &k, "admin").unwrap();
            patient(&d, "Mario", "Rossi", "1980-05-12");
        }
        let d = Db::open(&path, &k, "admin").unwrap();
        assert_eq!(d.search_patients("rossi", 10).unwrap().len(), 1); // indice FTS persistito
        drop(d);
        assert!(matches!(Db::open(&path, &keys(), "admin"), Err(DbError::WrongKeyOrNotDatabase)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn open_non_crea_mai_il_database() {
        let dir = tmpdir();
        let k = keys();
        let missing = dir.join("non-esiste.db");
        assert!(matches!(Db::open(&missing, &k, "admin"), Err(DbError::DatabaseMissing)));
        assert!(!missing.exists()); // nessun file creato come effetto collaterale

        let empty = dir.join("vuoto.db");
        std::fs::write(&empty, b"").unwrap();
        assert!(matches!(Db::open(&empty, &k, "admin"), Err(DbError::DatabaseMissing)));
        assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0); // e non l'ha inizializzato

        assert!(matches!(Db::open(&dir, &k, "admin"), Err(DbError::DatabaseMissing))); // una cartella

        let path = dir.join("t.db");
        drop(Db::create(&path, &k, "admin").unwrap());
        assert!(matches!(Db::create(&path, &k, "admin"), Err(DbError::AlreadyExists)));
        assert!(Db::open(&path, &k, "admin").is_ok());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn database_su_file_usa_wal_e_synchronous_full() {
        let dir = tmpdir();
        let d = Db::create(&dir.join("t.db"), &keys(), "admin").unwrap();
        let mode: String = d.conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        let sync: i64 = d.conn.query_row("PRAGMA synchronous", [], |r| r.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        assert_eq!(sync, 2); // FULL
        drop(d);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn backup_cifrato_consistente_e_apribile() {
        let dir = tmpdir();
        let k = keys();
        let d = Db::create(&dir.join("t.db"), &k, "admin").unwrap();
        let pid = patient(&d, "Mario", "Rossi", "1980-05-12");
        doc(&d, &pid, "Panoramica");
        let bk = dir.join("backup.db");
        d.backup_to(&bk, &k).unwrap();
        assert!(d.backup_to(&bk, &k).is_err()); // non sovrascrive

        let bytes = std::fs::read(&bk).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(!bytes.windows(5).any(|w| w == b"Rossi"));

        let b = Db::open(&bk, &k, "admin").unwrap();
        assert_eq!(b.search_patients("ross", 10).unwrap().len(), 1);
        assert_eq!(b.verify_audit_chain(None).unwrap(), 2);
        drop(b);
        assert!(Db::open(&bk, &keys(), "admin").is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    // ── schema / migrazioni ──

    #[test]
    fn migrazioni_idempotenti() {
        let mut d = db();
        migrate(&mut d.conn).unwrap();
        let v: usize = d.conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len());
    }

    #[test]
    fn migration_v1_congelata() {
        let h = hex(&Sha256::digest(MIGRATION_V1.as_bytes()));
        match FROZEN_V1_SHA256 {
            Some(f) => assert_eq!(h, f, "MIGRATION_V1 è congelata: crea una nuova migrazione"),
            None => eprintln!("MIGRATION_V1 sha256 = {h}"),
        }
    }

    #[test]
    fn data_di_nascita_solo_date_reali() {
        let d = db();
        let raw = |b: &str| d.conn.execute(
            "INSERT INTO patients (id, first_name, last_name, birth_date) VALUES (?1,'A','Bbb',?2)",
            params![new_uuid(), b],
        );
        for ok in ["2024-02-29", "2000-02-29", "1900-01-01", "2023-12-31"] {
            assert!(raw(ok).is_ok(), "{ok} dovrebbe essere accettata");
        }
        for bad in ["2023-02-29", "2023-02-30", "2023-02-32", "1900-02-29", "1899-12-31", "2023-13-01",
                    "2023-1-5", "05/12/1980", "not-a-date", ""] {
            assert!(raw(bad).is_err(), "{bad} dovrebbe essere rifiutata");
        }
    }

    #[test]
    fn data_futura_rifiutata_in_rust_e_oggi_accettato() {
        let d = db();
        assert!(matches!(d.create_patient("A", "Bbb", "2999-01-01", None), Err(DbError::InvalidInput(_))));
        assert!(matches!(d.create_patient("A", "Bbb", "2023-02-30", None), Err(DbError::InvalidInput(_))));
        let today: String = d.conn.query_row("SELECT date('now','localtime')", [], |r| r.get(0)).unwrap();
        assert!(d.create_patient("Neo", "Nato", &today, None).is_ok());
    }

    #[test]
    fn uuid_validati_dal_database() {
        let d = db();
        let ins = |id: &str| d.conn.execute(
            "INSERT INTO patients (id, first_name, last_name, birth_date) VALUES (?1,'A','Bbb','2000-01-01')",
            params![id],
        );
        assert!(ins("abc").is_err());
        assert!(ins("../../etc/passwd").is_err());
        assert!(ins(&new_uuid().to_uppercase()).is_err());
        assert!(ins(&new_uuid()).is_ok());
    }

    #[test]
    fn vincoli_sui_documenti() {
        let d = db();
        let pid = patient(&d, "Mario", "Rossi", "1980-05-12");
        let raw = |id: &str, path: &str, size: i64, sha: &str, tag: &str| d.conn.execute(
            "INSERT INTO documents (id, patient_id, original_filename, mime_type, category_tag, encrypted_path, size_bytes, sha256)
             VALUES (?1, ?2, 'x', 'x', ?3, ?4, ?5, ?6)",
            params![id, pid, tag, path, size, sha],
        );
        let good_sha = "a".repeat(64);
        let id = new_uuid();
        assert!(raw(&id, &format!("{id}.enc"), 10, &good_sha, "Altro").is_ok());
        let id2 = new_uuid();
        assert!(raw(&id2, "altro.enc", 10, &good_sha, "Altro").is_err()); // path ≠ id.enc
        assert!(raw(&id2, &format!("../{id2}.enc"), 10, &good_sha, "Altro").is_err());
        assert!(raw(&id2, &format!("{id2}.enc"), -1, &good_sha, "Altro").is_err());
        assert!(raw(&id2, &format!("{id2}.enc"), 10, "abc", "Altro").is_err());
        assert!(raw(&id2, &format!("{id2}.enc"), 10, &"G".repeat(64), "Altro").is_err());
        assert!(raw(&id2, &format!("{id2}.enc"), 10, &good_sha, "Boh").is_err());
        // FK
        assert!(d.conn.execute(
            "INSERT INTO documents (id, patient_id, original_filename, mime_type, encrypted_path, size_bytes, sha256)
             VALUES (?1, ?2, 'x','x', ?1 || '.enc', 1, ?3)",
            params![new_uuid(), new_uuid(), good_sha],
        ).is_err());
    }

    // ── pazienti e ricerca ──

    #[test]
    fn ricerca_per_sottostringa_case_insensitive() {
        let d = db();
        d.create_patient("Mario", "Rossi", "1980-05-12", Some(CF)).unwrap();
        patient(&d, "Luca", "Bianchi", "1975-01-02");
        assert_eq!(d.search_patients("ross", 10).unwrap().len(), 1);
        assert_eq!(d.search_patients("ROSSI mar", 10).unwrap().len(), 1);
        assert_eq!(d.search_patients("rssmra", 10).unwrap().len(), 1);
        assert!(d.search_patients("xyz", 10).unwrap().is_empty());
    }

    #[test]
    fn ricerca_con_1_o_2_caratteri_usa_il_prefisso() {
        let d = db();
        patient(&d, "Giulia", "Re", "1990-01-01");
        patient(&d, "Mario", "Rossi", "1980-05-12");
        let re = d.search_patients("re", 10).unwrap();
        assert_eq!(re.len(), 1);
        assert_eq!(re[0].last_name, "Re");
        assert_eq!(d.search_patients("R", 10).unwrap().len(), 2);
        assert_eq!(d.search_patients("ros ma", 10).unwrap().len(), 1);
        assert!(d.search_patients("%", 10).unwrap().is_empty());
        assert!(d.search_patients("   ", 10).unwrap().is_empty());
        assert!(d.search_patients("ro\"ssi OR *", 10).is_ok());
    }

    #[test]
    fn omonimi_distinguibili_per_data_nascita() {
        let d = db();
        patient(&d, "Mario", "Rossi", "1980-05-12");
        patient(&d, "Mario", "Rossi", "1962-11-30");
        let hits = d.search_patients("rossi", 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert_ne!(hits[0].birth_date, hits[1].birth_date);
    }

    #[test]
    fn indice_fts_segue_gli_update() {
        let d = db();
        let id = patient(&d, "Mario", "Rossi", "1980-05-12");
        d.conn.execute("UPDATE patients SET last_name='Verdi' WHERE id=?1", params![id]).unwrap();
        assert!(d.search_patients("rossi", 10).unwrap().is_empty());
        assert_eq!(d.search_patients("verdi", 10).unwrap().len(), 1);
    }

    #[test]
    fn codice_fiscale_normalizzato_univoco_e_validato() {
        let d = db();
        let id = d.create_patient("Mario", "Rossi", "1980-05-12", Some(" rssmra80e12a944x ")).unwrap();
        let stored: String = d.conn.query_row("SELECT fiscal_code FROM patients WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(stored, CF);
        match d.create_patient("Altro", "Paziente", "1990-01-01", Some(CF)) {
            Err(DbError::DuplicateFiscalCode { existing_id }) => assert_eq!(existing_id, id),
            other => panic!("atteso DuplicateFiscalCode, trovato {other:?}"),
        }
        assert!(d.create_patient("A", "Bbb", "1990-01-01", Some("  ")).is_ok());
        assert!(d.create_patient("C", "Ddd", "1990-01-01", Some("")).is_ok());
        assert!(matches!(d.create_patient("E", "Fff", "1990-01-01", Some("ABC")), Err(DbError::InvalidInput(_))));
        // il CHECK vale anche fuori da Rust
        let raw = |cf: &str| d.conn.execute(
            "INSERT INTO patients (id, first_name, last_name, birth_date, fiscal_code) VALUES (?1,'A','Bbb','2000-01-01',?2)",
            params![new_uuid(), cf]);
        assert!(raw("rssmra80e12a944y").is_err());
        assert!(raw("ABC").is_err());
    }

    // ── cestino ──

    #[test]
    fn cestino_paziente_con_documenti_e_ripristino() {
        let d = db();
        let pid = patient(&d, "Mario", "Rossi", "1980-05-12");
        let d1 = doc(&d, &pid, "Panoramica");
        let d2 = doc(&d, &pid, "Endorale");
        d.soft_delete_document(&d1).unwrap(); // cestinato prima, separatamente

        d.soft_delete_patient(&pid).unwrap();
        assert!(d.search_patients("rossi", 10).unwrap().is_empty());
        assert!(matches!(d.soft_delete_patient(&pid), Err(DbError::InvalidState(_))));
        assert!(matches!(d.restore_document(&d2), Err(DbError::PatientInTrash)));
        assert!(matches!(
            d.add_document(&NewDocument { id: &new_uuid(), patient_id: &pid, original_filename: "x", mime_type: "x",
                category_tag: "Altro", size_bytes: 1, sha256: [1; 32] }),
            Err(DbError::PatientInTrash)
        ));

        d.restore_patient(&pid).unwrap();
        assert_eq!(d.search_patients("rossi", 10).unwrap().len(), 1);
        let active: Vec<String> = d.conn.prepare("SELECT id FROM documents WHERE deleted_at IS NULL").unwrap()
            .query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(active, vec![d2.clone()]); // d1 resta nel cestino: era stato cestinato prima
        d.restore_document(&d1).unwrap();
        assert!(matches!(d.restore_document(&d1), Err(DbError::InvalidState(_))));
        assert_eq!(d.verify_audit_chain(None).unwrap(), 7);
    }

    #[test]
    fn ripristino_paziente_fallisce_se_il_cf_e_stato_riusato() {
        let d = db();
        let a = d.create_patient("Mario", "Rossi", "1980-05-12", Some(CF)).unwrap();
        d.soft_delete_patient(&a).unwrap();
        let b = d.create_patient("Genitore", "Rossi", "1950-01-01", Some(CF)).unwrap();
        match d.restore_patient(&a) {
            Err(DbError::DuplicateFiscalCode { existing_id }) => assert_eq!(existing_id, b),
            other => panic!("atteso DuplicateFiscalCode, trovato {other:?}"),
        }
        // l'operazione fallita non ha lasciato modifiche né audit
        let del: Option<String> = d.conn.query_row("SELECT deleted_at FROM patients WHERE id=?1", params![a], |r| r.get(0)).unwrap();
        assert!(del.is_some());
    }

    #[test]
    fn aggiunta_documento_valida_gli_input() {
        let d = db();
        let pid = patient(&d, "Mario", "Rossi", "1980-05-12");
        fn mk<'a>(id: &'a str, pid: &'a str, name: &'a str, tag: &'a str) -> NewDocument<'a> {
            NewDocument { id, patient_id: pid, original_filename: name, mime_type: "image/jpeg",
                category_tag: tag, size_bytes: 1, sha256: [1; 32] }
        }
        let id = new_uuid();
        assert!(matches!(d.add_document(&mk(&id, &pid, "  ", "Altro")), Err(DbError::InvalidInput(_))));
        assert!(matches!(d.add_document(&mk(&id, &pid, "x", "Boh")), Err(DbError::InvalidInput(_))));
        assert!(matches!(d.add_document(&mk(&id, &new_uuid(), "x", "Altro")), Err(DbError::NotFound)));
        assert!(d.add_document(&mk(&id, &pid, "x", "Scan 3D")).is_ok());
    }

    #[test]
    fn modifica_paziente_e_lettura_documenti() {
        let d = db();
        let a = d.create_patient("Mario", "Rossi", "1980-05-12", Some(CF)).unwrap();
        let b = d.create_patient("Luca", "Bianchi", "1975-01-02", Some("BNCLCU75A02A944Z")).unwrap();
        d.update_patient(&a, "Marco", "Rossetti", "1980-05-13", Some(CF), "allergia al lattice").unwrap();
        assert!(d.search_patients("rossi", 10).unwrap().is_empty()); // FTS aggiornato
        assert_eq!(d.search_patients("rossett", 10).unwrap()[0].birth_date, "1980-05-13");
        assert!(matches!(
            d.update_patient(&a, "Marco", "Rossetti", "1980-05-13", Some("BNCLCU75A02A944Z"), ""),
            Err(DbError::DuplicateFiscalCode { existing_id }) if existing_id == b
        ));
        assert!(matches!(d.update_patient(&a, "", "X", "1980-05-13", None, ""), Err(DbError::InvalidInput(_))));
        assert!(matches!(d.update_patient(&a, "M", "R", "2023-02-30", None, ""), Err(DbError::InvalidInput(_))));
        assert!(matches!(d.update_patient(&new_uuid(), "M", "R", "1980-01-01", None, ""), Err(DbError::NotFound)));
        d.soft_delete_patient(&b).unwrap();
        assert!(matches!(d.update_patient(&b, "L", "B", "1975-01-02", None, ""), Err(DbError::PatientInTrash)));

        let d1 = doc(&d, &a, "Panoramica");
        let d2 = doc(&d, &a, "Endorale");
        d.soft_delete_document(&d2).unwrap();
        assert_eq!(d.get_document(&d1).unwrap().size_bytes, 1234);
        assert_eq!(d.get_document(&d2).unwrap().deleted_at.is_some(), true);
        assert!(matches!(d.get_document(&new_uuid()), Err(DbError::NotFound)));
        assert_eq!(d.list_documents(&a, None).unwrap().len(), 1);
        assert_eq!(d.list_documents(&a, Some("Endorale")).unwrap().len(), 0);
        assert_eq!(d.list_documents(&a, Some("Panoramica")).unwrap().len(), 1);
        assert_eq!(d.all_documents().unwrap().len(), 2);
        assert_eq!(d.patient_active(&a).unwrap(), true);
        assert_eq!(d.patient_active(&b).unwrap(), false);
        assert!(matches!(d.patient_active(&new_uuid()), Err(DbError::NotFound)));
        assert_eq!(d.verify_audit_chain(None).unwrap() > 0, true);
    }

    #[test]
    fn riassegnazione_documento() {
        let d = db();
        let a = patient(&d, "Mario", "Rossi", "1980-05-12");
        let b = patient(&d, "Luca", "Bianchi", "1975-01-02");
        let c = patient(&d, "Anna", "Verdi", "1990-01-01");
        let x = doc(&d, &a, "Panoramica");
        d.reassign_document(&x, &b).unwrap();
        assert_eq!(d.get_document(&x).unwrap().patient_id, b);
        assert!(matches!(d.reassign_document(&x, &b), Err(DbError::InvalidState(_)))); // stesso paziente
        assert!(matches!(d.reassign_document(&x, &new_uuid()), Err(DbError::NotFound)));
        assert!(matches!(d.reassign_document(&new_uuid(), &a), Err(DbError::NotFound)));
        d.soft_delete_patient(&c).unwrap();
        assert!(matches!(d.reassign_document(&x, &c), Err(DbError::PatientInTrash)));
        d.soft_delete_document(&x).unwrap();
        assert!(matches!(d.reassign_document(&x, &a), Err(DbError::InvalidState(_)))); // nel cestino
        let det: String = d.conn
            .query_row("SELECT details FROM audit_log WHERE action='REASSIGN_DOCUMENT'", [], |r| r.get(0)).unwrap();
        assert_eq!(det, format!("from={a};to={b}")); // solo id, nessun dato personale
        assert!(d.verify_audit_chain(None).is_ok());
    }

    #[test]
    fn lettura_paziente_e_contenuto_del_cestino() {
        let d = db();
        let a = d.create_patient("Mario", "Rossi", "1980-05-12", Some(CF)).unwrap();
        d.update_patient(&a, "Mario", "Rossi", "1980-05-12", Some(CF), "allergia al lattice").unwrap();
        let rec = d.get_patient(&a).unwrap();
        assert_eq!((rec.last_name.as_str(), rec.notes.as_str()), ("Rossi", "allergia al lattice"));
        assert_eq!(rec.fiscal_code.as_deref(), Some(CF));
        assert!(rec.deleted_at.is_none());
        assert!(matches!(d.get_patient(&new_uuid()), Err(DbError::NotFound)));

        let b = patient(&d, "Luca", "Bianchi", "1975-01-02");
        let d_b1 = doc(&d, &b, "Panoramica");
        let d_a1 = doc(&d, &a, "Endorale");
        let d_a2 = doc(&d, &a, "Altro");
        d.soft_delete_document(&d_a1).unwrap(); // cestinato da solo
        d.soft_delete_patient(&b).unwrap(); // con il suo documento
        let t = d.list_trash().unwrap();
        assert_eq!(t.patients.len(), 1);
        assert_eq!((t.patients[0].id.as_str(), t.patients[0].documents), (b.as_str(), 1));
        assert_eq!(t.documents.len(), 1); // solo d_a1: d_b1 è cestinato insieme al paziente
        assert_eq!(t.documents[0].id, d_a1);
        assert!(d.get_patient(&b).unwrap().deleted_at.is_some());
        let _ = (d_b1, d_a2);
        assert_eq!(d.list_trash().unwrap().patients[0].documents, 1);
    }

    // ── purge ──

    #[test]
    fn purge_elimina_solo_il_cestino_scaduto_ed_e_ripetibile() {
        let d = db();
        // P1: attivo, un documento cestinato da 40 giorni e uno attivo
        let p1 = patient(&d, "Attivo", "Uno", "1980-01-01");
        let p1_old = doc(&d, &p1, "Panoramica");
        let p1_live = doc(&d, &p1, "Endorale");
        d.soft_delete_document(&p1_old).unwrap();
        backdate(&d, "documents", &p1_old, 40);
        // P2: cestinato da 40 giorni con un documento (cestinato con lui)
        let p2 = patient(&d, "Vecchio", "Due", "1980-01-01");
        let p2_doc = doc(&d, &p2, "Consenso");
        d.soft_delete_patient(&p2).unwrap();
        backdate(&d, "patients", &p2, 40);
        backdate(&d, "documents", &p2_doc, 40);
        // P3: cestinato da 5 giorni
        let p3 = patient(&d, "Recente", "Tre", "1980-01-01");
        let p3_doc = doc(&d, &p3, "Altro");
        d.soft_delete_patient(&p3).unwrap();
        backdate(&d, "patients", &p3, 5);
        backdate(&d, "documents", &p3_doc, 5);
        // P4: vecchio, ma la rimozione del file fallisce
        let p4 = patient(&d, "Bloccato", "Quattro", "1980-01-01");
        let p4_doc = doc(&d, &p4, "Altro");
        d.soft_delete_patient(&p4).unwrap();
        backdate(&d, "patients", &p4, 40);
        backdate(&d, "documents", &p4_doc, 40);

        let mut removed: Vec<String> = Vec::new();
        let blocked = format!("{p4_doc}.enc");
        let r = d.purge_expired(30, |name| {
            if name == blocked { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "occupato")); }
            removed.push(name.to_string());
            Ok(())
        }).unwrap();
        assert_eq!(r, PurgeReport { documents: 2, patients: 1, failed_files: 1 });
        removed.sort();
        let mut expected = vec![format!("{p1_old}.enc"), format!("{p2_doc}.enc")];
        expected.sort();
        assert_eq!(removed, expected);

        let count = |sql: &str| -> i64 { d.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM patients"), 3); // p1, p3, p4
        assert_eq!(count("SELECT count(*) FROM documents"), 3); // p1_live, p3_doc, p4_doc
        let _ = p1_live;

        // seconda esecuzione: ora il file di p4 è rimovibile ("non trovato" conta come ok)
        let r2 = d.purge_expired(30, |_| Err(io::Error::new(io::ErrorKind::NotFound, "già assente"))).unwrap();
        assert_eq!(r2, PurgeReport { documents: 1, patients: 1, failed_files: 0 });
        assert_eq!(count("SELECT count(*) FROM patients"), 2);
        assert!(d.verify_audit_chain(None).is_ok()); // l'audit resta integro e non viene toccato
        let purges: i64 = count("SELECT count(*) FROM audit_log WHERE action LIKE 'PURGE_%'");
        assert_eq!(purges, 5);
    }

    // ── audit ──

    fn db_with_audit() -> Db {
        let d = db();
        let p = patient(&d, "Mario", "Rossi", "1980-05-12");
        d.log_audit("VIEW_PATIENT", Some(&p), None).unwrap();
        d.log_audit("OPEN_FILE", Some("x"), Some("viewer")).unwrap();
        d.log_audit("EXPORT_ZIP", Some(&p), None).unwrap();
        d
    }
    fn tamper(d: &Db, sql: &str) {
        d.conn.execute_batch("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;").unwrap();
        d.conn.execute_batch(sql).unwrap();
    }

    #[test]
    fn audit_catena_valida_e_trigger_append_only() {
        let d = db_with_audit();
        assert_eq!(d.verify_audit_chain(None).unwrap(), 4);
        assert!(d.verify_audit_chain(Some(&d.audit_checkpoint().unwrap())).is_ok());
        assert!(d.conn.execute("UPDATE audit_log SET details='x'", []).is_err());
        assert!(d.conn.execute("DELETE FROM audit_log", []).is_err());
        assert!(d.log_audit("AZIONE_INVENTATA", None, None).is_err());
        assert_eq!(d.verify_audit_chain(None).unwrap(), 4); // l'insert fallito non ha lasciato nulla
        let actor: String = d.conn.query_row("SELECT actor FROM audit_log LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(actor, "admin");
    }

    #[test]
    fn audit_rileva_modifica_cancellazione_e_buchi() {
        let d = db_with_audit();
        tamper(&d, "UPDATE audit_log SET details='falso' WHERE id=2");
        assert!(matches!(d.verify_audit_chain(None), Err(DbError::AuditTampered(_))));

        let d = db_with_audit();
        tamper(&d, "DELETE FROM audit_log WHERE id=2");
        assert!(matches!(d.verify_audit_chain(None), Err(DbError::AuditTampered(_))));

        let d = db_with_audit();
        tamper(&d, "DELETE FROM audit_log WHERE id=1"); // testa del log
        assert!(matches!(d.verify_audit_chain(None), Err(DbError::AuditTampered(_))));

        // anche ricalcolando row_hash senza la chiave non si riesce a falsificare
        let d = db_with_audit();
        tamper(&d, &format!("UPDATE audit_log SET details='falso', row_hash='{}' WHERE id=3", "b".repeat(64)));
        assert!(matches!(d.verify_audit_chain(None), Err(DbError::AuditTampered(_))));
    }

    #[test]
    fn audit_troncamento_in_coda_visibile_solo_con_checkpoint_o_alla_scrittura_successiva() {
        let d = db_with_audit();
        let cp = d.audit_checkpoint().unwrap();
        assert_eq!(cp.last_id, 4);
        let line = cp.to_line();
        assert_eq!(AuditCheckpoint::from_line(&line), Some(cp.clone()));

        tamper(&d, "DELETE FROM audit_log WHERE id=4");
        assert_eq!(d.verify_audit_chain(None).unwrap(), 3); // da solo il log sembra valido...
        assert!(matches!(d.verify_audit_chain(Some(&cp)), Err(DbError::AuditTampered(_)))); // ...col checkpoint no

        // alla scrittura successiva il contatore AUTOINCREMENT crea un buco
        d.conn.execute_batch(
            "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'x'); END;").unwrap();
        d.log_audit("VIEW_PATIENT", None, None).unwrap();
        assert!(matches!(d.verify_audit_chain(None), Err(DbError::AuditTampered(_))));
    }

    #[test]
    fn audit_checkpoint_e_chiave_errata_non_validano() {
        let d = db_with_audit();
        let mut cp = d.audit_checkpoint().unwrap();
        cp.mac = "0".repeat(64);
        assert!(matches!(d.verify_audit_chain(Some(&cp)), Err(DbError::AuditTampered(_))));
        assert!(verify_chain(&d.conn, &[9u8; 32], None).is_err()); // chiave audit diversa
        assert!(AuditCheckpoint::from_line("non un checkpoint").is_none());
    }

    #[test]
    fn audit_su_log_vuoto_e_actor_personalizzato() {
        let mut d = db();
        assert_eq!(d.verify_audit_chain(None).unwrap(), 0);
        let cp = d.audit_checkpoint().unwrap();
        assert_eq!(cp.last_id, 0);
        assert!(d.verify_audit_chain(Some(&cp)).is_ok());
        d.set_actor("segreteria");
        d.log_audit("VIEW_PATIENT", None, None).unwrap();
        let actor: String = d.conn.query_row("SELECT actor FROM audit_log", [], |r| r.get(0)).unwrap();
        assert_eq!(actor, "segreteria");
    }
}