//! Modulo database: schema, migrazioni, ricerca FTS5.
//!
//! Cargo.toml:
//! ```toml
//! rusqlite = { version = "0.32", features = ["bundled"] } # bundled include FTS5
//! uuid     = { version = "1", features = ["v4"] }
//! ```
//!
//! NOTA: finché l'app non è in produzione, MIGRATION_V1 si può modificare
//! (cancella il .db di sviluppo e riparti). Dal primo dato reale in poi
//! ogni cambio schema = nuova voce in MIGRATIONS, mai modificare le vecchie.

use rusqlite::{Connection, OptionalExtension, Result, params, params_from_iter, types::Value};
use std::{path::Path, time::Duration};

const MIGRATIONS: &[&str] = &[MIGRATION_V1];

const MIGRATION_V1: &str = r#"
-- ───────── CONFIGURAZIONE / METADATI CRITTOGRAFICI ─────────
-- Chiavi previste (valori NON segreti, ma indispensabili):
--   argon2_salt       salt casuale per la derivazione della chiave
--   argon2_params     costi usati (m, t, p) + versione del formato
--   key_check_token   nonce || ciphertext || tag di un testo noto, cifrato con
--                     la chiave derivata: se la decifratura fallisce, la
--                     password è errata (il tag GCM autentica)
CREATE TABLE app_config (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);

-- ───────── PAZIENTI ─────────
CREATE TABLE patients (
    id           TEXT PRIMARY KEY NOT NULL,            -- UUID v4
    first_name   TEXT NOT NULL CHECK (length(trim(first_name)) > 0),
    last_name    TEXT NOT NULL CHECK (length(trim(last_name)) > 0),
    birth_date   TEXT NOT NULL,                        -- ISO 8601: YYYY-MM-DD
    fiscal_code  TEXT CHECK (
        fiscal_code IS NULL
        OR (length(fiscal_code) = 16 AND fiscal_code = upper(fiscal_code))
    ),                                                 -- normalizzato in Rust
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deleted_at   TEXT                                  -- soft delete
);
CREATE INDEX idx_patients_deleted ON patients(deleted_at);
CREATE INDEX idx_patients_name_birth ON patients(last_name, first_name, birth_date);
-- Un CF può comparire una sola volta tra i pazienti non nel cestino.
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
CREATE TABLE documents (
    id                TEXT PRIMARY KEY NOT NULL,       -- UUID v4
    patient_id        TEXT NOT NULL REFERENCES patients(id) ON DELETE RESTRICT,
    original_filename TEXT NOT NULL,
    mime_type         TEXT NOT NULL,
    category_tag      TEXT NOT NULL DEFAULT 'Altro'
        CHECK (category_tag IN ('Panoramica','Endorale','Scan 3D','Consenso','Preventivo','Altro')),
    encrypted_path    TEXT NOT NULL UNIQUE,            -- es. "<uuid>.enc"
    nonce             BLOB NOT NULL CHECK (length(nonce) = 12),  -- AES-GCM 96 bit
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deleted_at        TEXT
);
CREATE INDEX idx_documents_patient ON documents(patient_id, deleted_at, created_at);

-- ───────── AUDIT LOG (append-only) ─────────
-- Il CHECK su `action` non si può modificare senza ricostruire la tabella,
-- per questo l'elenco è già completo (incluso il ciclo cestino/ripristino).
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor      TEXT NOT NULL DEFAULT 'admin',
    action     TEXT NOT NULL CHECK (action IN (
        'CREATE_PATIENT','UPDATE_PATIENT','VIEW_PATIENT','DELETE_PATIENT','RESTORE_PATIENT',
        'UPLOAD_FILE','OPEN_FILE','EXPORT_ZIP','DELETE_FILE','RESTORE_FILE')),
    target_id  TEXT,
    details    TEXT                                    -- solo ID/metadati, mai dati clinici
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log è append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log è append-only'); END;
"#;

// ───────── APERTURA ─────────

pub fn open(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path)?;
    // busy_timeout per primo: anche il cambio di journal_mode può richiedere un lock.
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    init(&mut conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    init(&mut conn)?;
    Ok(conn)
}

fn init(conn: &mut Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(conn)
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

// ───────── CONFIG (salt Argon2, token di verifica) ─────────

pub fn get_config(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT value FROM app_config WHERE key = ?1",
        params![key],
        |r| r.get(0),
    )
    .optional()
}

/// Scrive una chiave SOLO se non esiste ancora (errore se già presente):
/// sovrascrivere per sbaglio `argon2_salt` renderebbe illeggibili tutti i file.
pub fn set_config_once(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO app_config (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

// ───────── PAZIENTI ─────────

#[derive(Debug, PartialEq)]
pub struct PatientHit {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
}

/// Trim + maiuscolo + niente spazi interni; stringa vuota → None.
pub fn normalize_fiscal_code(raw: Option<&str>) -> Option<String> {
    raw.map(|s| {
        s.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase()
    })
    .filter(|s| !s.is_empty())
}

pub fn insert_patient(
    conn: &Connection,
    first: &str,
    last: &str,
    birth: &str,
    fiscal_code: Option<&str>,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO patients (id, first_name, last_name, birth_date, fiscal_code)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            first.trim(),
            last.trim(),
            birth,
            normalize_fiscal_code(fiscal_code)
        ],
    )?;
    Ok(id)
}

pub fn soft_delete_patient(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE patients SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn log_audit(
    conn: &Connection,
    actor: &str,
    action: &str,
    target_id: Option<&str>,
    details: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_log (actor, action, target_id, details) VALUES (?1, ?2, ?3, ?4)",
        params![actor, action, target_id, details],
    )?;
    Ok(())
}

// ───────── RICERCA ─────────

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

/// - Termini >= 3 caratteri: FTS5 (sottostringa, ordinati per rank).
/// - Termini di 1–2 caratteri: prefisso su cognome O nome (LIKE).
/// - Più termini: tutti devono corrispondere (AND).
/// Con soli termini corti si fa una scansione della tabella: con migliaia di
/// righe è istantanea e non serve un indice dedicato.
pub fn search_patients(conn: &Connection, input: &str, limit: u32) -> Result<Vec<PatientHit>> {
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

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args), |r| {
        Ok(PatientHit {
            id: r.get(0)?,
            first_name: r.get(1)?,
            last_name: r.get(2)?,
            birth_date: r.get(3)?,
        })
    })?;
    rows.collect()
}

// ───────── TEST ─────────
#[cfg(test)]
mod tests {
    use super::*;

    const CF: &str = "RSSMRA80E12A944X";

    fn db() -> Connection {
        open_in_memory().unwrap()
    }

    #[test]
    fn migrazioni_idempotenti() {
        let mut c = db();
        migrate(&mut c).unwrap();
        let v: usize = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, MIGRATIONS.len());
    }

    #[test]
    fn ricerca_per_sottostringa_case_insensitive() {
        let c = db();
        insert_patient(&c, "Mario", "Rossi", "1980-05-12", Some(CF)).unwrap();
        insert_patient(&c, "Luca", "Bianchi", "1975-01-02", None).unwrap();
        assert_eq!(search_patients(&c, "ross", 10).unwrap().len(), 1);
        assert_eq!(search_patients(&c, "ROSSI mar", 10).unwrap().len(), 1);
        assert_eq!(search_patients(&c, "rssmra", 10).unwrap().len(), 1); // codice fiscale
        assert!(search_patients(&c, "xyz", 10).unwrap().is_empty());
    }

    #[test]
    fn ricerca_con_1_o_2_caratteri_usa_il_prefisso() {
        let c = db();
        insert_patient(&c, "Giulia", "Re", "1990-01-01", None).unwrap();
        insert_patient(&c, "Mario", "Rossi", "1980-05-12", None).unwrap();
        let re = search_patients(&c, "re", 10).unwrap();
        assert_eq!(re.len(), 1);
        assert_eq!(re[0].last_name, "Re");
        assert_eq!(search_patients(&c, "R", 10).unwrap().len(), 2);
        assert_eq!(search_patients(&c, "ros ma", 10).unwrap().len(), 1); // FTS + prefisso
        assert!(search_patients(&c, "%", 10).unwrap().is_empty()); // wildcard neutralizzato
        assert!(search_patients(&c, "   ", 10).unwrap().is_empty());
    }

    #[test]
    fn omonimi_distinguibili_per_data_nascita() {
        let c = db();
        insert_patient(&c, "Mario", "Rossi", "1980-05-12", None).unwrap();
        insert_patient(&c, "Mario", "Rossi", "1962-11-30", None).unwrap();
        let hits = search_patients(&c, "rossi", 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert_ne!(hits[0].birth_date, hits[1].birth_date);
    }

    #[test]
    fn soft_delete_esclude_dai_risultati() {
        let c = db();
        let id = insert_patient(&c, "Mario", "Rossi", "1980-05-12", None).unwrap();
        soft_delete_patient(&c, &id).unwrap();
        assert!(search_patients(&c, "rossi", 10).unwrap().is_empty());
        assert!(search_patients(&c, "ma", 10).unwrap().is_empty());
    }

    #[test]
    fn indice_fts_segue_gli_update() {
        let c = db();
        let id = insert_patient(&c, "Mario", "Rossi", "1980-05-12", None).unwrap();
        c.execute(
            "UPDATE patients SET last_name='Verdi' WHERE id=?1",
            params![id],
        )
        .unwrap();
        assert!(search_patients(&c, "rossi", 10).unwrap().is_empty());
        assert_eq!(search_patients(&c, "verdi", 10).unwrap().len(), 1);
    }

    #[test]
    fn query_con_caratteri_speciali_non_rompe_la_ricerca() {
        let c = db();
        assert!(search_patients(&c, "ro\"ssi OR *", 10).is_ok());
        assert!(search_patients(&c, "\"", 10).is_ok());
    }

    #[test]
    fn codice_fiscale_normalizzato_e_univoco() {
        let c = db();
        let id = insert_patient(
            &c,
            "Mario",
            "Rossi",
            "1980-05-12",
            Some(" rssmra80e12a944x "),
        )
        .unwrap();
        let stored: String = c
            .query_row(
                "SELECT fiscal_code FROM patients WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, CF);

        // duplicato tra pazienti attivi → rifiutato
        assert!(insert_patient(&c, "Altro", "Paziente", "1990-01-01", Some(CF)).is_err());
        // stringa vuota → NULL, quindi non confligge
        assert!(insert_patient(&c, "A", "Bbb", "1990-01-01", Some("  ")).is_ok());
        assert!(insert_patient(&c, "C", "Ddd", "1990-01-01", Some("")).is_ok());
        // dopo il soft delete il CF si libera
        soft_delete_patient(&c, &id).unwrap();
        assert!(insert_patient(&c, "Altro", "Paziente", "1990-01-01", Some(CF)).is_ok());
    }

    #[test]
    fn check_sul_codice_fiscale_vale_anche_fuori_da_rust() {
        let c = db();
        let raw = |cf: &str| {
            c.execute(
                "INSERT INTO patients (id, first_name, last_name, birth_date, fiscal_code)
             VALUES (?1, 'A', 'Bbb', '2000-01-01', ?2)",
                params![uuid::Uuid::new_v4().to_string(), cf],
            )
        };
        assert!(raw("ABC").is_err()); // lunghezza errata
        assert!(raw("rssmra80e12a944x").is_err()); // minuscolo
        assert!(raw(CF).is_ok());
    }

    #[test]
    fn nonce_deve_essere_12_byte() {
        let c = db();
        let pid = insert_patient(&c, "Mario", "Rossi", "1980-05-12", None).unwrap();
        let ins = |nonce: Vec<u8>, path: &str| {
            c.execute(
            "INSERT INTO documents (id, patient_id, original_filename, mime_type, category_tag, encrypted_path, nonce)
             VALUES (?1, ?2, 'rx.jpg', 'image/jpeg', 'Panoramica', ?3, ?4)",
            params![uuid::Uuid::new_v4().to_string(), pid, path, nonce],
        )
        };
        assert!(ins(vec![0u8; 12], "a.enc").is_ok());
        assert!(ins(vec![0u8; 8], "b.enc").is_err());
    }

    #[test]
    fn tag_non_valido_rifiutato_e_fk_attiva() {
        let c = db();
        let r = c.execute(
            "INSERT INTO documents (id, patient_id, original_filename, mime_type, category_tag, encrypted_path, nonce)
             VALUES ('d1','inesistente','x','x','Altro','z.enc', zeroblob(12))", [],
        );
        assert!(r.is_err()); // FK violata
        let pid = insert_patient(&c, "A", "Bbb", "2000-01-01", None).unwrap();
        let r = c.execute(
            "INSERT INTO documents (id, patient_id, original_filename, mime_type, category_tag, encrypted_path, nonce)
             VALUES ('d2', ?1,'x','x','Boh','y.enc', zeroblob(12))", params![pid],
        );
        assert!(r.is_err()); // tag non ammesso
    }

    #[test]
    fn audit_log_append_only_con_actor() {
        let c = db();
        log_audit(&c, "admin", "OPEN_FILE", Some("doc-1"), Some("viewer")).unwrap();
        for a in ["CREATE_PATIENT", "DELETE_PATIENT", "RESTORE_FILE"] {
            log_audit(&c, "segreteria", a, None, None).unwrap();
        }
        // actor ha default 'admin' anche per inserimenti che lo omettono
        c.execute("INSERT INTO audit_log (action) VALUES ('VIEW_PATIENT')", [])
            .unwrap();
        let actor: String = c
            .query_row(
                "SELECT actor FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(actor, "admin");

        assert!(c.execute("UPDATE audit_log SET details='x'", []).is_err());
        assert!(c.execute("DELETE FROM audit_log", []).is_err());
        assert!(log_audit(&c, "admin", "AZIONE_INVENTATA", None, None).is_err());
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn config_scrivibile_una_sola_volta() {
        let c = db();
        assert_eq!(get_config(&c, "argon2_salt").unwrap(), None);
        set_config_once(&c, "argon2_salt", &[1, 2, 3, 4]).unwrap();
        assert_eq!(
            get_config(&c, "argon2_salt").unwrap(),
            Some(vec![1, 2, 3, 4])
        );
        assert!(set_config_once(&c, "argon2_salt", &[9, 9]).is_err()); // niente sovrascrittura
    }

    #[test]
    fn open_su_file_attiva_wal() {
        let dir = std::env::temp_dir().join(format!("gestionale-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = open(&dir.join("test.db")).unwrap();
        let mode: String = c
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(c);
        std::fs::remove_dir_all(dir).ok();
    }
}
