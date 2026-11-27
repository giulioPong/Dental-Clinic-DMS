//! Schema SQL, migrazioni e categorie dei documenti.

use super::*;

pub(super) const MIGRATIONS: &[&str] = &[MIGRATION_V1];

/// Se `Some(hash)`, il test `migration_v1_congelata` fallisce quando MIGRATION_V1 cambia.
pub(super) const FROZEN_V1_SHA256: Option<&str> = None;

pub const CATEGORY_TAGS: [&str; 6] = ["Panoramica", "Endorale", "Scan 3D", "Consenso", "Preventivo", "Altro"];

pub(super) const MIGRATION_V1: &str = r#"
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

pub(super) fn migrate(conn: &mut Connection) -> Result<()> {
    let current: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}
