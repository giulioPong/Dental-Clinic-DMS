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
