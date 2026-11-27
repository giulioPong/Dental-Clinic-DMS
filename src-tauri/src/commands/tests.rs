use super::*;

const PW: &str = "correct horse battery";

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}
fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("gestionale-cmd-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&d).unwrap();
    d
}
fn core_with(idle: Duration) -> (PathBuf, AppCore) {
    let dir = tmpdir();
    let c = AppCore::new(&dir.join("vault"), &dir.join("gestionale.db"), idle)
        .unwrap()
        .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 });
    (dir, c)
}
fn core() -> (PathBuf, AppCore) {
    core_with(Duration::from_secs(600))
}
fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
fn code<T: std::fmt::Debug>(r: Res<T>) -> ErrorCode {
    r.unwrap_err().code
}

#[test]
fn flusso_completo_e_sblocco_successivo() {
    let (dir, c) = core();
    assert_eq!(c.status(), Status { initialized: false, unlocked: false });
    assert_eq!(code(c.search_patients("ross", 10)), ErrorCode::Locked);

    assert!(c.setup_vault(PW).unwrap().audit_ok);
    assert_eq!(c.status(), Status { initialized: true, unlocked: true });
    assert_eq!(code(c.setup_vault(PW)), ErrorCode::AlreadyInitialized);

    let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let f = dir.join("rx.jpg");
    fs::write(&f, data(5000)).unwrap();
    let mut progress = Vec::new();
    let rep = c.upload_documents(&pid, &[s(&f)], "Panoramica", |d, t| progress.push((d, t))).unwrap();
    assert_eq!((rep.uploaded.len(), rep.failed.len()), (1, 0));
    assert_eq!(progress, vec![(1, 1)]);

    let docs = c.list_documents(&pid, None).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].mime_type, "image/jpeg");
    let (meta, bytes) = c.open_document(&docs[0].id).unwrap();
    assert_eq!(&bytes[..], &data(5000)[..]);
    assert_eq!(meta.original_filename, "rx.jpg");

    let zip = dir.join("out.zip");
    assert_eq!(c.export_patient_zip(&pid, &zip).unwrap().documents, 1);
    assert_eq!(c.get_patient(&pid).unwrap().last_name, "Rossi");

    assert!(c.lock().unwrap());
    assert_eq!(c.status(), Status { initialized: true, unlocked: false });
    assert_eq!(code(c.open_document(&docs[0].id)), ErrorCode::Locked);
    assert_eq!(code(c.unlock("password sbagliata")), ErrorCode::WrongPassword);
    let info = c.unlock(PW).unwrap();
    assert!(info.audit_ok, "{:?}", info.audit_message);
    assert_eq!(c.search_patients("ross", 10).unwrap().len(), 1);

    // l'audit è una catena unica anche se scritto da connessioni diverse
    let keys = c.storage.unlock(PW).unwrap();
    let db = Db::open(&c.db_path, &keys, "t").unwrap();
    assert!(db.verify_audit_chain(None).unwrap() >= 5); // paziente, upload, apertura, export, vista
    fs::remove_dir_all(dir).ok();
}

#[test]
fn il_blocco_chiude_la_connessione_e_azzera_la_sessione() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    assert!(c.lock_session().is_some());
    c.lock().unwrap();
    assert!(c.lock_session().is_none());
    assert!(!c.keystore.is_unlocked());
    assert!(!c.lock().unwrap()); // già bloccato
    fs::remove_dir_all(dir).ok();
}

#[test]
fn blocco_per_inattivita_con_e_senza_watcher() {
    let (dir, c) = core_with(Duration::from_millis(300));
    c.setup_vault(PW).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(c.expire_if_idle().unwrap()); // il thread di fondo blocca e può emettere vault-locked
    assert!(c.lock_session().is_none());
    assert!(!c.expire_if_idle().unwrap());

    c.unlock(PW).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    // senza watcher: il primo comando trova la sessione scaduta e la elimina
    assert_eq!(code(c.search_patients("abc", 5)), ErrorCode::Locked);
    assert!(c.lock_session().is_none());

    c.unlock(PW).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(c.status().unlocked, false); // anche status() chiude la sessione scaduta
    assert!(c.lock_session().is_none());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn lo_snapshot_periodico_non_rinvia_il_blocco() {
    let dir = tmpdir();
    let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_millis(400))
        .unwrap()
        .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
        .with_snapshot_dir(&dir.join("staging"));
    c.setup_vault(PW).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    c.snapshot_db().unwrap(); // non è attività dell'utente
    std::thread::sleep(Duration::from_millis(250));
    assert!(c.expire_if_idle().unwrap()); // 500 ms dall'ultima attività vera, nonostante lo snapshot a 250
    fs::remove_dir_all(dir).ok();
}

#[test]
fn i_comandi_rinviano_il_blocco() {
    let (dir, c) = core_with(Duration::from_millis(600));
    c.setup_vault(PW).unwrap();
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(250));
        assert!(c.search_patients("abc", 5).is_ok()); // ogni uso azzera il timer
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn tentativi_di_sblocco_limitati() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    c.lock().unwrap();
    for _ in 0..4 {
        assert_eq!(code(c.unlock("sbagliata sbagliata")), ErrorCode::WrongPassword);
    }
    assert!(c.unlock(PW).is_ok()); // dopo 4 errori la password giusta passa e azzera il contatore
    c.lock().unwrap();
    for _ in 0..5 {
        assert_eq!(code(c.unlock("sbagliata sbagliata")), ErrorCode::WrongPassword);
    }
    let e = c.unlock(PW).unwrap_err(); // anche la password giusta viene rifiutata durante l'attesa
    assert_eq!(e.code, ErrorCode::TooManyAttempts);
    assert!(e.detail.unwrap().parse::<u64>().unwrap() >= 1);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn cambio_password_dalla_sessione() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    assert_eq!(code(c.change_password("sbagliata sbagliata", "nuova password lunga")), ErrorCode::WrongPassword);
    assert_eq!(code(c.change_password(PW, "corta")), ErrorCode::InvalidInput);
    c.change_password(PW, "nuova password lunga").unwrap();
    assert!(c.search_patients("abc", 5).is_ok()); // la sessione resta valida
    c.lock().unwrap();
    assert_eq!(code(c.unlock(PW)), ErrorCode::WrongPassword);
    assert!(c.unlock("nuova password lunga").is_ok());
    c.lock().unwrap();
    assert_eq!(code(c.change_password(PW, "x")), ErrorCode::Locked);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn il_database_non_viene_mai_creato_allo_sblocco() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    c.lock().unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", s(&dir.join("gestionale.db"))));
    }
    assert_eq!(code(c.unlock(PW)), ErrorCode::DbMissing);
    assert!(!dir.join("gestionale.db").exists());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn setup_fallito_non_lascia_un_vault_senza_database() {
    let (dir, c) = core();
    fs::write(dir.join("gestionale.db"), b"qualcosa").unwrap(); // un file occupa già il posto del DB
    assert!(c.setup_vault(PW).is_err());
    assert!(!dir.join("vault").join("vault.meta").exists());
    assert_eq!(c.status(), Status { initialized: false, unlocked: false });
    fs::remove_dir_all(dir).ok();
}

#[test]
fn limite_di_ricerca_e_validazione_input() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    for i in 0..105 {
        c.create_patient(&format!("Prova{i:03}"), "Test", "1990-01-01", None).unwrap();
    }
    assert_eq!(c.search_patients("test", 5000).unwrap().len(), 100);
    assert_eq!(c.search_patients("test", 0).unwrap().len(), 1);
    assert_eq!(code(c.create_patient(&"x".repeat(101), "Test", "1990-01-01", None)), ErrorCode::InvalidInput);
    assert_eq!(code(c.create_patient("A", "Bbb", "2023-02-30", None)), ErrorCode::InvalidInput);
    let long = "a".repeat(10_000);
    assert!(c.search_patients(&long, 10).is_ok()); // la query viene troncata, non rifiutata
    fs::remove_dir_all(dir).ok();
}

#[test]
fn codice_fiscale_duplicato_riporta_l_id_esistente() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let a = c.create_patient("Mario", "Rossi", "1980-05-12", Some("RSSMRA80E12A944X")).unwrap();
    let e = c.create_patient("Altro", "Paziente", "1990-01-01", Some("rssmra80e12a944x")).unwrap_err();
    assert_eq!(e.code, ErrorCode::DuplicateFiscalCode);
    assert_eq!(e.detail.as_deref(), Some(a.as_str()));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn upload_di_cartelle_con_esclusioni_e_errori_per_file() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let root = dir.join("storico");
    fs::create_dir_all(root.join("2019/endorali")).unwrap();
    fs::write(root.join("pano.png"), data(3000)).unwrap();
    fs::write(root.join("2019/referto.pdf"), data(1000)).unwrap();
    fs::write(root.join("2019/endorali/e1.jpg"), data(500)).unwrap();
    fs::write(root.join(".DS_Store"), b"x").unwrap();
    fs::write(root.join("Thumbs.db"), b"x").unwrap();
    fs::create_dir_all(root.join(".nascosta")).unwrap();
    fs::write(root.join(".nascosta/x.jpg"), b"x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("pano.png"), root.join("collegamento.png")).unwrap();
    let vault_file = dir.join("vault").join("vault.meta");

    let mut calls = 0;
    let rep = c
        .upload_documents(&pid, &[s(&root), s(&dir.join("non-esiste.jpg")), s(&vault_file)], "Altro", |_, t| {
            calls += 1;
            assert_eq!(t, 3);
        })
        .unwrap();
    assert_eq!(rep.uploaded.len(), 3);
    assert_eq!(calls, 3);
    let names: Vec<&str> = rep.uploaded.iter().map(|u| u.name.as_str()).collect();
    assert!(names.contains(&"pano.png") && names.contains(&"referto.pdf") && names.contains(&"e1.jpg"));
    let failed: Vec<(&str, ErrorCode)> = rep.failed.iter().map(|f| (f.name.as_str(), f.code)).collect();
    assert!(failed.contains(&("non-esiste.jpg", ErrorCode::NotFound)));
    assert!(failed.contains(&("vault.meta", ErrorCode::InvalidInput)));
    #[cfg(unix)]
    assert!(failed.contains(&("collegamento.png", ErrorCode::InvalidInput)));

    // paziente nel cestino: ogni file fallisce con il codice giusto, nessun file lasciato
    c.delete_patient(&pid).unwrap();
    let rep2 = c.upload_documents(&pid, &[s(&root.join("pano.png"))], "Altro", |_, _| {}).unwrap();
    assert!(rep2.uploaded.is_empty());
    assert_eq!(rep2.failed[0].code, ErrorCode::PatientInTrash);
    // categoria non valida
    c.restore_patient(&pid).unwrap();
    let rep3 = c.upload_documents(&pid, &[s(&root.join("pano.png"))], "Boh", |_, _| {}).unwrap();
    assert_eq!(rep3.failed[0].code, ErrorCode::InvalidInput);
    assert_eq!(c.list_documents(&pid, None).unwrap().len(), 3);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn upload_si_ferma_se_l_archivio_si_blocca_a_meta() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let root = dir.join("lotto");
    fs::create_dir_all(&root).unwrap();
    for i in 0..4 {
        fs::write(root.join(format!("f{i}.jpg")), data(200)).unwrap();
    }
    let rep = c
        .upload_documents(&pid, &[s(&root)], "Altro", |done, _| {
            if done == 2 {
                c.lock().unwrap(); // blocco manuale durante l'importazione
            }
        })
        .unwrap();
    assert_eq!(rep.uploaded.len(), 2);
    assert_eq!(rep.failed.len(), 2);
    assert!(rep.failed.iter().all(|f| f.code == ErrorCode::Locked));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn shutdown_aspetta_le_operazioni_pesanti() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let start = Instant::now();
    std::thread::scope(|sc| {
        let op = c.begin_op();
        sc.spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(op);
        });
        c.shutdown(Duration::from_secs(5)).unwrap();
    });
    assert!(start.elapsed() >= Duration::from_millis(300));
    assert_eq!(c.status(), Status { initialized: true, unlocked: false });
    assert_eq!(code(c.search_patients("x", 1)), ErrorCode::Locked);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn shutdown_con_operazione_bloccata_chiude_comunque_e_segnala() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let _op = c.begin_op();
    assert_eq!(code(c.shutdown(Duration::from_millis(50))), ErrorCode::Internal);
    assert!(c.lock_session().is_none());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn lock_segnala_lo_snapshot_fallito_ma_blocca() {
    let dir = tmpdir();
    // la "cartella" di snapshot è un file: create_dir_all fallisce
    let bad = dir.join("non-una-cartella");
    fs::write(&bad, b"x").unwrap();
    let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_secs(600))
        .unwrap()
        .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
        .with_snapshot_dir(&bad);
    c.setup_vault(PW).unwrap();
    assert_eq!(code(c.lock()), ErrorCode::IoError);
    assert!(c.lock_session().is_none());
    assert!(!c.lock().unwrap());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn viewer_rispetta_il_limite() {
    let dir = tmpdir();
    let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_secs(600))
        .unwrap()
        .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
        .with_viewer_limit(1000);
    c.setup_vault(PW).unwrap();
    let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let (small, big) = (dir.join("piccolo.jpg"), dir.join("grande.stl"));
    fs::write(&small, data(900)).unwrap();
    fs::write(&big, data(5000)).unwrap();
    c.upload_documents(&pid, &[s(&small), s(&big)], "Scan 3D", |_, _| {}).unwrap();
    for d in c.list_documents(&pid, None).unwrap() {
        if d.size_bytes == 5000 {
            assert_eq!(code(c.open_document(&d.id)), ErrorCode::TooLarge);
        } else {
            assert!(c.open_document(&d.id).is_ok());
        }
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn export_valida_la_destinazione() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let f = dir.join("a.jpg");
    fs::write(&f, data(500)).unwrap();
    c.upload_documents(&pid, &[s(&f)], "Altro", |_, _| {}).unwrap();

    assert_eq!(code(c.export_patient_zip(&pid, &dir.join("a.txt"))), ErrorCode::InvalidInput);
    assert_eq!(code(c.export_patient_zip(&pid, &dir.join("manca/a.zip"))), ErrorCode::InvalidInput);
    assert_eq!(code(c.export_patient_zip(&pid, &dir.join("vault").join("a.zip"))), ErrorCode::InvalidInput); // dentro il vault
    assert_eq!(code(c.export_patient_zip(&pid, &dir.join("vault").join("tmp").join("a.zip"))), ErrorCode::InvalidInput);
    let ok = dir.join("export.ZIP");
    assert!(c.export_patient_zip(&pid, &ok).is_ok());
    assert_eq!(code(c.export_patient_zip(&pid, &ok)), ErrorCode::AlreadyExists);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn cestino_ripristino_e_riassegnazione_via_comandi() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let a = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let b = c.create_patient("Luca", "Bianchi", "1975-01-02", None).unwrap();
    let f = dir.join("a.jpg");
    fs::write(&f, data(300)).unwrap();
    c.upload_documents(&a, &[s(&f)], "Altro", |_, _| {}).unwrap();
    let id = c.list_documents(&a, None).unwrap()[0].id.clone();

    c.reassign_document(&id, &b).unwrap();
    assert_eq!(c.list_documents(&a, None).unwrap().len(), 0);
    c.delete_document(&id).unwrap();
    c.delete_patient(&a).unwrap();
    let t = c.list_trash().unwrap();
    assert_eq!((t.patients.len(), t.documents.len()), (1, 1));
    assert_eq!(code(c.restore_document("00000000-0000-0000-0000-000000000000")), ErrorCode::NotFound);
    c.restore_document(&id).unwrap();
    c.restore_patient(&a).unwrap();
    assert!(c.list_trash().unwrap().documents.is_empty());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn manutenzione_elimina_il_cestino_scaduto() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let f = dir.join("a.jpg");
    fs::write(&f, data(300)).unwrap();
    c.upload_documents(&pid, &[s(&f)], "Altro", |_, _| {}).unwrap();
    let id = c.list_documents(&pid, None).unwrap()[0].id.clone();
    assert_eq!(c.maintenance().unwrap(), MaintenanceReport::default()); // nulla di scaduto
    c.delete_document(&id).unwrap();
    assert_eq!(c.maintenance().unwrap(), MaintenanceReport::default()); // cestinato da poco

    let keys = c.storage.unlock(PW).unwrap();
    let db = Db::open(&c.db_path, &keys, "t").unwrap();
    db.conn()
        .execute("UPDATE documents SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','-40 days')", [])
        .unwrap();
    drop(db);
    let r = c.maintenance().unwrap();
    assert_eq!((r.purged_documents, r.failed_files), (1, 0));
    assert!(!dir.join("vault").join(format!("{id}.enc")).exists());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn snapshot_e_checkpoint_alla_chiusura_della_sessione() {
    let dir = tmpdir();
    let staging = dir.join("staging");
    let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_secs(600))
        .unwrap()
        .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
        .with_snapshot_dir(&staging);
    c.setup_vault(PW).unwrap();
    c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    c.snapshot_db().unwrap(); // periodico
    assert!(staging.join("gestionale.db").exists());
    assert!(dir.join("vault").join("audit.checkpoint").exists());
    c.create_patient("Luca", "Bianchi", "1975-01-02", None).unwrap();
    c.lock().unwrap(); // chiusura: snapshot aggiornato (sostituisce il precedente) e checkpoint
    assert!(!staging.join("gestionale.db.new").exists());
    assert!(dir.join("vault").join("audit.checkpoint").exists());

    let keys = c.storage.unlock(PW).unwrap();
    let snap = Db::open(&staging.join("gestionale.db"), &keys, "t").unwrap();
    assert_eq!(snap.search_patients("bianchi", 5).unwrap().len(), 1); // contiene anche l'ultima modifica
    assert!(!fs::read(staging.join("gestionale.db")).unwrap().starts_with(b"SQLite format 3")); // cifrato
    assert!(c.snapshot_db().is_err()); // bloccato
    fs::remove_dir_all(dir).ok();
}

#[test]
fn troncamento_del_registro_accessi_segnalato_allo_sblocco() {
    let (dir, c) = core();
    c.setup_vault(PW).unwrap();
    c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    c.lock().unwrap(); // scrive il checkpoint
    let keys = c.storage.unlock(PW).unwrap();
    {
        let db = Db::open(&c.db_path, &keys, "t").unwrap();
        db.conn()
            .execute_batch(
                "DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;
                 DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log);",
            )
            .unwrap();
    }
    let info = c.unlock(PW).unwrap();
    assert!(!info.audit_ok);
    assert!(info.audit_message.is_some());
    assert!(c.search_patients("ross", 5).is_ok()); // l'accesso resta possibile: è un avviso
    fs::remove_dir_all(dir).ok();
}

#[test]
fn errori_serializzati_senza_dettagli_interni() {
    let e = CommandError::from(CryptoError::WrongPasswordOrCorrupted);
    let j = serde_json::to_value(&e).unwrap();
    assert_eq!(j["code"], "WRONG_PASSWORD");
    assert!(j.get("detail").is_none());

    let e = CommandError::from(DbError::DuplicateFiscalCode { existing_id: "abc".into() });
    let j = serde_json::to_value(&e).unwrap();
    assert_eq!((j["code"].as_str(), j["detail"].as_str()), (Some("DUPLICATE_FISCAL_CODE"), Some("abc")));

    // un errore di SQLite non espone il testo originale (tabelle, query)
    let e = CommandError::from(DbError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(1),
        Some("UNIQUE constraint failed: patients.fiscal_code".into()),
    )));
    let text = serde_json::to_string(&e).unwrap();
    assert!(!text.contains("patients") && !text.contains("UNIQUE"));
    for c in [ErrorCode::TooManyAttempts, ErrorCode::DbMissing, ErrorCode::AuditTampered] {
        assert!(serde_json::to_string(&c).unwrap().chars().all(|ch| ch == '"' || ch == '_' || ch.is_ascii_uppercase()));
    }
    let dto = serde_json::to_value(&Status { initialized: true, unlocked: false }).unwrap();
    assert_eq!(dto["initialized"], true); // camelCase per il frontend
    let up = serde_json::to_value(&UploadedDto { id: "1".into(), name: "a".into() }).unwrap();
    assert!(up.get("id").is_some());
}

#[test]
fn mime_e_file_ignorati() {
    assert_eq!(mime_for("RX.JPG"), "image/jpeg");
    assert_eq!(mime_for("scan.stl"), "model/stl");
    assert_eq!(mime_for("senza_estensione"), "application/octet-stream");
    assert!(is_ignored_child(".DS_Store") && is_ignored_child("THUMBS.DB") && is_ignored_child("desktop.ini"));
    assert!(!is_ignored_child("rx.jpg"));
}
