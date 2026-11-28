use super::*;
use crate::commands::AppCore;
use crate::crypto::KdfParams;

const PW: &str = "correct horse battery";

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("gestionale-bk-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&d).unwrap();
    d
}

/// AppCore con la stessa struttura di cartelle dell'app vera.
fn app_core(data: &Path) -> AppCore {
    AppCore::new(&data.join(VAULT_DIR), &data.join(DB_FILE), Duration::from_secs(600))
        .unwrap()
        .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
        .with_snapshot_dir(&data.join(STAGING_DIR))
}

/// Archivio con un paziente, sessione chiusa (come dopo la chiusura dell'app).
fn archive_closed(data: &Path) {
    let c = app_core(data);
    c.setup_vault(PW).unwrap();
    c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    c.lock().unwrap();
}

/// Ripristino come da procedura: vault/ dal backup, DB e checkpoint dallo staging.
fn restore_and_check(data: &Path, staging: &Path, expect_patients: usize) {
    let r = tmpdir();
    fs::create_dir_all(r.join(VAULT_DIR)).unwrap();
    for e in fs::read_dir(data.join(VAULT_DIR)).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() && e.file_name() != CHECKPOINT_FILE {
            fs::copy(e.path(), r.join(VAULT_DIR).join(e.file_name())).unwrap();
        }
    }
    fs::copy(staging.join(DB_FILE), r.join(DB_FILE)).unwrap();
    fs::copy(staging.join(CHECKPOINT_FILE), r.join(VAULT_DIR).join(CHECKPOINT_FILE)).unwrap();
    let c = app_core(&r);
    let info = c.unlock(PW).unwrap();
    assert!(info.audit_ok, "{:?}", info.audit_message);
    assert_eq!(c.search_patients("ross", 10).unwrap().len() + c.search_patients("verd", 10).unwrap().len(), expect_patients);
    c.lock().unwrap();
    drop(c);
    fs::remove_dir_all(r).ok();
}

#[test]
fn app_chiusa_copia_db_e_checkpoint_attuali() {
    let data = tmpdir();
    archive_closed(&data);
    let staging = tmpdir().join("staging");
    let o = backup_db(&data, &staging).unwrap();
    assert_eq!(o.source, BackupSource::LiveDatabase);
    assert_eq!(fs::read(staging.join(DB_FILE)).unwrap(), fs::read(data.join(DB_FILE)).unwrap());
    assert_eq!(
        fs::read(staging.join(CHECKPOINT_FILE)).unwrap(),
        fs::read(data.join(VAULT_DIR).join(CHECKPOINT_FILE)).unwrap()
    );
    assert!(fs::read_dir(&staging).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
    restore_and_check(&data, &staging, 1);
    // il lock è stato rilasciato: l'app può ripartire
    assert!(InstanceLock::try_acquire(&data).unwrap().is_some());
    fs::remove_dir_all(data).ok();
    fs::remove_dir_all(staging.parent().unwrap()).ok();
}

#[test]
fn app_aperta_copia_lo_snapshot_dell_app() {
    let data = tmpdir();
    let staging = tmpdir().join("staging");
    let _app = InstanceLock::try_acquire(&data).unwrap().expect("lock libero");
    let c = app_core(&data);
    c.setup_vault(PW).unwrap();
    // nessuno snapshot ancora: il backup lo dice e non copia nulla
    let e = backup_db(&data, &staging).unwrap_err();
    assert!(e.contains("nessuno snapshot"), "{e}");
    assert!(!staging.join(DB_FILE).exists());

    c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    c.snapshot_db().unwrap(); // snapshot periodico
    c.create_patient("Luigi", "Verdi", "1970-01-01", None).unwrap(); // dopo lo snapshot
    let o = backup_db(&data, &staging).unwrap();
    assert_eq!(o.source, BackupSource::AppSnapshot);
    assert!(o.snapshot_age.is_some());
    assert_eq!(fs::read(staging.join(DB_FILE)).unwrap(), fs::read(data.join(STAGING_DIR).join(DB_FILE)).unwrap());
    // lo snapshot non contiene ancora Verdi, ma è coerente con il suo checkpoint
    restore_and_check(&data, &staging, 1);

    // staging coincidente con quello dell'app: niente da copiare
    let o = backup_db(&data, &data.join(STAGING_DIR)).unwrap();
    assert_eq!(o.source, BackupSource::AppSnapshot);
    c.lock().unwrap();
    drop(c);
    fs::remove_dir_all(data).ok();
    fs::remove_dir_all(staging.parent().unwrap()).ok();
}

#[test]
fn una_sola_istanza_alla_volta() {
    let data = tmpdir();
    let first = InstanceLock::try_acquire(&data).unwrap();
    assert!(first.is_some());
    assert!(InstanceLock::try_acquire(&data).unwrap().is_none());
    assert!(InstanceLock::acquire_waiting(&data, Duration::from_millis(300)).unwrap().is_none());
    drop(first);
    assert!(InstanceLock::acquire_waiting(&data, Duration::from_millis(300)).unwrap().is_some());
    fs::remove_dir_all(data).ok();
}

#[test]
fn rifiuta_wal_pendente_e_staging_pericolosi() {
    let data = tmpdir();
    archive_closed(&data);
    let staging = tmpdir().join("staging");

    let mut wal = data.join(DB_FILE).into_os_string();
    wal.push("-wal");
    fs::write(&wal, b"pagine non ancora nel database").unwrap();
    assert!(backup_db(&data, &staging).unwrap_err().contains("WAL"));
    assert!(!staging.join(DB_FILE).exists());
    fs::write(&wal, b"").unwrap(); // WAL vuoto: va bene
    assert!(backup_db(&data, &staging).is_ok());

    let before = fs::read(data.join(DB_FILE)).unwrap();
    assert!(backup_db(&data, &data).is_err());
    assert!(backup_db(&data, &data.join(VAULT_DIR).join("dentro")).is_err());
    assert_eq!(fs::read(data.join(DB_FILE)).unwrap(), before, "il DB non deve essere toccato");

    let empty = tmpdir();
    assert!(backup_db(&empty, &staging).unwrap_err().contains("non trovato"));
    fs::remove_dir_all(data).ok();
    fs::remove_dir_all(empty).ok();
    fs::remove_dir_all(staging.parent().unwrap()).ok();
}

#[test]
fn riga_di_comando() {
    let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(cli_main(&args(&["app.exe"])), None); // nessun comando: si avvia l'app
    assert_eq!(cli_main(&args(&["app.exe", "--backup-db"])), Some(exit::USAGE));
    assert_eq!(cli_main(&args(&["app.exe", "--backup-db", "--data-dir", "x"])), Some(exit::USAGE));

    let data = tmpdir();
    archive_closed(&data);
    let staging = tmpdir().join("staging");
    let (st, dd) = (staging.to_string_lossy().into_owned(), data.to_string_lossy().into_owned());
    assert_eq!(cli_main(&args(&["app.exe", "--backup-db", &st, "--data-dir", &dd])), Some(exit::OK));
    let log = fs::read_to_string(staging.join(LOG_FILE)).unwrap();
    assert!(log.contains(" OK ") && log.contains("app chiusa"), "{log}");

    let empty = tmpdir();
    let ed = empty.to_string_lossy().into_owned();
    assert_eq!(cli_main(&args(&["app.exe", "--backup-db", &st, "--data-dir", &ed])), Some(exit::FAILED));
    assert!(fs::read_to_string(staging.join(LOG_FILE)).unwrap().contains("ERRORE"));
    fs::remove_dir_all(data).ok();
    fs::remove_dir_all(empty).ok();
    fs::remove_dir_all(staging.parent().unwrap()).ok();
}

#[test]
fn identificativo_coincide_con_tauri_conf() {
    let conf: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json")).unwrap()).unwrap();
    assert_eq!(conf["identifier"].as_str(), Some(APP_IDENTIFIER));
    assert!(default_data_dir().unwrap().ends_with(APP_IDENTIFIER));
}

#[test]
fn data_utc_leggibile() {
    assert_eq!(humantime_utc(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    assert_eq!(humantime_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(951_868_799)), "2000-02-29T23:59:59Z");
    assert_eq!(humantime_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_813_507)), "2026-11-27T21:05:07Z");
}

#[test]
fn l_app_aspetta_solo_il_backup_non_un_altra_istanza() {
    let data = tmpdir();
    let other = InstanceLock::try_acquire(&data).unwrap().unwrap();
    // altra istanza dell'app: risposta immediata
    let t = Instant::now();
    assert!(InstanceLock::acquire_for_app(&data, Duration::from_secs(5)).unwrap().is_none());
    assert!(t.elapsed() < Duration::from_secs(1));

    // backup in corso: l'app aspetta che finisca
    fs::write(data.join(BACKUP_MARKER), b"").unwrap();
    std::thread::scope(|s| {
        s.spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            drop(other);
        });
        let t = Instant::now();
        assert!(InstanceLock::acquire_for_app(&data, Duration::from_secs(5)).unwrap().is_some());
        assert!(t.elapsed() >= Duration::from_millis(300));
    });
    fs::remove_dir_all(data).ok();
}

#[test]
fn il_segnale_di_backup_sparisce_anche_in_caso_di_errore() {
    let data = tmpdir();
    archive_closed(&data);
    let staging = tmpdir().join("staging");
    let mut wal = data.join(DB_FILE).into_os_string();
    wal.push("-wal");
    fs::write(&wal, b"x").unwrap();
    assert!(backup_db(&data, &staging).is_err());
    assert!(!data.join(BACKUP_MARKER).exists());
    fs::write(&wal, b"").unwrap();
    backup_db(&data, &staging).unwrap();
    assert!(!data.join(BACKUP_MARKER).exists());
    fs::remove_dir_all(data).ok();
    fs::remove_dir_all(staging.parent().unwrap()).ok();
}
