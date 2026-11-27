use super::*;
use super::export::{sanitize_filename, unique_name};
use std::io::Cursor;

const PW: &str = "correct horse battery";
const PW2: &str = "tutt'altra password 42";

fn tp() -> KdfParams { KdfParams { m_kib: 8, t: 2, p: 1 } }
fn data(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }
fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("gestionale-st-{}", new_uuid()));
    fs::create_dir_all(&d).unwrap();
    d
}
fn setup() -> (PathBuf, Storage, Db, Keys) {
    let dir = tmpdir();
    let st = Storage::open(&dir.join("vault")).unwrap();
    let keys = st.create_vault_with_params(PW, tp()).unwrap();
    let db = Db::open_in_memory(&keys, "admin").unwrap();
    (dir, st, db, keys)
}
fn up(st: &Storage, db: &Db, k: &Keys, pid: &str, name: &str, tag: &str, bytes: &[u8]) -> String {
    st.upload_document(
        db, k,
        &UploadRequest { patient_id: pid, original_filename: name, mime_type: "application/octet-stream", category_tag: tag },
        Cursor::new(bytes.to_vec()),
    )
    .unwrap()
}
fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into()).collect();
    v.sort();
    v
}
fn enc_files(st: &Storage) -> Vec<String> {
    files_in(st.root()).into_iter().filter(|n| is_enc_name(n)).collect()
}
struct FailingReader(usize);
impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "disco USB scollegato"));
        }
        let n = buf.len().min(self.0).min(1000);
        buf[..n].fill(7);
        self.0 -= n;
        Ok(n)
    }
}

// ── vault.meta ──

#[test]
fn creazione_e_sblocco_del_vault() {
    let (dir, st, _db, keys) = setup();
    assert!(st.meta_path().exists());
    assert!(!st.meta_tmp().exists());
    let k2 = st.unlock(PW).unwrap();
    assert_eq!(k2.files_key(), keys.files_key());
    assert!(matches!(st.unlock("password sbagliata"), Err(StorageError::Crypto(CryptoError::WrongPasswordOrCorrupted))));
    assert!(matches!(st.create_vault_with_params(PW, tp()), Err(StorageError::VaultAlreadyExists)));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn non_si_crea_un_vault_sopra_file_cifrati_esistenti() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &data(100));
    fs::remove_file(st.meta_path()).unwrap(); // vault.meta perso
    assert!(matches!(st.unlock(PW), Err(StorageError::VaultMissing)));
    assert!(matches!(st.create_vault_with_params(PW, tp()), Err(StorageError::VaultNotEmpty)));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn cambio_password_atomico_senza_residui_e_file_ancora_leggibili() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let id = up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &data(5000));

    st.change_password(PW, PW2).unwrap();
    assert!(!st.meta_bak().exists() && !st.meta_tmp().exists());
    assert!(matches!(st.unlock(PW), Err(StorageError::Crypto(CryptoError::WrongPasswordOrCorrupted))));
    let k2 = st.unlock(PW2).unwrap();
    let (_, plain) = st.open_document(&db, &k2, &id, 1 << 20).unwrap();
    assert_eq!(&plain[..], &data(5000)[..]);

    assert!(matches!(st.change_password("sbagliata sbagliata", PW2), Err(StorageError::Crypto(_))));
    assert!(matches!(st.change_password(PW2, "corta"), Err(StorageError::Crypto(CryptoError::PasswordTooShort))));
    assert!(st.unlock(PW2).is_ok()); // i tentativi falliti non hanno toccato il file
    fs::remove_dir_all(dir).ok();
}

#[test]
fn bak_residuo_viene_eliminato_e_meta_corrotto_si_ripristina_dal_bak() {
    let (dir, st, _db, _k) = setup();
    // crash dopo il rename ma prima di cancellare il .bak: la vecchia password non deve restare valida
    fs::copy(st.meta_path(), st.meta_bak()).unwrap();
    st.unlock(PW).unwrap();
    assert!(!st.meta_bak().exists());

    // vault.meta illeggibile + copia di riserva valida → ripristino
    let good = fs::read(st.meta_path()).unwrap();
    fs::write(st.meta_bak(), &good).unwrap();
    fs::write(st.meta_path(), vec![0u8; good.len()]).unwrap();
    st.unlock(PW).unwrap();
    assert_eq!(fs::read(st.meta_path()).unwrap(), good);
    assert!(!st.meta_bak().exists());

    // password errata non ripristina nulla né cancella il bak
    fs::write(st.meta_bak(), &good).unwrap();
    fs::write(st.meta_path(), vec![0u8; good.len()]).unwrap();
    assert!(st.unlock("password sbagliata").is_err());
    assert!(st.meta_bak().exists());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn unlock_non_ignora_il_fallimento_rimozione_backup() {
    let (dir, st, _db, _k) = setup();
    fs::create_dir(st.meta_bak()).unwrap();

    assert!(matches!(st.unlock(PW), Err(StorageError::Io(_))));
    assert!(st.meta_bak().is_dir());

    fs::remove_dir_all(dir).ok();
}

// ── upload / viewer ──

#[test]
fn upload_e_apertura_con_file_multi_blocco() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let big = data(2 * 1024 * 1024 + 123_456);
    let id = up(&st, &db, &keys, &pid, "C:\\Users\\papa\\scan 3d.stl", "Scan 3D", &big);

    assert_eq!(enc_files(&st), vec![format!("{id}.enc")]);
    assert!(files_in(&st.tmp_dir()).is_empty());
    let rec = db.get_document(&id).unwrap();
    assert_eq!(rec.original_filename, "scan 3d.stl"); // solo il nome, niente percorso
    assert_eq!(rec.size_bytes, big.len() as u64);
    assert_eq!(rec.sha256, hex(&Sha256::digest(&big)));

    let (_, plain) = st.open_document(&db, &keys, &id, 10 << 20).unwrap();
    assert_eq!(&plain[..], &big[..]);
    assert_eq!(db.verify_audit_chain(None).unwrap(), 3); // CREATE_PATIENT, UPLOAD_FILE, OPEN_FILE
    assert!(matches!(st.open_document(&db, &keys, &id, 1000), Err(StorageError::Crypto(CryptoError::TooLarge))));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn upload_fallito_non_lascia_ne_file_ne_righe() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let req = |tag| UploadRequest { patient_id: &pid, original_filename: "rx.jpg", mime_type: "image/jpeg", category_tag: tag };

    // sorgente che si interrompe a metà (chiavetta staccata)
    assert!(st.upload_document(&db, &keys, &req("Altro"), FailingReader(5_000_000)).is_err());
    assert!(files_in(&st.tmp_dir()).is_empty());
    assert!(enc_files(&st).is_empty());
    assert!(st.upload_lock.try_write().is_ok()); // nessun lock rimasto preso

    // input rifiutati prima di cifrare
    assert!(matches!(st.upload_document(&db, &keys, &req("Boh"), Cursor::new(vec![1])), Err(StorageError::InvalidInput(_))));
    let bad_name = UploadRequest { original_filename: "  ", ..req("Altro") };
    assert!(matches!(st.upload_document(&db, &keys, &bad_name, Cursor::new(vec![1])), Err(StorageError::InvalidInput(_))));
    let ghost = UploadRequest { patient_id: &new_uuid(), ..req("Altro") };
    assert!(matches!(st.upload_document(&db, &keys, &ghost, Cursor::new(vec![1])), Err(StorageError::Db(DbError::NotFound))));
    db.soft_delete_patient(&pid).unwrap();
    assert!(matches!(st.upload_document(&db, &keys, &req("Altro"), Cursor::new(vec![1])), Err(StorageError::Db(DbError::PatientInTrash))));
    assert!(enc_files(&st).is_empty() && files_in(&st.tmp_dir()).is_empty());
    assert_eq!(db.all_documents().unwrap().len(), 0);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn open_all_avvio_svuota_tmp() {
    let (dir, st, _db, _k) = setup();
    fs::write(st.tmp_dir().join("residuo.part"), b"parziale").unwrap();
    fs::write(st.tmp_dir().join("altro.part"), b"parziale").unwrap();
    let st2 = Storage::open(st.root()).unwrap();
    assert!(files_in(&st2.tmp_dir()).is_empty());
    assert!(st2.meta_path().exists()); // il resto non si tocca
    fs::remove_dir_all(dir).ok();
}

#[test]
fn apertura_rileva_file_alterati_troncati_scambiati_o_mancanti() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let a = up(&st, &db, &keys, &pid, "a.jpg", "Panoramica", &data(5000));
    let b = up(&st, &db, &keys, &pid, "b.jpg", "Endorale", &data(5000));
    let open = |id: &str| st.open_document(&db, &keys, id, 1 << 20).map(|(_, p)| p.len());
    assert_eq!(open(&a).unwrap(), 5000);

    let good = fs::read(st.enc_path(&a)).unwrap();
    // troncato di 1 byte → scoperto dal controllo O(1), senza decifrare
    fs::write(st.enc_path(&a), &good[..good.len() - 1]).unwrap();
    assert!(matches!(open(&a), Err(StorageError::Crypto(CryptoError::SizeMismatch { .. }))));
    // un byte alterato a lunghezza invariata → scoperto dal tag GCM
    let mut flipped = good.clone();
    flipped[40] ^= 1;
    fs::write(st.enc_path(&a), &flipped).unwrap();
    assert!(matches!(open(&a), Err(StorageError::Crypto(CryptoError::FileCorrupted))));
    // il file di un altro documento (stessa lunghezza) copiato sopra → l'AAD non coincide
    fs::copy(st.enc_path(&b), st.enc_path(&a)).unwrap();
    assert!(matches!(open(&a), Err(StorageError::Crypto(CryptoError::FileCorrupted))));
    // file mancante
    fs::remove_file(st.enc_path(&a)).unwrap();
    assert!(matches!(open(&a), Err(StorageError::FileMissing(_))));
    // il DB non coincide col contenuto (hash diverso)
    db.conn().execute("UPDATE documents SET sha256 = ?1 WHERE id = ?2", rusqlite::params!["f".repeat(64), b]).unwrap();
    assert!(matches!(open(&b), Err(StorageError::IntegrityMismatch(_))));
    // cestinato
    db.soft_delete_document(&b).unwrap();
    assert!(matches!(open(&b), Err(StorageError::Db(DbError::InvalidState(_)))));
    fs::remove_dir_all(dir).ok();
}

// ── export ZIP ──

fn read_zip(path: &Path) -> Vec<(String, Vec<u8>, CompressionMethod)> {
    let mut z = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            (f.name().to_string(), buf, f.compression())
        })
        .collect()
}

#[test]
fn export_zip_nomi_contenuti_compressione_e_audit() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let (j1, j2, t, gone) = (data(3000), data(4000), b"referto di testo ".repeat(200), data(10));
    let id1 = up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &j1);
    up(&st, &db, &keys, &pid, "RX.JPG", "Panoramica", &j2); // stesso nome (maiuscole diverse)
    up(&st, &db, &keys, &pid, "../../etc/passwd", "Consenso", &t);
    let trashed = up(&st, &db, &keys, &pid, "scartato.png", "Altro", &gone);
    db.soft_delete_document(&trashed).unwrap();
    let date = db.get_document(&id1).unwrap().created_at[..10].to_string();

    let dest = dir.join("export.zip");
    let rep = st.export_patient_zip(&db, &keys, &pid, &dest).unwrap();
    assert_eq!(rep, ExportReport { documents: 3, plain_bytes: (j1.len() + j2.len() + t.len()) as u64 });
    assert!(!dir.join("export.zip.part").exists());

    let mut entries = read_zip(&dest);
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let names: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
    // i due file con lo stesso nome (maiuscole a parte) hanno lo stesso created_at:
    // quale dei due riceve il suffisso "-2" dipende dall'ordine, quindi si confronta in minuscolo
    let mut got: Vec<String> = names.iter().map(|s| s.to_lowercase()).collect();
    got.sort();
    let mut expected = vec![
        format!("{date}_consenso_passwd").replace("consenso", "Consenso").to_lowercase(),
        format!("{date}_panoramica_rx.jpg"),
        format!("{date}_panoramica_rx-2.jpg"),
    ];
    expected.sort();
    assert_eq!(got, expected);
    for (name, content, method) in &entries {
        if name.ends_with("passwd") {
            assert_eq!(content, &t);
            assert_eq!(*method, CompressionMethod::Deflated);
        } else {
            assert_eq!(*method, CompressionMethod::Stored); // jpg già compresso
            assert!(content == &j1 || content == &j2);
        }
    }
    assert!(db.verify_audit_chain(None).unwrap() > 0);
    let n: i64 = db.conn().query_row("SELECT count(*) FROM audit_log WHERE action='EXPORT_ZIP'", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);

    // non sovrascrive
    assert!(matches!(st.export_patient_zip(&db, &keys, &pid, &dest), Err(StorageError::DestinationExists)));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn export_fallito_non_lascia_zip_parziali() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let a = up(&st, &db, &keys, &pid, "a.jpg", "Panoramica", &data(5000));
    up(&st, &db, &keys, &pid, "b.jpg", "Endorale", &data(5000));
    let dest = dir.join("out.zip");

    // alterazione a lunghezza invariata: si scopre solo durante la decifratura
    let mut bytes = fs::read(st.enc_path(&a)).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(st.enc_path(&a), &bytes).unwrap();
    assert!(st.export_patient_zip(&db, &keys, &pid, &dest).is_err());
    assert!(!dest.exists() && !dir.join("out.zip.part").exists());

    // file troncato: scoperto prima ancora di creare lo ZIP
    fs::write(st.enc_path(&a), &bytes[..bytes.len() - 3]).unwrap();
    assert!(matches!(st.export_patient_zip(&db, &keys, &pid, &dest), Err(StorageError::Crypto(CryptoError::SizeMismatch { .. }))));
    assert!(!dest.exists() && !dir.join("out.zip.part").exists());

    // nessun documento / paziente nel cestino
    let empty = db.create_patient("Luca", "Bianchi", "1975-01-02", None).unwrap();
    assert!(matches!(st.export_patient_zip(&db, &keys, &empty, &dest), Err(StorageError::InvalidInput(_))));
    db.soft_delete_patient(&pid).unwrap();
    assert!(matches!(st.export_patient_zip(&db, &keys, &pid, &dest), Err(StorageError::Db(DbError::PatientInTrash))));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn sanitizzazione_nomi_file() {
    let s = |x: &str| sanitize_filename(x, 120);
    assert_eq!(s("../../etc/passwd"), "passwd");
    assert_eq!(s("C:\\Users\\papa\\rx.jpg"), "rx.jpg");
    assert_eq!(s("a<b>c:d\"e|f?g*h.jpg"), "a_b_c_d_e_f_g_h.jpg");
    assert_eq!(s("referto.pdf. . "), "referto.pdf");
    assert_eq!(s("  rx.jpg  "), "rx.jpg");
    assert_eq!(s(""), "file");
    assert_eq!(s(".."), "file");
    assert_eq!(s("..."), "file");
    assert_eq!(s("tab\there\n.txt"), "tab_here_.txt");
    // nomi riservati di Windows, anche con estensione e in qualsiasi maiuscola
    for n in ["CON", "con.pdf", "NUL.jpg", "Com1.txt", "LPT9.png", "aux", "PRN.tar.gz", "CON .txt"] {
        assert!(s(n).starts_with('_'), "{n} → {}", s(n));
    }
    assert_eq!(s("CONSENSO.pdf"), "CONSENSO.pdf");
    assert_eq!(s("COM10.txt"), "COM10.txt");
    // lunghezza: si accorcia il nome, non l'estensione
    let long = format!("{}.jpg", "è".repeat(200));
    let out = sanitize_filename(&long, 50);
    assert!(out.len() <= 50 && out.ends_with(".jpg") && out.is_char_boundary(out.len()));
    assert!(sanitize_filename(&"x".repeat(500), 40).len() <= 40);
}

#[test]
fn nomi_duplicati_nello_zip() {
    let mut used = HashSet::new();
    assert_eq!(unique_name(&mut used, "a.jpg".into()), "a.jpg");
    assert_eq!(unique_name(&mut used, "A.JPG".into()), "A-2.JPG");
    assert_eq!(unique_name(&mut used, "a.jpg".into()), "a-3.jpg");
    assert_eq!(unique_name(&mut used, "senza_estensione".into()), "senza_estensione");
    assert_eq!(unique_name(&mut used, "senza_estensione".into()), "senza_estensione-2");
}

// ── coerenza, quarantena, purge ──

#[test]
fn coerenza_orfani_mancanti_e_quarantena() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let ok = up(&st, &db, &keys, &pid, "ok.jpg", "Altro", &data(2000));
    let missing = up(&st, &db, &keys, &pid, "manca.jpg", "Altro", &data(2000));
    let short = up(&st, &db, &keys, &pid, "corto.jpg", "Altro", &data(2000));
    fs::remove_file(st.enc_path(&missing)).unwrap();
    let b = fs::read(st.enc_path(&short)).unwrap();
    fs::write(st.enc_path(&short), &b[..b.len() - 4]).unwrap();
    let orphan = new_uuid();
    fs::copy(st.enc_path(&ok), st.enc_path(&orphan)).unwrap(); // simula un upload il cui DB è stato perso
    fs::write(st.root().join("note.txt"), b"altro").unwrap(); // file estranei ignorati

    let rep = st.check_consistency(&db).unwrap();
    assert_eq!(rep, ConsistencyReport {
        orphan_files: vec![orphan.clone()], missing_files: vec![missing.clone()], size_mismatch: vec![short.clone()],
    });

    {
        let _busy = st.read_lock(); // upload in corso: non si tocca nulla
        assert!(st.quarantine_orphans(&db, Duration::ZERO).unwrap().is_empty());
        assert!(st.enc_path(&orphan).exists());
    }
    assert!(st.quarantine_orphans(&db, Duration::from_secs(3600)).unwrap().is_empty()); // troppo recente
    assert!(st.enc_path(&orphan).exists());

    assert_eq!(st.quarantine_orphans(&db, Duration::ZERO).unwrap(), vec![orphan.clone()]);
    assert!(!st.enc_path(&orphan).exists());
    assert!(st.quarantine_dir().join(format!("{orphan}.enc")).exists()); // spostato, non cancellato
    assert!(st.check_consistency(&db).unwrap().orphan_files.is_empty());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn purge_elimina_prima_il_file_poi_la_riga() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let old = up(&st, &db, &keys, &pid, "vecchio.jpg", "Altro", &data(500));
    let recent = up(&st, &db, &keys, &pid, "recente.jpg", "Altro", &data(500));
    let live = up(&st, &db, &keys, &pid, "attivo.jpg", "Altro", &data(500));
    db.soft_delete_document(&old).unwrap();
    db.soft_delete_document(&recent).unwrap();
    db.conn()
        .execute(
            "UPDATE documents SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','-40 days') WHERE id = ?1",
            rusqlite::params![old],
        )
        .unwrap();
    let rep = st.purge_expired(&db, 30).unwrap();
    assert_eq!(rep, PurgeReport { documents: 1, patients: 0, failed_files: 0 });
    assert!(!st.enc_path(&old).exists());
    assert!(st.enc_path(&recent).exists() && st.enc_path(&live).exists());
    assert_eq!(st.check_consistency(&db).unwrap(), ConsistencyReport::default());
    assert!(db.verify_audit_chain(None).is_ok());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn quarantena_non_sovrascrive_file_gia_presenti() {
    let (dir, st, db, _k) = setup();
    let orphan = new_uuid();
    fs::write(st.enc_path(&orphan), b"nuovo").unwrap();
    fs::write(st.quarantine_dir().join(format!("{orphan}.enc")), b"vecchio").unwrap();
    assert_eq!(st.quarantine_orphans(&db, Duration::ZERO).unwrap(), vec![orphan.clone()]);
    assert_eq!(fs::read(st.quarantine_dir().join(format!("{orphan}.enc"))).unwrap(), b"vecchio");
    assert_eq!(fs::read(st.quarantine_dir().join(format!("{orphan}-2.enc"))).unwrap(), b"nuovo");
    assert!(!st.enc_path(&orphan).exists());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn creazione_vault_rifiutata_anche_con_file_in_quarantena() {
    let (dir, st, _db, _k) = setup();
    fs::remove_file(st.meta_path()).unwrap();
    fs::write(st.quarantine_dir().join(format!("{}.enc", new_uuid())), b"x").unwrap();
    assert!(matches!(st.create_vault_with_params(PW, tp()), Err(StorageError::VaultNotEmpty)));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn rename_senza_sovrascrittura() {
    let dir = tmpdir();
    let (src, dest) = (dir.join("a.part"), dir.join("a.enc"));
    fs::write(&src, b"nuovo").unwrap();
    fs::write(&dest, b"esistente").unwrap();
    let e = rename_no_clobber(&src, &dest).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&dest).unwrap(), b"esistente"); // intatto
    assert!(src.exists()); // la sorgente resta
    fs::remove_file(&dest).unwrap();
    rename_no_clobber(&src, &dest).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"nuovo");
    assert!(!src.exists());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn errori_di_pulizia_non_vengono_ignorati() {
    let dir = tmpdir();
    assert!(remove_checked(&dir.join("non-esiste")).is_ok());
    let blocked = dir.join("export.zip.part");
    fs::create_dir_all(blocked.join("dentro")).unwrap(); // una cartella non si rimuove con remove_file
    assert!(remove_checked(&blocked).is_err());
    match fail_with_cleanup(&blocked, StorageError::VaultMissing) {
        StorageError::CleanupFailed { path, cause, .. } => {
            assert_eq!(path, blocked);
            assert!(cause.contains("vault.meta"));
        }
        other => panic!("atteso CleanupFailed, trovato {other:?}"),
    }
    assert!(matches!(fail_with_cleanup(&dir.join("x"), StorageError::VaultMissing), StorageError::VaultMissing));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn senza_audit_ne_viewer_ne_export_consegnano_dati() {
    let (dir, st, db, keys) = setup();
    let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
    let id = up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &data(3000));
    db.conn().execute_batch("DROP TABLE audit_log;").unwrap(); // l'audit non può più scrivere

    assert!(matches!(st.open_document(&db, &keys, &id, 1 << 20), Err(StorageError::Db(_))));
    let dest = dir.join("out.zip");
    assert!(st.export_patient_zip(&db, &keys, &pid, &dest).is_err());
    assert!(!dest.exists() && !dir.join("out.zip.part").exists()); // nessuno ZIP in chiaro rimasto
    fs::remove_dir_all(dir).ok();
}

#[test]
fn nomi_enc_validi() {
    assert!(is_enc_name(&format!("{}.enc", new_uuid())));
    for bad in ["abc.enc", "vault.meta", "../x.enc", &format!("{}.enc", new_uuid().to_uppercase()),
                &format!("{}.enc.part", new_uuid()), &format!("{{{}}}.enc", new_uuid())] {
        assert!(!is_enc_name(bad), "{bad}");
    }
}
