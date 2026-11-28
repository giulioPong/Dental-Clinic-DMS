//! Comandi sui documenti: metadati sulla connessione di sessione, operazioni pesanti
//! (upload, viewer, export, manutenzione) su una connessione propria.

use super::*;
use std::cell::Cell;
use std::io::Read;

/// Ogni quanti byte letti l'upload ricontrolla che la sessione sia ancora aperta.
const UPLOAD_CHECK_EVERY: u64 = 8 * 1024 * 1024;

/// Sorgente dell'upload: impone un tetto ai byte letti DAVVERO (il file può crescere dopo
/// il controllo della dimensione) e ogni `UPLOAD_CHECK_EVERY` verifica la sessione. Il
/// motivo dell'interruzione finisce in `stop`, perché l'errore di I/O lo perde.
struct GuardedReader<'a, R> {
    inner: R,
    read: u64,
    limit: u64,
    next_check: u64,
    alive: &'a dyn Fn() -> bool,
    stop: &'a Cell<Option<ErrorCode>>,
}

impl<R: Read> Read for GuardedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read >= self.next_check {
            if !(self.alive)() {
                self.stop.set(Some(ErrorCode::Locked));
                return Err(std::io::Error::other("archivio bloccato durante l'import"));
            }
            self.next_check = self.read + UPLOAD_CHECK_EVERY;
        }
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        if self.read > self.limit {
            self.stop.set(Some(ErrorCode::TooLarge));
            return Err(std::io::Error::other("limite di dimensione superato"));
        }
        Ok(n)
    }
}

impl AppCore {
    pub fn list_documents(&self, patient_id: &str, tag: Option<&str>) -> Res<Vec<DocumentDto>> {
        let docs = self.with_db(|db| db.list_documents(patient_id, tag))?;
        Ok(docs.into_iter().map(Into::into).collect())
    }
    pub fn delete_document(&self, id: &str) -> Res<()> {
        self.with_db(|db| db.soft_delete_document(id))
    }
    pub fn restore_document(&self, id: &str) -> Res<()> {
        self.with_db(|db| db.restore_document(id))
    }
    pub fn reassign_document(&self, doc_id: &str, new_patient_id: &str) -> Res<()> {
        self.with_db(|db| db.reassign_document(doc_id, new_patient_id))
    }

    pub fn list_trash(&self) -> Res<TrashDto> {
        let t = self.with_db(|db| db.list_trash())?;
        Ok(TrashDto {
            patients: t
                .patients
                .into_iter()
                .map(|p| TrashedPatientDto {
                    id: p.id, first_name: p.first_name, last_name: p.last_name, birth_date: p.birth_date,
                    deleted_at: p.deleted_at, documents: p.documents,
                })
                .collect(),
            documents: t.documents.into_iter().map(Into::into).collect(),
        })
    }

    // ───── operazioni pesanti ─────

    /// Importa file e cartelle (percorsi scelti dall'utente, mai contenuti via IPC). Un errore
    /// su un file non ferma gli altri: finisce in `failed`. Collegamenti simbolici e file del
    /// vault vengono ignorati e segnalati. `on_progress(fatti, totali)` dopo ogni file.
    pub fn upload_documents(
        &self,
        patient_id: &str,
        paths: &[String],
        category_tag: &str,
        mut on_progress: impl FnMut(usize, usize),
    ) -> Res<UploadReport> {
        let _op = self.begin_op();
        let (keys, epoch) = self.op_session()?;
        let db = self.heavy_db(&keys)?;
        let mut report = UploadReport::default();
        let files = self.collect_files(paths, &mut report.failed)?;
        let total = files.len();
        let total_bytes: u64 = files.iter().filter_map(|p| fs::metadata(p).ok()).map(|m| m.len()).sum();
        if total_bytes > MAX_UPLOAD_BATCH_BYTES {
            return Err(CommandError::new(ErrorCode::TooLarge, "Import troppo grande (massimo 20 GB per operazione): dividilo in più parti."));
        }
        let mut budget = MAX_UPLOAD_BATCH_BYTES;

        for (i, path) in files.iter().enumerate() {
            let name = display_name(path);
            let session = self.auth().and_then(|_| if self.still_current(epoch) { Ok(()) } else { Err(CommandError::locked()) });
            if let Err(e) = session {
                // archivio bloccato a metà: i file restanti non vengono importati
                for rest in &files[i..] {
                    report.failed.push(UploadFailure { name: display_name(rest), code: e.code, message: e.message.clone() });
                }
                break;
            }
            match self.upload_one(&db, &keys, patient_id, path, &name, category_tag, epoch, &mut budget) {
                Ok(id) => report.uploaded.push(UploadedDto { id, name }),
                Err(e) => report.failed.push(UploadFailure { name, code: e.code, message: e.message }),
            }
            on_progress(i + 1, total);
        }
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn upload_one(
        &self, db: &Db, keys: &Keys, patient_id: &str, path: &Path, name: &str, tag: &str,
        epoch: u64, budget: &mut u64,
    ) -> Res<String> {
        let file = File::open(path).map_err(|_| CommandError::new(ErrorCode::IoError, "File non leggibile."))?;
        let len = file.metadata().map_err(|_| CommandError::new(ErrorCode::IoError, "File non leggibile."))?.len();
        if len > MAX_UPLOAD_FILE_BYTES {
            return Err(CommandError::new(ErrorCode::TooLarge, "File troppo grande (massimo 4 GB)."));
        }
        let req = UploadRequest { patient_id, original_filename: name, mime_type: mime_for(name), category_tag: tag };
        let stop = Cell::new(None);
        let alive = || self.still_current(epoch);
        let mut reader = GuardedReader {
            inner: BufReader::new(file),
            read: 0,
            limit: MAX_UPLOAD_FILE_BYTES.min(*budget),
            next_check: 0,
            alive: &alive,
            stop: &stop,
        };
        let r = self.storage.upload_document(db, keys, &req, &mut reader);
        *budget = budget.saturating_sub(reader.read);
        r.map_err(|e| match stop.get() {
            Some(ErrorCode::Locked) => CommandError::locked(),
            Some(ErrorCode::TooLarge) => CommandError::new(
                ErrorCode::TooLarge,
                "File troppo grande, cresciuto durante l'import o oltre il limite dell'operazione.",
            ),
            _ => e.into(),
        })
    }

    pub(super) fn collect_files(&self, paths: &[String], failures: &mut Vec<UploadFailure>) -> Res<Vec<PathBuf>> {
        let vault = fs::canonicalize(&self.vault_dir).ok();
        let mut out = Vec::new();
        for p in paths {
            self.walk(Path::new(p), 0, &vault, &mut out, failures)?;
        }
        Ok(out)
    }

    pub(super) fn walk(&self, path: &Path, depth: usize, vault: &Option<PathBuf>, out: &mut Vec<PathBuf>, failures: &mut Vec<UploadFailure>) -> Res<()> {
        let name = display_name(path);
        let mut fail = |code: ErrorCode, msg: &str| failures.push(UploadFailure { name: name.clone(), code, message: msg.to_string() });
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => {
                fail(ErrorCode::NotFound, "File o cartella non trovati.");
                return Ok(());
            }
        };
        if meta.file_type().is_symlink() {
            fail(ErrorCode::InvalidInput, "Collegamento simbolico ignorato.");
            return Ok(());
        }
        if let (Some(v), Ok(c)) = (vault, fs::canonicalize(path)) {
            if c.starts_with(v) {
                fail(ErrorCode::InvalidInput, "File dell'archivio ignorato.");
                return Ok(());
            }
        }
        if meta.is_dir() {
            if depth >= MAX_DIR_DEPTH {
                fail(ErrorCode::InvalidInput, "Cartella troppo annidata: ignorata.");
                return Ok(());
            }
            let mut children: Vec<PathBuf> = Vec::new();
            let mut unreadable = 0usize;
            match fs::read_dir(path) {
                Ok(rd) => {
                    for e in rd {
                        match e {
                            Ok(e) => children.push(e.path()),
                            Err(_) => unreadable += 1,
                        }
                    }
                }
                Err(_) => {
                    fail(ErrorCode::IoError, "Cartella non leggibile.");
                    return Ok(());
                }
            }
            if unreadable > 0 {
                // la cartella si importa comunque, ma va detto che qualcosa è rimasto fuori
                fail(ErrorCode::IoError, &format!("{unreadable} elementi della cartella non leggibili: non importati."));
            }
            children.sort();
            for child in children {
                if is_ignored_child(&display_name(&child)) {
                    continue;
                }
                self.walk(&child, depth + 1, vault, out, failures)?;
            }
        } else if meta.is_file() {
            if out.len() >= MAX_FILES_PER_UPLOAD {
                return Err(CommandError::invalid("Troppi file in una sola operazione (massimo 5000)."));
            }
            out.push(path.to_path_buf());
        } else {
            fail(ErrorCode::InvalidInput, "Elemento non supportato (né file né cartella): ignorato.");
        }
        Ok(())
    }

    /// Viewer: decifra in RAM (limite `viewer_limit`), registra OPEN_FILE.
    pub fn open_document(&self, id: &str) -> Res<(DocumentDto, Zeroizing<Vec<u8>>)> {
        let _op = self.begin_op();
        let (keys, epoch) = self.op_session()?;
        let db = self.heavy_db(&keys)?;
        let (rec, bytes) =
            self.storage.open_document_checked(&db, &keys, id, self.viewer_limit, &|| self.still_current(epoch))?;
        Ok((rec.into(), bytes))
    }

    /// Esporta in CHIARO. La destinazione deve essere un `.zip` in una cartella esistente e
    /// non dentro il vault (finirebbe nel raggio del backup).
    pub fn export_patient_zip(&self, patient_id: &str, dest: &Path) -> Res<ExportDto> {
        let _op = self.begin_op();
        let (keys, epoch) = self.op_session()?;
        check_export_dest(&self.vault_dir, dest, "zip")?;
        let db = self.heavy_db(&keys)?;
        let r = self.storage.export_patient_zip_checked(&db, &keys, patient_id, dest, &|| self.still_current(epoch))?;
        Ok(ExportDto { documents: r.documents, plain_bytes: r.plain_bytes })
    }

    /// Quarantena degli orfani (solo file più vecchi di 5 minuti) e purge del cestino scaduto (30 giorni).
    pub fn maintenance(&self) -> Res<MaintenanceReport> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let db = self.heavy_db(&keys)?;
        let quarantined = self.storage.quarantine_orphans(&db, ORPHAN_MIN_AGE)?;
        let purge = self.storage.purge_expired(&db, TRASH_RETENTION_DAYS)?;
        Ok(MaintenanceReport {
            quarantined_files: quarantined.len() as u32,
            purged_documents: purge.documents,
            purged_patients: purge.patients,
            failed_files: purge.failed_files,
        })
    }
}
