//! Comandi sui documenti: metadati sulla connessione di sessione, operazioni pesanti
//! (upload, viewer, export, manutenzione) su una connessione propria.

use super::*;

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
        let keys = self.auth()?;
        let db = self.heavy_db(&keys)?;
        let mut report = UploadReport::default();
        let files = self.collect_files(paths, &mut report.failed)?;
        let total = files.len();

        for (i, path) in files.iter().enumerate() {
            let name = display_name(path);
            if let Err(e) = self.auth() {
                // archivio bloccato a metà: i file restanti non vengono importati
                for rest in &files[i..] {
                    report.failed.push(UploadFailure { name: display_name(rest), code: e.code, message: e.message.clone() });
                }
                break;
            }
            match self.upload_one(&db, &keys, patient_id, path, &name, category_tag) {
                Ok(id) => report.uploaded.push(UploadedDto { id, name }),
                Err(e) => report.failed.push(UploadFailure { name, code: e.code, message: e.message }),
            }
            on_progress(i + 1, total);
        }
        Ok(report)
    }

    pub(super) fn upload_one(&self, db: &Db, keys: &Keys, patient_id: &str, path: &Path, name: &str, tag: &str) -> Res<String> {
        let file = File::open(path).map_err(|_| CommandError::new(ErrorCode::IoError, "File non leggibile."))?;
        let len = file.metadata().map_err(|_| CommandError::new(ErrorCode::IoError, "File non leggibile."))?.len();
        if len > MAX_UPLOAD_FILE_BYTES {
            return Err(CommandError::new(ErrorCode::TooLarge, "File troppo grande (massimo 4 GB)."));
        }
        let req = UploadRequest { patient_id, original_filename: name, mime_type: mime_for(name), category_tag: tag };
        Ok(self.storage.upload_document(db, keys, &req, BufReader::new(file))?)
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
            let mut children: Vec<PathBuf> = match fs::read_dir(path) {
                Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
                Err(_) => {
                    fail(ErrorCode::IoError, "Cartella non leggibile.");
                    return Ok(());
                }
            };
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
        }
        Ok(())
    }

    /// Viewer: decifra in RAM (limite `viewer_limit`), registra OPEN_FILE.
    pub fn open_document(&self, id: &str) -> Res<(DocumentDto, Zeroizing<Vec<u8>>)> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let db = self.heavy_db(&keys)?;
        let (rec, bytes) = self.storage.open_document(&db, &keys, id, self.viewer_limit)?;
        Ok((rec.into(), bytes))
    }

    /// Esporta in CHIARO. La destinazione deve essere un `.zip` in una cartella esistente e
    /// non dentro il vault (finirebbe nel raggio del backup).
    pub fn export_patient_zip(&self, patient_id: &str, dest: &Path) -> Res<ExportDto> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let is_zip = dest.extension().map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false);
        if !is_zip {
            return Err(CommandError::invalid("Il file di destinazione deve avere estensione .zip."));
        }
        let parent = match dest.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let parent_canon = fs::canonicalize(&parent).map_err(|_| CommandError::invalid("La cartella di destinazione non esiste."))?;
        if let Ok(vault) = fs::canonicalize(&self.vault_dir) {
            if parent_canon.starts_with(&vault) {
                return Err(CommandError::invalid("Scegli una cartella fuori dall'archivio."));
            }
        }
        let db = self.heavy_db(&keys)?;
        let r = self.storage.export_patient_zip(&db, &keys, patient_id, dest)?;
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
