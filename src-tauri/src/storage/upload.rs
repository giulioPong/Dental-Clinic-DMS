//! Upload cifrato in streaming e lettura per il viewer con verifica di integrità.

use super::*;

impl Storage {
    pub(super) fn store_encrypted<R: Read>(&self, keys: &Keys, doc_id: &str, source: R) -> Result<EncryptedInfo> {
        let dest = self.enc_path(doc_id);
        if dest.exists() {
            return Err(StorageError::Io(io::Error::new(io::ErrorKind::AlreadyExists, "file già esistente")));
        }
        let part = self.tmp_dir().join(format!("{}.part", new_uuid()));
        let result = (|| -> Result<EncryptedInfo> {
            let file = OpenOptions::new().write(true).create_new(true).open(&part)?;
            let mut w = BufWriter::new(file);
            let info = crypto::encrypt_stream(keys.files_key(), doc_id, source, &mut w)?;
            let file = w.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            rename_no_clobber(&part, &dest)?;
            sync_dir(&self.root)?;
            Ok(info)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&part);
        }
        result
    }

    /// Cifra `source` e registra il documento. Restituisce l'id.
    pub fn upload_document<R: Read>(&self, db: &Db, keys: &Keys, req: &UploadRequest, source: R) -> Result<String> {
        if !CATEGORY_TAGS.contains(&req.category_tag) {
            return Err(StorageError::InvalidInput("categoria non valida"));
        }
        let name = req.original_filename.rsplit(['/', '\\']).next().unwrap_or("").trim().to_string();
        if name.is_empty() {
            return Err(StorageError::InvalidInput("nome file non valido"));
        }
        if !db.patient_active(req.patient_id)? {
            return Err(StorageError::Db(DbError::PatientInTrash));
        }
        let _guard = self.read_lock();
        let id = new_uuid();
        let info = match self.store_encrypted(keys, &id, source) {
            Ok(i) => i,
            // store_encrypted ripulisce da sé il proprio .part; un eventuale .enc già
            // rinominato resta come orfano (innocuo) e non si cancella qui.
            Err(e) => return Err(e),
        };
        let res = db.add_document(&NewDocument {
            id: &id,
            patient_id: req.patient_id,
            original_filename: &name,
            mime_type: req.mime_type,
            category_tag: req.category_tag,
            size_bytes: info.size_bytes,
            sha256: info.sha256,
        });
        if let Err(e) = res {
            let _ = fs::remove_file(self.enc_path(&id));
            return Err(e.into());
        }
        Ok(id)
    }

    // ───── lettura ─────

    pub(super) fn check_file(&self, rec: &DocumentRecord) -> Result<()> {
        match crypto::verify_encrypted_file_len(&self.enc_path(&rec.id), rec.size_bytes) {
            Err(CryptoError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Err(StorageError::FileMissing(rec.id.clone())),
            r => Ok(r?),
        }
    }

    /// Viewer: decifra in RAM (mai su disco), verifica dimensione e SHA-256 contro il
    /// DB e registra OPEN_FILE. Se l'audit non si scrive, non restituisce i dati.
    #[cfg(test)]
    pub fn open_document(
        &self, db: &Db, keys: &Keys, doc_id: &str, max_bytes: usize,
    ) -> Result<(DocumentRecord, Zeroizing<Vec<u8>>)> {
        self.open_document_checked(db, keys, doc_id, max_bytes, &|| true)
    }

    /// Come `open_document`; se `proceed()` è falso dopo la decifratura (archivio bloccato
    /// nel frattempo) il buffer viene azzerato, l'audit non viene scritto e si restituisce
    /// `Cancelled`.
    pub fn open_document_checked(
        &self, db: &Db, keys: &Keys, doc_id: &str, max_bytes: usize, proceed: &dyn Fn() -> bool,
    ) -> Result<(DocumentRecord, Zeroizing<Vec<u8>>)> {
        let rec = db.get_document(doc_id)?;
        if rec.deleted_at.is_some() {
            return Err(StorageError::Db(DbError::InvalidState("il documento è nel cestino")));
        }
        if rec.size_bytes > max_bytes as u64 {
            return Err(StorageError::Crypto(CryptoError::TooLarge));
        }
        self.check_file(&rec)?;
        let f = File::open(self.enc_path(&rec.id))?;
        let hint = usize::try_from(rec.size_bytes).unwrap_or(usize::MAX);
        let plain = crypto::decrypt_to_vec(keys.files_key(), &rec.id, f, max_bytes, hint)?;
        if plain.len() as u64 != rec.size_bytes || hex(&Sha256::digest(&plain[..])) != rec.sha256 {
            return Err(StorageError::IntegrityMismatch(rec.id.clone()));
        }
        if !proceed() {
            return Err(StorageError::Cancelled); // `plain` è Zeroizing: azzerato alla drop
        }
        db.log_audit("OPEN_FILE", Some(&rec.id), None)?;
        Ok((rec, plain))
    }
}
