//! Coerenza tra DB e file, quarantena degli orfani e purge del cestino.

use super::*;

impl Storage {
    pub fn check_consistency(&self, db: &Db) -> Result<ConsistencyReport> {
        let docs = db.all_documents()?;
        let known: HashSet<&str> = docs.iter().map(|d| d.id.as_str()).collect();
        let on_disk = self.list_enc_ids()?;
        let present: HashSet<&str> = on_disk.iter().map(|s| s.as_str()).collect();
        let mut report = ConsistencyReport::default();
        for id in &on_disk {
            if !known.contains(id.as_str()) {
                report.orphan_files.push(id.clone());
            }
        }
        for d in &docs {
            if !present.contains(d.id.as_str()) {
                report.missing_files.push(d.id.clone());
            } else if matches!(self.check_file(d), Err(StorageError::Crypto(CryptoError::SizeMismatch { .. }))) {
                report.size_mismatch.push(d.id.clone());
            }
        }
        Ok(report)
    }

    /// Sposta in `quarantine/` (non cancella) i `.enc` senza riga nel DB più vecchi di
    /// `min_age`. Non fa nulla mentre c'è un upload in corso.
    pub fn quarantine_orphans(&self, db: &Db, min_age: Duration) -> Result<Vec<String>> {
        // Lock in scrittura per tutta l'operazione: se c'è un upload in corso non si fa nulla.
        let _exclusive = match self.upload_lock.try_write() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return Ok(Vec::new()),
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
        };
        let mut moved = Vec::new();
        for id in self.check_consistency(db)?.orphan_files {
            let src = self.enc_path(&id);
            let age = fs::metadata(&src)?.modified()?.elapsed().unwrap_or(Duration::ZERO);
            if age < min_age {
                continue;
            }
            // creazione esclusiva del nome di destinazione: niente corsa exists()+rename
            let mut n = 1;
            loop {
                let name = if n == 1 { format!("{id}.enc") } else { format!("{id}-{n}.enc") };
                match rename_no_clobber(&src, &self.quarantine_dir().join(name)) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1,
                    Err(e) => return Err(e.into()),
                }
            }
            moved.push(id);
        }
        if !moved.is_empty() {
            sync_dir(&self.root)?; // rimozione dalla sorgente
            sync_dir(&self.quarantine_dir())?; // comparsa nella destinazione
        }
        Ok(moved)
    }

    /// Elimina definitivamente il cestino scaduto. Il file passa da `purging/` e si cancella
    /// solo dopo che la riga è stata eliminata; prima si sistemano i resti di un purge
    /// interrotto.
    pub fn purge_expired(&self, db: &Db, retention_days: u32) -> Result<PurgeReport> {
        self.recover_purging(db)?;
        let staged_path = |name: &str| self.purging_dir().join(name);
        let report = db.purge_expired(
            retention_days,
            |name| {
                if !is_enc_name(name) {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "nome file non valido"));
                }
                match rename_no_clobber(&self.root.join(name), &staged_path(name)) {
                    Ok(()) => Ok(true),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(e),
                }
            },
            |name, staged, committed| {
                if !staged {
                    return;
                }
                // se uno dei due fallisce, ci pensa `recover_purging` alla prossima esecuzione
                if committed {
                    let _ = fs::remove_file(staged_path(name));
                } else {
                    let _ = rename_no_clobber(&staged_path(name), &self.root.join(name));
                }
            },
        )?;
        sync_dir(&self.root)?;
        sync_dir(&self.purging_dir())?;
        Ok(report)
    }

    /// File rimasti in `purging/` da un purge interrotto (crash, blackout): se la riga
    /// esiste ancora il file torna al suo posto, altrimenti il purge era stato confermato e
    /// il file si cancella.
    pub(super) fn recover_purging(&self, db: &Db) -> Result<()> {
        for entry in fs::read_dir(self.purging_dir())? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_enc_name(&name) {
                continue;
            }
            let id = name.trim_end_matches(".enc");
            match db.get_document(id) {
                Ok(_) => match rename_no_clobber(&entry.path(), &self.root.join(&name)) {
                    Ok(()) => {}
                    // c'è già un file con quel nome al suo posto: si tiene quello, il doppione resta qui
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                },
                Err(DbError::NotFound) => remove_checked(&entry.path())?,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
