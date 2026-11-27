//! Documenti: metadati, cestino, riassegnazione e purge dei record scaduti.

use super::*;

impl Db {
    /// Va chiamata DOPO che il file `<id>.enc` è stato scritto e sincronizzato su disco:
    /// il caso peggiore in un blackout è un `.enc` orfano, non una riga senza file.
    pub fn add_document(&self, d: &NewDocument) -> Result<()> {
        let name = d.original_filename.trim();
        if name.is_empty() || name.len() > 255 {
            return Err(DbError::InvalidInput("nome file non valido"));
        }
        if !CATEGORY_TAGS.contains(&d.category_tag) {
            return Err(DbError::InvalidInput("categoria non valida"));
        }
        let size = i64::try_from(d.size_bytes).map_err(|_| DbError::InvalidInput("dimensione non valida"))?;
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![d.patient_id], |r| r.get(0))
                .optional()?;
            match st {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::PatientInTrash),
                Some(None) => {}
            }
            c.execute(
                "INSERT INTO documents (id, patient_id, original_filename, mime_type, category_tag,
                                        encrypted_path, size_bytes, sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?1 || '.enc', ?6, ?7)",
                params![d.id, d.patient_id, name, d.mime_type, d.category_tag, size, hex(&d.sha256)],
            )?;
            self.audit_append(c, "UPLOAD_FILE", Some(d.id), None)
        })
    }

    pub fn soft_delete_document(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM documents WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?;
            match st {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::InvalidState("documento già nel cestino")),
                Some(None) => {}
            }
            c.execute("UPDATE documents SET deleted_at = ?1 WHERE id = ?2", params![now(c)?, id])?;
            self.audit_append(c, "DELETE_FILE", Some(id), None)
        })
    }

    /// Rifiutato se il paziente è nel cestino: va ripristinato prima il paziente.
    pub fn restore_document(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let row: Option<(Option<String>, Option<String>)> = c
                .query_row(
                    "SELECT d.deleted_at, p.deleted_at FROM documents d JOIN patients p ON p.id = d.patient_id
                     WHERE d.id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (doc_del, pat_del) = row.ok_or(DbError::NotFound)?;
            if doc_del.is_none() {
                return Err(DbError::InvalidState("il documento non è nel cestino"));
            }
            if pat_del.is_some() {
                return Err(DbError::PatientInTrash);
            }
            c.execute(
                "UPDATE documents SET deleted_at = NULL, trashed_with_patient = 0 WHERE id = ?1",
                params![id],
            )?;
            self.audit_append(c, "RESTORE_FILE", Some(id), None)
        })
    }

    /// Elimina definitivamente ciò che è nel cestino da più di `retention_days`.
    /// Per ogni documento, in tre passi:
    /// 1. `stage(nome)` mette da parte il file (riceve solo `<uuid>.enc`): `Ok(true)` se
    ///    spostato, `Ok(false)` se già assente, `Err` se non spostabile (la riga resta e si
    ///    riprova alla prossima esecuzione);
    /// 2. una transazione cancella la riga e registra PURGE_FILE;
    /// 3. `finish(nome, spostato, confermato)` cancella il file messo da parte se la
    ///    transazione è riuscita, altrimenti lo rimette al suo posto.
    /// Così un errore del database non lascia mai una riga senza file. I pazienti si
    /// eliminano solo quando non hanno più documenti. L'audit non si tocca.
    pub fn purge_expired(
        &self,
        retention_days: u32,
        mut stage: impl FnMut(&str) -> io::Result<bool>,
        mut finish: impl FnMut(&str, bool, bool),
    ) -> Result<PurgeReport> {
        let modifier = format!("-{retention_days} days");
        let mut report = PurgeReport::default();

        let docs: Vec<(String, String)> = {
            let mut st = self.conn.prepare(
                "SELECT d.id, d.encrypted_path FROM documents d JOIN patients p ON p.id = d.patient_id
                 WHERE (d.deleted_at IS NOT NULL AND d.deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?1))
                    OR (p.deleted_at IS NOT NULL AND p.deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?1))",
            )?;
            let rows = st.query_map(params![modifier], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, path) in docs {
            let staged = match stage(&path) {
                Ok(s) => s,
                Err(_) => { report.failed_files += 1; continue; }
            };
            let r = self.tx(|c| {
                c.execute("DELETE FROM documents WHERE id = ?1", params![id])?;
                self.audit_append(c, "PURGE_FILE", Some(&id), None)
            });
            finish(&path, staged, r.is_ok());
            r?;
            report.documents += 1;
        }

        let pats: Vec<String> = {
            let mut st = self.conn.prepare(
                "SELECT id FROM patients p
                 WHERE deleted_at IS NOT NULL AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?1)
                   AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.patient_id = p.id)",
            )?;
            let rows = st.query_map(params![modifier], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for id in pats {
            self.tx(|c| {
                c.execute("DELETE FROM patients WHERE id = ?1", params![id])?;
                self.audit_append(c, "PURGE_PATIENT", Some(&id), None)
            })?;
            report.patients += 1;
        }
        Ok(report)
    }

    /// Contenuto del cestino, dal più recente.
    pub fn list_trash(&self) -> Result<Trash> {
        let mut st = self.conn.prepare(
            "SELECT p.id, p.first_name, p.last_name, p.birth_date, p.deleted_at,
                    (SELECT count(*) FROM documents d WHERE d.patient_id = p.id)
             FROM patients p WHERE p.deleted_at IS NOT NULL ORDER BY p.deleted_at DESC, p.id",
        )?;
        let patients = st
            .query_map([], |r| {
                let n: i64 = r.get(5)?;
                Ok(TrashedPatient {
                    id: r.get(0)?, first_name: r.get(1)?, last_name: r.get(2)?, birth_date: r.get(3)?,
                    deleted_at: r.get(4)?, documents: n as u32,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut st = self.conn.prepare(&format!(
            "SELECT {DOC_COLS} FROM documents
             WHERE deleted_at IS NOT NULL AND trashed_with_patient = 0 ORDER BY deleted_at DESC, id"
        ))?;
        let documents = st.query_map([], doc_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Trash { patients, documents })
    }

    pub fn get_document(&self, id: &str) -> Result<DocumentRecord> {
        self.conn
            .query_row(&format!("SELECT {DOC_COLS} FROM documents WHERE id = ?1"), params![id], doc_from_row)
            .optional()?
            .ok_or(DbError::NotFound)
    }

    /// Documenti ATTIVI di un paziente, dal più recente; `tag` filtra per categoria.
    pub fn list_documents(&self, patient_id: &str, tag: Option<&str>) -> Result<Vec<DocumentRecord>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {DOC_COLS} FROM documents
             WHERE patient_id = ?1 AND deleted_at IS NULL AND (?2 IS NULL OR category_tag = ?2)
             ORDER BY created_at DESC, id"
        ))?;
        let rows = st.query_map(params![patient_id, tag], doc_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Tutti i documenti, cestinati compresi (controlli di coerenza con la cartella).
    pub fn all_documents(&self) -> Result<Vec<DocumentRecord>> {
        let mut st = self.conn.prepare(&format!("SELECT {DOC_COLS} FROM documents ORDER BY created_at, id"))?;
        let rows = st.query_map([], doc_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Sposta un documento attivo a un altro paziente attivo. Il file `.enc` non si
    /// tocca: `patient_id` non fa parte dell'AAD. In `details` solo gli id.
    pub fn reassign_document(&self, doc_id: &str, new_patient_id: &str) -> Result<()> {
        self.tx(|c| {
            let row: Option<(String, Option<String>)> = c
                .query_row("SELECT patient_id, deleted_at FROM documents WHERE id = ?1", params![doc_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let (old, deleted) = row.ok_or(DbError::NotFound)?;
            if deleted.is_some() {
                return Err(DbError::InvalidState("il documento è nel cestino"));
            }
            if old == new_patient_id {
                return Err(DbError::InvalidState("il documento è già associato a questo paziente"));
            }
            let target: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![new_patient_id], |r| r.get(0))
                .optional()?;
            match target {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::PatientInTrash),
                Some(None) => {}
            }
            c.execute("UPDATE documents SET patient_id = ?1 WHERE id = ?2", params![new_patient_id, doc_id])?;
            self.audit_append(c, "REASSIGN_DOCUMENT", Some(doc_id), Some(&format!("from={old};to={new_patient_id}")))
        })
    }
}
