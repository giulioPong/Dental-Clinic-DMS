//! Pazienti: creazione, modifica, cestino e ricerca full-text.

use super::*;

impl Db {
    pub fn create_patient(&self, first: &str, last: &str, birth: &str, fiscal_code: Option<&str>) -> Result<String> {
        let (first, last) = (first.trim(), last.trim());
        if first.is_empty() || last.is_empty() {
            return Err(DbError::InvalidInput("nome e cognome obbligatori"));
        }
        let cf = normalize_fiscal_code(fiscal_code);
        if let Some(cf) = &cf {
            if cf.len() != 16 || !cf.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(DbError::InvalidInput("codice fiscale non valido"));
            }
        }
        self.tx(|c| {
            check_birth_date(c, birth)?;
            if let Some(cf) = &cf {
                if let Some(existing_id) = active_patient_by_cf(c, cf, None)? {
                    return Err(DbError::DuplicateFiscalCode { existing_id });
                }
            }
            let id = new_uuid();
            c.execute(
                "INSERT INTO patients (id, first_name, last_name, birth_date, fiscal_code)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, first, last, birth, cf],
            )?;
            self.audit_append(c, "CREATE_PATIENT", Some(&id), None)?;
            Ok(id)
        })
    }

    /// Sposta nel cestino il paziente e tutti i suoi documenti attivi (stesso timestamp,
    /// così il ripristino riporta indietro solo quelli).
    pub fn soft_delete_patient(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?;
            match st {
                None => Err(DbError::NotFound),
                Some(Some(_)) => Err(DbError::InvalidState("paziente già nel cestino")),
                Some(None) => {
                    let ts = now(c)?;
                    let n = c.execute(
                        "UPDATE documents SET deleted_at = ?1, trashed_with_patient = 1
                         WHERE patient_id = ?2 AND deleted_at IS NULL",
                        params![ts, id],
                    )?;
                    c.execute("UPDATE patients SET deleted_at = ?1 WHERE id = ?2", params![ts, id])?;
                    self.audit_append(c, "DELETE_PATIENT", Some(id), Some(&format!("documents={n}")))
                }
            }
        })
    }

    /// Fallisce se nel frattempo il codice fiscale è stato usato da un altro paziente attivo.
    pub fn restore_patient(&self, id: &str) -> Result<()> {
        self.tx(|c| {
            let row: Option<(Option<String>, Option<String>)> = c
                .query_row("SELECT deleted_at, fiscal_code FROM patients WHERE id = ?1", params![id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let (ts, cf) = row.ok_or(DbError::NotFound)?;
            ts.ok_or(DbError::InvalidState("il paziente non è nel cestino"))?;
            if let Some(cf) = cf {
                if let Some(existing_id) = active_patient_by_cf(c, &cf, Some(id))? {
                    return Err(DbError::DuplicateFiscalCode { existing_id });
                }
            }
            let n = c.execute(
                "UPDATE documents SET deleted_at = NULL, trashed_with_patient = 0
                 WHERE patient_id = ?1 AND trashed_with_patient = 1",
                params![id],
            )?;
            c.execute("UPDATE patients SET deleted_at = NULL WHERE id = ?1", params![id])?;
            self.audit_append(c, "RESTORE_PATIENT", Some(id), Some(&format!("documents={n}")))
        })
    }

    /// Modifica l'anagrafica di un paziente attivo (stessi controlli della creazione).
    pub fn update_patient(
        &self, id: &str, first: &str, last: &str, birth: &str, fiscal_code: Option<&str>, notes: &str,
    ) -> Result<()> {
        let (first, last, cf) = clean_patient_fields(first, last, fiscal_code)?;
        self.tx(|c| {
            let st: Option<Option<String>> = c
                .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?;
            match st {
                None => return Err(DbError::NotFound),
                Some(Some(_)) => return Err(DbError::PatientInTrash),
                Some(None) => {}
            }
            check_birth_date(c, birth)?;
            if let Some(cf) = &cf {
                if let Some(existing_id) = active_patient_by_cf(c, cf, Some(id))? {
                    return Err(DbError::DuplicateFiscalCode { existing_id });
                }
            }
            c.execute(
                "UPDATE patients SET first_name = ?1, last_name = ?2, birth_date = ?3, fiscal_code = ?4, notes = ?5
                 WHERE id = ?6",
                params![first, last, birth, cf, notes, id],
            )?;
            self.audit_append(c, "UPDATE_PATIENT", Some(id), None)
        })
    }

    /// `Ok(true)` se il paziente esiste ed è attivo, `Ok(false)` se è nel cestino,
    /// `Err(NotFound)` se non esiste.
    pub fn patient_active(&self, id: &str) -> Result<bool> {
        let st: Option<Option<String>> = self
            .conn
            .query_row("SELECT deleted_at FROM patients WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        st.map(|d| d.is_none()).ok_or(DbError::NotFound)
    }

    // ───── ricerca ─────

    /// - Termini >= 3 caratteri: FTS5 (sottostringa, ordinati per rank).
    /// - Termini di 1–2 caratteri: prefisso su cognome O nome (LIKE).
    /// - Più termini: tutti devono corrispondere (AND).
    pub fn search_patients(&self, input: &str, limit: u32) -> Result<Vec<PatientHit>> {
        let (long, short) = split_terms(input);
        if long.is_empty() && short.is_empty() {
            return Ok(vec![]);
        }
        let mut args: Vec<Value> = Vec::new();
        let mut sql = String::from("SELECT p.id, p.first_name, p.last_name, p.birth_date ");
        let order;
        if long.is_empty() {
            sql.push_str("FROM patients p WHERE p.deleted_at IS NULL");
            order = "ORDER BY p.last_name COLLATE NOCASE, p.first_name COLLATE NOCASE";
        } else {
            sql.push_str(
                "FROM patients_fts JOIN patients p ON p.rowid = patients_fts.rowid
                 WHERE patients_fts MATCH ? AND p.deleted_at IS NULL",
            );
            args.push(Value::Text(long.join(" ")));
            order = "ORDER BY rank";
        }
        for t in &short {
            sql.push_str(" AND (p.last_name LIKE ? OR p.first_name LIKE ?)");
            let pat = format!("{t}%");
            args.push(Value::Text(pat.clone()));
            args.push(Value::Text(pat));
        }
        sql.push_str(&format!(" {order} LIMIT ?"));
        args.push(Value::Integer(limit as i64));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            Ok(PatientHit { id: r.get(0)?, first_name: r.get(1)?, last_name: r.get(2)?, birth_date: r.get(3)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Legge un paziente (anche se nel cestino: `deleted_at` lo dice). Non scrive l'audit:
    /// per VIEW_PATIENT usa `log_audit` dal chiamante quando la scheda viene davvero aperta.
    pub fn get_patient(&self, id: &str) -> Result<PatientRecord> {
        self.conn
            .query_row(
                "SELECT id, first_name, last_name, birth_date, fiscal_code, notes, created_at, deleted_at
                 FROM patients WHERE id = ?1",
                params![id],
                |r| {
                    Ok(PatientRecord {
                        id: r.get(0)?, first_name: r.get(1)?, last_name: r.get(2)?, birth_date: r.get(3)?,
                        fiscal_code: r.get(4)?, notes: r.get(5)?, created_at: r.get(6)?, deleted_at: r.get(7)?,
                    })
                },
            )
            .optional()?
            .ok_or(DbError::NotFound)
    }
}

/// Divide l'input in termini "lunghi" (>= 3 caratteri → FTS5 trigram, già
/// racchiusi tra virgolette) e "corti" (1–2 caratteri → prefisso con LIKE,
/// dove i wildcard % e _ vengono rimossi).
pub(super) fn split_terms(input: &str) -> (Vec<String>, Vec<String>) {
    let (mut long, mut short) = (Vec::new(), Vec::new());
    for t in input.split_whitespace() {
        if t.chars().count() >= 3 {
            long.push(format!("\"{}\"", t.replace('"', "\"\"")));
        } else {
            let clean: String = t.chars().filter(|c| *c != '%' && *c != '_').collect();
            if !clean.is_empty() {
                short.push(clean);
            }
        }
    }
    (long, short)
}
