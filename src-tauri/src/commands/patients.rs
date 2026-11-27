//! Comandi sui pazienti: ricerca, schede, cestino. Usano la connessione di sessione.

use super::*;

impl AppCore {
    pub fn search_patients(&self, query: &str, limit: u32) -> Res<Vec<PatientHitDto>> {
        let q: String = query.chars().take(MAX_QUERY_CHARS).collect();
        let limit = limit.clamp(1, MAX_SEARCH_RESULTS);
        let hits = self.with_db(|db| db.search_patients(&q, limit))?;
        Ok(hits
            .into_iter()
            .map(|h| PatientHitDto { id: h.id, first_name: h.first_name, last_name: h.last_name, birth_date: h.birth_date })
            .collect())
    }

    pub(super) fn check_patient_fields(first: &str, last: &str, fiscal_code: Option<&str>, notes: &str) -> Res<()> {
        check_len(first, MAX_NAME_CHARS)?;
        check_len(last, MAX_NAME_CHARS)?;
        check_len(notes, MAX_NOTES_CHARS)?;
        if let Some(cf) = fiscal_code {
            check_len(cf, 32)?;
        }
        Ok(())
    }

    pub fn create_patient(&self, first: &str, last: &str, birth: &str, fiscal_code: Option<&str>) -> Res<String> {
        Self::check_patient_fields(first, last, fiscal_code, "")?;
        self.with_db(|db| db.create_patient(first, last, birth, fiscal_code))
    }

    pub fn update_patient(&self, id: &str, first: &str, last: &str, birth: &str, fiscal_code: Option<&str>, notes: &str) -> Res<()> {
        Self::check_patient_fields(first, last, fiscal_code, notes)?;
        self.with_db(|db| db.update_patient(id, first, last, birth, fiscal_code, notes))
    }

    /// Apre la scheda: registra VIEW_PATIENT, e se l'audit non si scrive non restituisce i dati.
    pub fn get_patient(&self, id: &str) -> Res<PatientDto> {
        self.with_db(|db| {
            let p = db.get_patient(id)?;
            db.log_audit("VIEW_PATIENT", Some(id), None)?;
            Ok(PatientDto {
                id: p.id, first_name: p.first_name, last_name: p.last_name, birth_date: p.birth_date,
                fiscal_code: p.fiscal_code, notes: p.notes, created_at: p.created_at, in_trash: p.deleted_at.is_some(),
            })
        })
    }

    pub fn delete_patient(&self, id: &str) -> Res<()> {
        self.with_db(|db| db.soft_delete_patient(id))
    }
    pub fn restore_patient(&self, id: &str) -> Res<()> {
        self.with_db(|db| db.restore_patient(id))
    }
}
