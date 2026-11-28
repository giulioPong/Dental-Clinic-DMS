//! Strutture serializzate verso il frontend.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub initialized: bool,
    pub unlocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockInfo {
    /// `false` se il registro degli accessi non coincide con l'ultimo checkpoint salvato.
    pub audit_ok: bool,
    pub audit_message: Option<String>,
    /// Prima riga del registro dove la verifica fallisce, per il banner di allerta.
    pub audit_row_id: Option<i64>,
}

impl UnlockInfo {
    pub(super) fn ok() -> Self {
        UnlockInfo { audit_ok: true, audit_message: None, audit_row_id: None }
    }
    pub(super) fn warn(message: impl Into<String>, row_id: Option<i64>) -> Self {
        UnlockInfo { audit_ok: false, audit_message: Some(message.into()), audit_row_id: row_id }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportDto {
    pub rows: u32,
    /// Esito della verifica della catena al momento dell'export.
    pub audit_ok: bool,
    pub audit_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatientHitDto {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatientDto {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
    pub fiscal_code: Option<String>,
    pub notes: String,
    pub created_at: String,
    pub in_trash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentDto {
    pub id: String,
    pub patient_id: String,
    pub original_filename: String,
    pub mime_type: String,
    pub category_tag: String,
    pub size_bytes: u64,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashedPatientDto {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub birth_date: String,
    pub deleted_at: String,
    pub documents: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashDto {
    pub patients: Vec<TrashedPatientDto>,
    pub documents: Vec<DocumentDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadedDto {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadFailure {
    pub name: String,
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadReport {
    pub uploaded: Vec<UploadedDto>,
    pub failed: Vec<UploadFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDto {
    pub documents: u32,
    pub plain_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceReport {
    pub quarantined_files: u32,
    pub purged_documents: u32,
    pub purged_patients: u32,
    pub failed_files: u32,
}

impl From<DocumentRecord> for DocumentDto {
    fn from(d: DocumentRecord) -> Self {
        Self {
            id: d.id, patient_id: d.patient_id, original_filename: d.original_filename, mime_type: d.mime_type,
            category_tag: d.category_tag, size_bytes: d.size_bytes, created_at: d.created_at, deleted_at: d.deleted_at,
        }
    }
}

// ───────── Import dello storico ─────────

/// Problema su una cartella o su un file dell'import. `file` è il percorso relativo alla
/// cartella del paziente (assente se il problema riguarda la cartella).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportIssueDto {
    pub folder: String,
    pub file: Option<String>,
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPatientDto {
    pub folder: String,
    pub last_name: String,
    pub first_name: String,
    pub birth_date: String,
    pub fiscal_code: Option<String>,
    /// Scheda già presente a cui verranno aggiunti i documenti; `None` = verrà creata.
    pub existing_id: Option<String>,
    pub files: u32,
    pub bytes: u64,
}

/// Anteprima: cosa farebbe l'import, senza scrivere nulla.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewDto {
    pub patients: Vec<ImportPatientDto>,
    pub problems: Vec<ImportIssueDto>,
    pub total_files: u32,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReportDto {
    pub patients_created: u32,
    pub patients_matched: u32,
    pub uploaded: u32,
    /// File già presenti per quel paziente (stesso contenuto): saltati.
    pub duplicates: Vec<ImportIssueDto>,
    /// Cartelle o file non importati, con il motivo.
    pub failed: Vec<ImportIssueDto>,
}
