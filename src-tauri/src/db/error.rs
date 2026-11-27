//! Errori del database.

use super::*;

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    /// La build non include SQLCipher: `PRAGMA key` sarebbe ignorato in silenzio
    /// e il database resterebbe in chiaro. Si rifiuta di aprirlo.
    SqlcipherMissing,
    WrongKeyOrNotDatabase,
    /// Il file del database manca o è vuoto: `open` non lo crea mai.
    DatabaseMissing,
    AlreadyExists,
    InvalidInput(&'static str),
    NotFound,
    InvalidState(&'static str),
    DuplicateFiscalCode { existing_id: String },
    PatientInTrash,
    AuditTampered(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "errore database: {e}"),
            Self::Io(e) => write!(f, "errore I/O: {e}"),
            Self::SqlcipherMissing => write!(f, "SQLCipher non disponibile in questa build"),
            Self::WrongKeyOrNotDatabase => write!(f, "chiave errata o file non è un database cifrato"),
            Self::DatabaseMissing => write!(f, "database mancante o vuoto: non viene creato automaticamente"),
            Self::AlreadyExists => write!(f, "il database esiste già"),
            Self::InvalidInput(m) => write!(f, "dato non valido: {m}"),
            Self::NotFound => write!(f, "elemento non trovato"),
            Self::InvalidState(m) => write!(f, "operazione non consentita: {m}"),
            Self::DuplicateFiscalCode { existing_id } => {
                write!(f, "esiste già una scheda con questo codice fiscale ({existing_id})")
            }
            Self::PatientInTrash => write!(f, "il paziente è nel cestino"),
            Self::AuditTampered(m) => write!(f, "audit log manomesso: {m}"),
        }
    }
}
impl std::error::Error for DbError {}
impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self { Self::Sqlite(e) }
}
impl From<io::Error> for DbError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}
pub type Result<T> = std::result::Result<T, DbError>;
