//! Errori verso la UI: codici stabili per il frontend e conversione dagli errori dei moduli.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    Locked,
    WrongPassword,
    TooManyAttempts,
    InvalidInput,
    NotFound,
    InvalidState,
    DuplicateFiscalCode,
    PatientInTrash,
    TooLarge,
    Corrupted,
    FileMissing,
    DbMissing,
    VaultMissing,
    VaultNotEmpty,
    AlreadyInitialized,
    AlreadyExists,
    AuditTampered,
    CleanupFailed,
    DbError,
    IoError,
    Internal,
}

/// Errore serializzabile: la UI reagisce al `code`, mostra `message` (italiano, mai
/// `Debug`, mai percorsi interni) e usa `detail` dove serve (id del duplicato, secondi di attesa).
#[derive(Debug, Clone, Serialize)]
pub struct CommandError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CommandError {
    pub(super) fn new(code: ErrorCode, message: &str) -> Self {
        Self { code, message: message.to_string(), detail: None }
    }
    pub(super) fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
    pub(super) fn locked() -> Self {
        Self::new(ErrorCode::Locked, "Archivio bloccato: inserisci la password.")
    }
    pub(super) fn invalid(msg: &str) -> Self {
        Self::new(ErrorCode::InvalidInput, msg)
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CommandError {}

impl From<CryptoError> for CommandError {
    fn from(e: CryptoError) -> Self {
        use CryptoError::*;
        match e {
            Locked => Self::locked(),
            PasswordTooShort => Self::invalid("Password troppo corta (minimo 10 caratteri)."),
            WrongPasswordOrCorrupted => Self::new(ErrorCode::WrongPassword, "Password errata."),
            InvalidMeta(_) => Self::new(ErrorCode::Corrupted, "File di configurazione del vault non valido."),
            FileCorrupted | InvalidFormat(_) | SizeMismatch { .. } => {
                Self::new(ErrorCode::Corrupted, "File cifrato danneggiato o non coerente con l'archivio.")
            }
            TooLarge => Self::new(ErrorCode::TooLarge, "File troppo grande per l'anteprima."),
            Io(_) => Self::new(ErrorCode::IoError, "Errore di lettura o scrittura su disco."),
            Kdf(_) | Internal => Self::new(ErrorCode::Internal, "Errore crittografico interno."),
        }
    }
}

impl From<DbError> for CommandError {
    fn from(e: DbError) -> Self {
        use DbError::*;
        match e {
            DatabaseMissing => Self::new(ErrorCode::DbMissing, "Database mancante: ripristina dal backup (non viene creato automaticamente)."),
            WrongKeyOrNotDatabase => Self::new(ErrorCode::Corrupted, "Il database non si apre con questa chiave o è danneggiato."),
            AlreadyExists => Self::new(ErrorCode::AlreadyExists, "Il database esiste già."),
            InvalidInput(m) => Self::invalid(m),
            NotFound => Self::new(ErrorCode::NotFound, "Elemento non trovato."),
            InvalidState(m) => Self::new(ErrorCode::InvalidState, m),
            DuplicateFiscalCode { existing_id } => {
                Self::new(ErrorCode::DuplicateFiscalCode, "Esiste già una scheda con questo codice fiscale.").with_detail(existing_id)
            }
            PatientInTrash => Self::new(ErrorCode::PatientInTrash, "Il paziente è nel cestino."),
            AuditTampered { row_id, reason } => {
                let e = Self::new(ErrorCode::AuditTampered, &format!("Registro degli accessi non coerente: {reason}"));
                match row_id {
                    Some(id) => e.with_detail(format!("row_id={id}")),
                    None => e,
                }
            }
            Io(_) => Self::new(ErrorCode::IoError, "Errore di lettura o scrittura su disco."),
            Sqlite(_) => Self::new(ErrorCode::DbError, "Errore del database."),
            SqlcipherMissing => Self::new(ErrorCode::Internal, "Cifratura del database non disponibile in questa build."),
        }
    }
}

impl From<StorageError> for CommandError {
    fn from(e: StorageError) -> Self {
        use StorageError::*;
        match e {
            Crypto(e) => e.into(),
            Db(e) => e.into(),
            Io(_) | Zip(_) => Self::new(ErrorCode::IoError, "Errore di lettura o scrittura su disco."),
            VaultAlreadyExists => Self::new(ErrorCode::AlreadyInitialized, "L'archivio è già stato creato."),
            VaultMissing => Self::new(ErrorCode::VaultMissing, "File vault.meta mancante: ripristina dal backup."),
            VaultNotEmpty => Self::new(
                ErrorCode::VaultNotEmpty,
                "La cartella contiene documenti cifrati ma manca vault.meta: non si crea un nuovo archivio.",
            ),
            FileMissing(_) => Self::new(ErrorCode::FileMissing, "File cifrato mancante: ripristina dal backup."),
            IntegrityMismatch(_) => Self::new(ErrorCode::Corrupted, "Il documento non corrisponde ai dati registrati."),
            DestinationExists => Self::new(ErrorCode::AlreadyExists, "Il file di destinazione esiste già."),
            InvalidInput(m) => Self::invalid(m),
            Cancelled => Self::locked(),
            // Qui il percorso serve: c'è un file in chiaro da cancellare a mano.
            CleanupFailed { path, .. } => Self::new(
                ErrorCode::CleanupFailed,
                &format!("Operazione non riuscita e impossibile rimuovere il file {}: cancellalo manualmente.", path.display()),
            )
            .with_detail(path.display().to_string()),
        }
    }
}

pub(super) type Res<T> = std::result::Result<T, CommandError>;
