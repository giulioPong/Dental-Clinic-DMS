//! Errori dello storage.

use super::*;

#[derive(Debug)]
pub enum StorageError {
    Crypto(CryptoError),
    Db(DbError),
    Io(io::Error),
    Zip(zip::result::ZipError),
    VaultAlreadyExists,
    VaultMissing,
    /// La cartella contiene già file `.enc` ma manca `vault.meta`: creare un nuovo
    /// vault li renderebbe illeggibili per sempre.
    VaultNotEmpty,
    FileMissing(String),
    /// Il contenuto decifrato non coincide con dimensione o SHA-256 registrati nel DB.
    IntegrityMismatch(String),
    DestinationExists,
    InvalidInput(&'static str),
    /// L'operazione è fallita E non è stato possibile rimuovere un file in chiaro: va cancellato a mano.
    CleanupFailed { path: PathBuf, cause: String, io: String },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Db(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "errore I/O: {e}"),
            Self::Zip(e) => write!(f, "errore ZIP: {e}"),
            Self::VaultAlreadyExists => write!(f, "vault già esistente"),
            Self::VaultMissing => write!(f, "vault.meta non trovato"),
            Self::VaultNotEmpty => write!(f, "la cartella contiene già documenti cifrati ma manca vault.meta"),
            Self::FileMissing(id) => write!(f, "file cifrato mancante per il documento {id}"),
            Self::IntegrityMismatch(id) => write!(f, "il documento {id} non corrisponde ai dati registrati"),
            Self::DestinationExists => write!(f, "la destinazione esiste già"),
            Self::InvalidInput(m) => write!(f, "dato non valido: {m}"),
            Self::CleanupFailed { path, cause, io } => write!(
                f, "{cause}; inoltre non è stato possibile rimuovere {} ({io}): cancellalo manualmente", path.display()
            ),
        }
    }
}
impl std::error::Error for StorageError {}
impl From<CryptoError> for StorageError { fn from(e: CryptoError) -> Self { Self::Crypto(e) } }
impl From<DbError> for StorageError { fn from(e: DbError) -> Self { Self::Db(e) } }
impl From<io::Error> for StorageError { fn from(e: io::Error) -> Self { Self::Io(e) } }
impl From<zip::result::ZipError> for StorageError { fn from(e: zip::result::ZipError) -> Self { Self::Zip(e) } }
pub type Result<T> = std::result::Result<T, StorageError>;
