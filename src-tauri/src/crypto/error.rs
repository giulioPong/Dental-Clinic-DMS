//! Errori crittografici.

use super::*;

#[derive(Debug)]
pub enum CryptoError {
    PasswordTooShort,
    /// Password errata OPPURE vault.meta alterato: con GCM non si distinguono.
    WrongPasswordOrCorrupted,
    InvalidMeta(&'static str),
    /// File `.enc` non decifrabile: chiave/id errati, dati alterati o troncati.
    FileCorrupted,
    InvalidFormat(&'static str),
    TooLarge,
    /// Il file `.enc` ha una lunghezza diversa da quella attesa (troncato o aggiunto).
    SizeMismatch { expected: u64, actual: u64 },
    Locked,
    Kdf(String),
    Internal,
    Io(io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordTooShort => write!(f, "password troppo corta (minimo {MIN_PASSWORD_CHARS} caratteri)"),
            Self::WrongPasswordOrCorrupted => write!(f, "password errata oppure vault.meta danneggiato"),
            Self::InvalidMeta(m) => write!(f, "vault.meta non valido: {m}"),
            Self::FileCorrupted => write!(f, "file cifrato danneggiato, alterato o associato a un altro documento"),
            Self::InvalidFormat(m) => write!(f, "formato file non valido: {m}"),
            Self::TooLarge => write!(f, "file troppo grande per l'operazione richiesta"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "dimensione del file cifrato errata (attesi {expected} byte, trovati {actual})")
            }
            Self::Locked => write!(f, "archivio bloccato"),
            Self::Kdf(m) => write!(f, "errore derivazione chiave: {m}"),
            Self::Internal => write!(f, "errore crittografico interno"),
            Self::Io(e) => write!(f, "errore I/O: {e}"),
        }
    }
}
impl std::error::Error for CryptoError {}
impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}
pub type Result<T> = std::result::Result<T, CryptoError>;
