//! Storage: cartella `vault/` con i file `.enc`, `vault.meta`, upload atomico,
//! viewer in memoria, export ZIP (in chiaro), controlli di coerenza.
//!
//! Cargo.toml:
//! ```toml
//! zip = { version = "0.6", default-features = false, features = ["deflate"] }
//! ```
//!
//! Layout:
//! ```text
//! vault/
//!   vault.meta              master key avvolta + parametri Argon2 (scritta in modo atomico)
//!   <doc_id>.enc            un file cifrato per documento
//!   tmp/                    file parziali (*.part), svuotata all'avvio
//!   quarantine/             .enc senza riga nel DB (mai cancellati in automatico)
//! ```
//!
//! # Invarianti
//! - Upload: cifra in `tmp/<uuid>.part` → `fsync` → `rename` in `<doc_id>.enc` →
//!   SOLO ALLORA la riga nel DB. Il caso peggiore dopo un crash è un `.enc` orfano.
//! - Nessun file decifrato viene mai scritto su disco, tranne lo ZIP di export, che
//!   per scelta è in chiaro (è il suo scopo: far uscire i dati dal vault).
//! - Gli `.enc` senza riga NON si cancellano: dopo il ripristino di un backup vecchio
//!   del DB sono gli unici originali. Si spostano in `quarantine/`.

use crate::crypto::{self, hex, CryptoError, EncryptedInfo, KdfParams, Keys};
use crate::db::{new_uuid, Db, DbError, DocumentRecord, NewDocument, PurgeReport, CATEGORY_TAGS};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard, TryLockError};
use std::time::Duration;
use zeroize::Zeroizing;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

mod error;
mod fsutil;
mod upload;
mod export;
mod maintenance;

pub use error::*;
use fsutil::*;

// ───────── Storage ─────────

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConsistencyReport {
    /// File `.enc` senza riga nel DB (id del documento).
    pub orphan_files: Vec<String>,
    /// Righe nel DB (cestino compreso) senza file.
    pub missing_files: Vec<String>,
    /// File presenti ma di lunghezza diversa da quella attesa (troncati o aggiunti).
    pub size_mismatch: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExportReport {
    pub documents: u32,
    pub plain_bytes: u64,
}

pub struct UploadRequest<'a> {
    pub patient_id: &'a str,
    pub original_filename: &'a str,
    pub mime_type: &'a str,
    pub category_tag: &'a str,
}

pub struct Storage {
    root: PathBuf,
    /// Gli upload prendono il lock in lettura (possono essere concorrenti) per tutta la
    /// durata "scrivi .enc → inserisci riga"; la quarantena lo prende in scrittura, quindi
    /// non può mai vedere un `.enc` la cui riga non è ancora stata scritta.
    upload_lock: RwLock<()>,
}

impl Storage {
    /// Crea le cartelle se mancano e svuota `tmp/` (residui di un crash). Da chiamare
    /// una sola volta all'avvio, prima di qualunque upload.
    pub fn open(root: &Path) -> Result<Storage> {
        fs::create_dir_all(root.join("tmp"))?;
        fs::create_dir_all(root.join("quarantine"))?;
        let s = Storage { root: root.to_path_buf(), upload_lock: RwLock::new(()) };
        for entry in fs::read_dir(s.tmp_dir())? {
            let p = entry?.path();
            if p.is_file() {
                let _ = fs::remove_file(p);
            }
        }
        Ok(s)
    }

    pub fn root(&self) -> &Path { &self.root }
    fn read_lock(&self) -> RwLockReadGuard<'_, ()> {
        self.upload_lock.read().unwrap_or_else(|e| e.into_inner())
    }
    fn tmp_dir(&self) -> PathBuf { self.root.join("tmp") }
    fn quarantine_dir(&self) -> PathBuf { self.root.join("quarantine") }
    fn enc_path(&self, doc_id: &str) -> PathBuf { self.root.join(format!("{doc_id}.enc")) }
    fn meta_path(&self) -> PathBuf { self.root.join("vault.meta") }
    fn meta_tmp(&self) -> PathBuf { self.root.join("vault.meta.tmp") }
    fn meta_bak(&self) -> PathBuf { self.root.join("vault.meta.bak") }

    fn list_enc_ids(&self) -> io::Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if is_enc_name(name) {
                    ids.push(name[..36].to_string());
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    // ───── vault.meta ─────

    pub fn create_vault(&self, password: &str) -> Result<Keys> {
        self.create_vault_with_params(password, KdfParams::DEFAULT)
    }

    pub fn create_vault_with_params(&self, password: &str, params: KdfParams) -> Result<Keys> {
        if self.meta_path().exists() {
            return Err(StorageError::VaultAlreadyExists);
        }
        if !self.list_enc_ids()?.is_empty() || has_enc_files(&self.quarantine_dir())? {
            return Err(StorageError::VaultNotEmpty);
        }
        let nv = crypto::create_vault_with_params(password, params)?;
        write_new_synced(&self.meta_tmp(), &nv.meta_bytes)?;
        fs::rename(self.meta_tmp(), self.meta_path())?;
        sync_dir(&self.root)?;
        // conferma: il file scritto deve davvero aprirsi con la password
        crypto::unlock_vault(&fs::read(self.meta_path())?, password)?;
        Ok(nv.keys)
    }

    pub fn unlock(&self, password: &str) -> Result<Keys> {
        let meta = match fs::read(self.meta_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.meta_bak().exists() => Vec::new(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StorageError::VaultMissing),
            Err(e) => return Err(e.into()),
        };
        match crypto::unlock_vault(&meta, password) {
            Ok(keys) => {
                // Un `.bak` rimasto contiene la master key avvolta con la VECCHIA password:
                // finché esiste, quella password continuerebbe ad aprire tutto. Se non si
                // riesce a rimuoverlo lo sblocco fallisce: meglio saperlo subito.
                remove_if_exists(&self.meta_bak())?;
                remove_if_exists(&self.meta_tmp())?;
                sync_dir(&self.root)?;
                Ok(keys)
            }
            // vault.meta illeggibile (non una password errata) e copia di riserva presente
            Err(CryptoError::InvalidMeta(_)) if self.meta_bak().exists() => {
                let bak = fs::read(self.meta_bak())?;
                let keys = crypto::unlock_vault(&bak, password)?;
                write_new_synced(&self.meta_tmp(), &bak)?;
                fs::rename(self.meta_tmp(), self.meta_path())?;
                sync_dir(&self.root)?;
                remove_if_exists(&self.meta_bak())?;
                sync_dir(&self.root)?;
                Ok(keys)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Sequenza a prova di crash: scrive la nuova versione in `.tmp` (fsync), salva la
    /// vecchia in `.bak`, `rename`, verifica che la nuova password apra davvero il file
    /// e solo allora cancella il `.bak` (altrimenti ripristina la vecchia).
    pub fn change_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let current = match fs::read(self.meta_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StorageError::VaultMissing),
            Err(e) => return Err(e.into()),
        };
        let new_bytes = crypto::change_password(&current, old_password, new_password)?;
        write_new_synced(&self.meta_tmp(), &new_bytes)?;
        write_new_synced(&self.meta_bak(), &current)?;
        fs::rename(self.meta_tmp(), self.meta_path())?;
        sync_dir(&self.root)?;
        match crypto::unlock_vault(&fs::read(self.meta_path())?, new_password) {
            Ok(_) => {
                fs::remove_file(self.meta_bak())?;
                sync_dir(&self.root)?;
                Ok(())
            }
            Err(e) => {
                write_new_synced(&self.meta_tmp(), &current)?;
                fs::rename(self.meta_tmp(), self.meta_path())?;
                sync_dir(&self.root)?;
                let _ = fs::remove_file(self.meta_bak());
                Err(e.into())
            }
        }
    }

}

#[cfg(test)]
mod tests;
