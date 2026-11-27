//! Livello applicativo tra l'interfaccia (Tauri/React) e i moduli `db`, `crypto`, `storage`.
//!
//! Tutta la logica sta qui ed è indipendente da Tauri, quindi si prova con `cargo test`.
//! `tauri_api.rs` contiene solo gli involucri `#[tauri::command]`.
//!
//! Cargo.toml: vedi `Cargo.dependencies.toml` (serde, serde_json per i test).
//!
//! # Sessione e blocco
//! - Finché l'archivio è bloccato NON esiste nessuna connessione al database.
//! - Dopo lo sblocco c'è una sola `Session` (connessione SQLCipher + copia delle chiavi,
//!   azzerate alla drop). `lock()`, il blocco per inattività e un comando che trova la
//!   sessione scaduta la eliminano: la connessione si chiude e la cache decifrata sparisce.
//! - Ogni comando autenticato passa da `auth()`: verifica la scadenza e rinvia il timer.
//! - Le operazioni veloci (ricerca, schede, cestino) usano la connessione di sessione sotto
//!   `Mutex`. Le operazioni pesanti (upload, viewer, export, manutenzione, snapshot) aprono
//!   una connessione propria (WAL consente più connessioni), così una scansione 3D da
//!   centinaia di MB non blocca la ricerca. L'audit resta una catena unica: ogni scrittura
//!   è una transazione IMMEDIATE.
//!
//! # Backup: il DB viene copiato dall'app, non dallo scheduler
//! Una copia cifrata del DB richiede la chiave, e la chiave nasce dalla password: uno
//! scheduler non presidiato (le 20:00) non può ottenerla. Quindi l'app, mentre è sbloccata,
//! scrive uno snapshot consistente e cifrato in `snapshot_dir` (alla chiusura della sessione
//! e periodicamente), e restic/borg salvano quella cartella + `vault/` (con `vault.meta`).
//! Limite: se l'app resta chiusa per giorni, lo snapshot è quello dell'ultima chiusura.

pub mod tauri_api;

use crate::crypto::{CryptoError, KdfParams, KeyStore, Keys};
use crate::db::{AuditCheckpoint, Db, DbError, DocumentRecord};
use crate::storage::{Storage, StorageError, UploadRequest};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod error;
mod dto;
mod util;
mod throttle;
mod patients;
mod documents;

pub use dto::*;
pub use error::*;
use throttle::*;
use util::*;

pub const ACTOR: &str = "admin";
pub const MAX_VIEWER_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_SEARCH_RESULTS: u32 = 100;
pub const MAX_QUERY_CHARS: usize = 200;
pub const MAX_UPLOAD_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_FILES_PER_UPLOAD: usize = 5000;
const MAX_DIR_DEPTH: usize = 10;
const MAX_NAME_CHARS: usize = 100;
const MAX_NOTES_CHARS: usize = 10_000;
const TRASH_RETENTION_DAYS: u32 = 30;
const ORPHAN_MIN_AGE: Duration = Duration::from_secs(300);
const THROTTLE_FREE_ATTEMPTS: u32 = 5;
const THROTTLE_BASE_SECS: u64 = 30;
const THROTTLE_MAX_SECS: u64 = 300;

// ───────── Stato applicativo ─────────

struct Session {
    db: Db,
    keys: Keys,
}

pub struct AppCore {
    vault_dir: PathBuf,
    db_path: PathBuf,
    snapshot_dir: Option<PathBuf>,
    storage: Storage,
    keystore: KeyStore,
    session: Mutex<Option<Session>>,
    throttle: Mutex<Throttle>,
    /// Operazioni pesanti in corso (ognuna con chiavi e connessione proprie).
    ops: Mutex<usize>,
    ops_done: Condvar,
    kdf: KdfParams,
    viewer_limit: usize,
}

struct OpGuard<'a>(&'a AppCore);

impl Drop for OpGuard<'_> {
    fn drop(&mut self) {
        let mut n = self.0.ops.lock().unwrap_or_else(|e| e.into_inner());
        *n -= 1;
        if *n == 0 {
            self.0.ops_done.notify_all();
        }
    }
}

impl AppCore {
    pub fn new(vault_dir: &Path, db_path: &Path, idle_timeout: Duration) -> Res<AppCore> {
        let storage = Storage::open(vault_dir)?; // crea le cartelle e svuota vault/tmp
        Ok(AppCore {
            vault_dir: vault_dir.to_path_buf(),
            db_path: db_path.to_path_buf(),
            snapshot_dir: None,
            storage,
            keystore: KeyStore::new(idle_timeout),
            session: Mutex::new(None),
            throttle: Mutex::new(Throttle::default()),
            ops: Mutex::new(0),
            ops_done: Condvar::new(),
            kdf: KdfParams::DEFAULT,
            viewer_limit: MAX_VIEWER_BYTES,
        })
    }

    /// Cartella dove l'app scrive lo snapshot cifrato del DB (da includere nel backup).
    pub fn with_snapshot_dir(mut self, dir: &Path) -> Self {
        self.snapshot_dir = Some(dir.to_path_buf());
        self
    }
    pub fn with_kdf_params(mut self, p: KdfParams) -> Self {
        self.kdf = p;
        self
    }
    pub fn with_viewer_limit(mut self, bytes: usize) -> Self {
        self.viewer_limit = bytes;
        self
    }

    fn lock_session(&self) -> MutexGuard<'_, Option<Session>> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn lock_throttle(&self) -> MutexGuard<'_, Throttle> {
        self.throttle.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn meta_path(&self) -> PathBuf {
        self.vault_dir.join("vault.meta")
    }
    fn checkpoint_path(&self) -> PathBuf {
        self.vault_dir.join("audit.checkpoint")
    }

    // ───── ciclo di vita ─────

    pub fn status(&self) -> Status {
        let unlocked = self.keystore.is_unlocked();
        if !unlocked {
            // scaduta: la connessione non deve restare aperta
            self.close_session_logged("status");
        }
        Status { initialized: self.meta_path().exists(), unlocked }
    }

    /// Primo avvio: crea `vault.meta` e il database. Se la creazione del DB fallisce,
    /// `vault.meta` viene rimosso (è sicuro: `create_vault` rifiuta se esistono già `.enc`).
    pub fn setup_vault(&self, password: &str) -> Res<UnlockInfo> {
        if self.meta_path().exists() {
            return Err(CommandError::new(ErrorCode::AlreadyInitialized, "L'archivio è già stato creato."));
        }
        let keys = self.storage.create_vault_with_params(password, self.kdf)?;
        let db = match Db::create(&self.db_path, &keys, ACTOR) {
            Ok(d) => d,
            Err(e) => {
                let _ = fs::remove_file(self.meta_path());
                return Err(e.into());
            }
        };
        self.start_session(keys, db);
        Ok(UnlockInfo { audit_ok: true, audit_message: None })
    }

    pub fn unlock(&self, password: &str) -> Res<UnlockInfo> {
        self.lock_throttle().check()?;
        let keys = match self.storage.unlock(password) {
            Ok(k) => k,
            Err(StorageError::Crypto(CryptoError::WrongPasswordOrCorrupted)) => {
                self.lock_throttle().fail();
                return Err(CryptoError::WrongPasswordOrCorrupted.into());
            }
            Err(e) => return Err(e.into()),
        };
        let db = Db::open(&self.db_path, &keys, ACTOR)?; // non crea mai il database
        self.lock_throttle().reset();
        let info = self.audit_info(&db);
        self.start_session(keys, db);
        Ok(info)
    }

    fn start_session(&self, keys: Keys, db: Db) {
        self.keystore.unlock(keys.clone());
        *self.lock_session() = Some(Session { db, keys });
    }

    /// Blocco manuale. Azzera le chiavi, chiude la connessione, salva checkpoint e snapshot.
    /// Non aspetta le operazioni pesanti in corso: si fermano al prossimo controllo di
    /// `auth()` e rilasciano la loro copia delle chiavi quando terminano.
    /// `Ok(false)` se era già bloccato; `Err` se la sessione è stata chiusa ma il
    /// salvataggio di checkpoint o snapshot è fallito.
    pub fn lock(&self) -> Res<bool> {
        self.keystore.lock(); // prima le chiavi: i comandi in arrivo trovano `Locked`
        self.close_session()
    }

    /// Chiusura dell'app: blocca, poi aspetta (al massimo `wait`) che le operazioni pesanti
    /// terminino, così nessuna copia delle chiavi o connessione propria sopravvive al
    /// salvataggio finale. Lo snapshot viene scritto in ogni caso; l'errore segnala se
    /// qualcosa è rimasto in sospeso o se il salvataggio è fallito.
    pub fn shutdown(&self, wait: Duration) -> Res<()> {
        self.keystore.lock();
        let deadline = Instant::now() + wait;
        let mut pending = self.ops.lock().unwrap_or_else(|e| e.into_inner());
        while *pending > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            pending = self.ops_done.wait_timeout(pending, left).unwrap_or_else(|e| e.into_inner()).0;
        }
        let still_running = *pending;
        drop(pending);
        self.close_session()?;
        if still_running > 0 {
            return Err(CommandError::new(
                ErrorCode::Internal,
                "Chiusura con operazioni ancora in corso: lo snapshot potrebbe non includerle.",
            ));
        }
        Ok(())
    }

    /// Da chiamare ogni pochi secondi da un thread. `Ok(true)` se ha appena bloccato;
    /// `Err` se ha bloccato ma il salvataggio di checkpoint o snapshot è fallito.
    pub fn expire_if_idle(&self) -> Res<bool> {
        if self.keystore.expire_if_idle() {
            self.close_session()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Elimina la sessione: la connessione e la copia delle chiavi vengono rilasciate in
    /// ogni caso, dopo aver tentato checkpoint dell'audit e snapshot. `Ok(false)` se non
    /// c'era nessuna sessione; il primo errore di salvataggio viene restituito.
    fn close_session(&self) -> Res<bool> {
        let Some(s) = self.lock_session().take() else {
            return Ok(false);
        };
        let checkpoint = self.write_checkpoint(&s.db);
        let snapshot = match &self.snapshot_dir {
            Some(dir) => write_snapshot(&s.db, &s.keys, dir),
            None => Ok(()),
        };
        drop(s);
        checkpoint?;
        snapshot?;
        Ok(true)
    }

    /// Per i percorsi che scoprono la scadenza dentro un altro comando: l'errore di quel
    /// comando è `Locked`, quindi quello di salvataggio può solo essere registrato.
    fn close_session_logged(&self, ctx: &str) {
        if let Err(e) = self.close_session() {
            eprintln!("[dms] chiusura sessione ({ctx}): {}", e.message);
        }
    }

    /// Registra un'operazione pesante; il guard va preso PRIMA di `auth()`, così
    /// `shutdown()` (che azzera le chiavi e poi conta) non può perderla.
    fn begin_op(&self) -> OpGuard<'_> {
        *self.ops.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        OpGuard(self)
    }

    fn auth(&self) -> Res<Keys> {
        match self.keystore.keys() {
            Ok(k) => Ok(k),
            Err(e) => {
                if matches!(e, CryptoError::Locked) {
                    self.close_session_logged("auth");
                }
                Err(e.into())
            }
        }
    }

    fn with_db<T>(&self, f: impl FnOnce(&Db) -> Result<T, DbError>) -> Res<T> {
        let _keys = self.auth()?;
        let g = self.lock_session();
        let s = g.as_ref().ok_or_else(CommandError::locked)?;
        Ok(f(&s.db)?)
    }

    /// Connessione propria per le operazioni lunghe.
    fn heavy_db(&self, keys: &Keys) -> Res<Db> {
        Ok(Db::open(&self.db_path, keys, ACTOR)?)
    }

    fn write_checkpoint(&self, db: &Db) -> Res<()> {
        let cp = db.audit_checkpoint()?;
        write_replace_synced(&self.checkpoint_path(), cp.to_line().as_bytes())
            .map_err(|_| CommandError::new(ErrorCode::IoError, "Impossibile salvare il checkpoint dell'audit."))
    }

    fn audit_info(&self, db: &Db) -> UnlockInfo {
        let ok = UnlockInfo { audit_ok: true, audit_message: None };
        let cp = match fs::read_to_string(self.checkpoint_path()) {
            Ok(s) => match AuditCheckpoint::from_line(&s) {
                Some(c) => Some(c),
                None => return UnlockInfo { audit_ok: false, audit_message: Some("Checkpoint del registro accessi illeggibile.".into()) },
            },
            Err(_) => None,
        };
        match db.verify_audit_chain(cp.as_ref()) {
            Ok(_) => ok,
            Err(e) => UnlockInfo { audit_ok: false, audit_message: Some(CommandError::from(e).message) },
        }
    }

    pub fn change_password(&self, old_password: &str, new_password: &str) -> Res<()> {
        self.auth()?;
        self.lock_throttle().check()?;
        match self.storage.change_password(old_password, new_password) {
            Ok(()) => {
                self.lock_throttle().reset();
                Ok(()) // la master key non cambia: la sessione in corso resta valida
            }
            Err(StorageError::Crypto(CryptoError::WrongPasswordOrCorrupted)) => {
                self.lock_throttle().fail();
                Err(CryptoError::WrongPasswordOrCorrupted.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Snapshot cifrato e consistente del DB in `snapshot_dir`, più il checkpoint dell'audit.
    /// Pensato per il thread periodico: NON conta come attività (non rinvia il blocco per
    /// inattività) e usa la sessione già aperta. Il DB contiene solo metadati: è piccolo.
    pub fn snapshot_db(&self) -> Res<()> {
        if !self.keystore.is_unlocked() {
            self.close_session()?;
            return Err(CommandError::locked());
        }
        let dir = self.snapshot_dir.as_ref().ok_or_else(|| CommandError::invalid("Cartella di backup non configurata."))?;
        let g = self.lock_session();
        let s = g.as_ref().ok_or_else(CommandError::locked)?;
        write_snapshot(&s.db, &s.keys, dir)?;
        self.write_checkpoint(&s.db)
    }
}

#[cfg(test)]
mod tests;
