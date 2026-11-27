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

// ───────── Errori verso la UI ─────────

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
    fn new(code: ErrorCode, message: &str) -> Self {
        Self { code, message: message.to_string(), detail: None }
    }
    fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
    fn locked() -> Self {
        Self::new(ErrorCode::Locked, "Archivio bloccato: inserisci la password.")
    }
    fn invalid(msg: &str) -> Self {
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
            AuditTampered(m) => Self::new(ErrorCode::AuditTampered, &format!("Registro degli accessi non coerente: {m}")),
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
            // Qui il percorso serve: c'è un file in chiaro da cancellare a mano.
            CleanupFailed { path, .. } => Self::new(
                ErrorCode::CleanupFailed,
                &format!("Operazione non riuscita e impossibile rimuovere il file {}: cancellalo manualmente.", path.display()),
            )
            .with_detail(path.display().to_string()),
        }
    }
}

type Res<T> = std::result::Result<T, CommandError>;

// ───────── DTO ─────────

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

// ───────── Utilità ─────────

fn display_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.to_string_lossy().into_owned())
}

fn mime_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "pdf" => "application/pdf",
        "dcm" => "application/dicom",
        "stl" => "model/stl",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// File di sistema che non vanno importati quando si trascina una cartella.
fn is_ignored_child(name: &str) -> bool {
    name.starts_with('.') || name.eq_ignore_ascii_case("thumbs.db") || name.eq_ignore_ascii_case("desktop.ini")
}

fn check_len(s: &str, max: usize) -> Res<()> {
    if s.chars().count() > max { Err(CommandError::invalid("Testo troppo lungo.")) } else { Ok(()) }
}

fn write_replace_synced(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dest)
}

fn write_snapshot(db: &Db, keys: &Keys, dir: &Path) -> Res<()> {
    fs::create_dir_all(dir).map_err(|_| CommandError::new(ErrorCode::IoError, "Cartella di backup non accessibile."))?;
    let tmp = dir.join("gestionale.db.new");
    let _ = fs::remove_file(&tmp);
    db.backup_to(&tmp, keys)?;
    fs::rename(&tmp, dir.join("gestionale.db")).map_err(|_| CommandError::new(ErrorCode::IoError, "Impossibile salvare lo snapshot del database."))
}

// ───────── Tentativi di sblocco ─────────

#[derive(Default)]
struct Throttle {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl Throttle {
    fn check(&self) -> Res<()> {
        if let Some(t) = self.blocked_until {
            let now = Instant::now();
            if t > now {
                let secs = (t - now).as_secs() + 1;
                return Err(CommandError::new(ErrorCode::TooManyAttempts, &format!("Troppi tentativi: riprova tra {secs} secondi."))
                    .with_detail(secs.to_string()));
            }
        }
        Ok(())
    }
    fn fail(&mut self) {
        self.failures += 1;
        if self.failures >= THROTTLE_FREE_ATTEMPTS {
            let exp = (self.failures - THROTTLE_FREE_ATTEMPTS).min(8);
            let secs = (THROTTLE_BASE_SECS << exp).min(THROTTLE_MAX_SECS);
            self.blocked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }
    fn reset(&mut self) {
        *self = Throttle::default();
    }
}

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

    // ───── pazienti ─────

    pub fn search_patients(&self, query: &str, limit: u32) -> Res<Vec<PatientHitDto>> {
        let q: String = query.chars().take(MAX_QUERY_CHARS).collect();
        let limit = limit.clamp(1, MAX_SEARCH_RESULTS);
        let hits = self.with_db(|db| db.search_patients(&q, limit))?;
        Ok(hits
            .into_iter()
            .map(|h| PatientHitDto { id: h.id, first_name: h.first_name, last_name: h.last_name, birth_date: h.birth_date })
            .collect())
    }

    fn check_patient_fields(first: &str, last: &str, fiscal_code: Option<&str>, notes: &str) -> Res<()> {
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

    // ───── documenti (metadati) ─────

    pub fn list_documents(&self, patient_id: &str, tag: Option<&str>) -> Res<Vec<DocumentDto>> {
        let docs = self.with_db(|db| db.list_documents(patient_id, tag))?;
        Ok(docs.into_iter().map(Into::into).collect())
    }
    pub fn delete_document(&self, id: &str) -> Res<()> {
        self.with_db(|db| db.soft_delete_document(id))
    }
    pub fn restore_document(&self, id: &str) -> Res<()> {
        self.with_db(|db| db.restore_document(id))
    }
    pub fn reassign_document(&self, doc_id: &str, new_patient_id: &str) -> Res<()> {
        self.with_db(|db| db.reassign_document(doc_id, new_patient_id))
    }

    pub fn list_trash(&self) -> Res<TrashDto> {
        let t = self.with_db(|db| db.list_trash())?;
        Ok(TrashDto {
            patients: t
                .patients
                .into_iter()
                .map(|p| TrashedPatientDto {
                    id: p.id, first_name: p.first_name, last_name: p.last_name, birth_date: p.birth_date,
                    deleted_at: p.deleted_at, documents: p.documents,
                })
                .collect(),
            documents: t.documents.into_iter().map(Into::into).collect(),
        })
    }

    // ───── operazioni pesanti ─────

    /// Importa file e cartelle (percorsi scelti dall'utente, mai contenuti via IPC). Un errore
    /// su un file non ferma gli altri: finisce in `failed`. Collegamenti simbolici e file del
    /// vault vengono ignorati e segnalati. `on_progress(fatti, totali)` dopo ogni file.
    pub fn upload_documents(
        &self,
        patient_id: &str,
        paths: &[String],
        category_tag: &str,
        mut on_progress: impl FnMut(usize, usize),
    ) -> Res<UploadReport> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let db = self.heavy_db(&keys)?;
        let mut report = UploadReport::default();
        let files = self.collect_files(paths, &mut report.failed)?;
        let total = files.len();

        for (i, path) in files.iter().enumerate() {
            let name = display_name(path);
            if let Err(e) = self.auth() {
                // archivio bloccato a metà: i file restanti non vengono importati
                for rest in &files[i..] {
                    report.failed.push(UploadFailure { name: display_name(rest), code: e.code, message: e.message.clone() });
                }
                break;
            }
            match self.upload_one(&db, &keys, patient_id, path, &name, category_tag) {
                Ok(id) => report.uploaded.push(UploadedDto { id, name }),
                Err(e) => report.failed.push(UploadFailure { name, code: e.code, message: e.message }),
            }
            on_progress(i + 1, total);
        }
        Ok(report)
    }

    fn upload_one(&self, db: &Db, keys: &Keys, patient_id: &str, path: &Path, name: &str, tag: &str) -> Res<String> {
        let file = File::open(path).map_err(|_| CommandError::new(ErrorCode::IoError, "File non leggibile."))?;
        let len = file.metadata().map_err(|_| CommandError::new(ErrorCode::IoError, "File non leggibile."))?.len();
        if len > MAX_UPLOAD_FILE_BYTES {
            return Err(CommandError::new(ErrorCode::TooLarge, "File troppo grande (massimo 4 GB)."));
        }
        let req = UploadRequest { patient_id, original_filename: name, mime_type: mime_for(name), category_tag: tag };
        Ok(self.storage.upload_document(db, keys, &req, BufReader::new(file))?)
    }

    fn collect_files(&self, paths: &[String], failures: &mut Vec<UploadFailure>) -> Res<Vec<PathBuf>> {
        let vault = fs::canonicalize(&self.vault_dir).ok();
        let mut out = Vec::new();
        for p in paths {
            self.walk(Path::new(p), 0, &vault, &mut out, failures)?;
        }
        Ok(out)
    }

    fn walk(&self, path: &Path, depth: usize, vault: &Option<PathBuf>, out: &mut Vec<PathBuf>, failures: &mut Vec<UploadFailure>) -> Res<()> {
        let name = display_name(path);
        let mut fail = |code: ErrorCode, msg: &str| failures.push(UploadFailure { name: name.clone(), code, message: msg.to_string() });
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => {
                fail(ErrorCode::NotFound, "File o cartella non trovati.");
                return Ok(());
            }
        };
        if meta.file_type().is_symlink() {
            fail(ErrorCode::InvalidInput, "Collegamento simbolico ignorato.");
            return Ok(());
        }
        if let (Some(v), Ok(c)) = (vault, fs::canonicalize(path)) {
            if c.starts_with(v) {
                fail(ErrorCode::InvalidInput, "File dell'archivio ignorato.");
                return Ok(());
            }
        }
        if meta.is_dir() {
            if depth >= MAX_DIR_DEPTH {
                fail(ErrorCode::InvalidInput, "Cartella troppo annidata: ignorata.");
                return Ok(());
            }
            let mut children: Vec<PathBuf> = match fs::read_dir(path) {
                Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
                Err(_) => {
                    fail(ErrorCode::IoError, "Cartella non leggibile.");
                    return Ok(());
                }
            };
            children.sort();
            for child in children {
                if is_ignored_child(&display_name(&child)) {
                    continue;
                }
                self.walk(&child, depth + 1, vault, out, failures)?;
            }
        } else if meta.is_file() {
            if out.len() >= MAX_FILES_PER_UPLOAD {
                return Err(CommandError::invalid("Troppi file in una sola operazione (massimo 5000)."));
            }
            out.push(path.to_path_buf());
        }
        Ok(())
    }

    /// Viewer: decifra in RAM (limite `viewer_limit`), registra OPEN_FILE.
    pub fn open_document(&self, id: &str) -> Res<(DocumentDto, Zeroizing<Vec<u8>>)> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let db = self.heavy_db(&keys)?;
        let (rec, bytes) = self.storage.open_document(&db, &keys, id, self.viewer_limit)?;
        Ok((rec.into(), bytes))
    }

    /// Esporta in CHIARO. La destinazione deve essere un `.zip` in una cartella esistente e
    /// non dentro il vault (finirebbe nel raggio del backup).
    pub fn export_patient_zip(&self, patient_id: &str, dest: &Path) -> Res<ExportDto> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let is_zip = dest.extension().map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false);
        if !is_zip {
            return Err(CommandError::invalid("Il file di destinazione deve avere estensione .zip."));
        }
        let parent = match dest.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let parent_canon = fs::canonicalize(&parent).map_err(|_| CommandError::invalid("La cartella di destinazione non esiste."))?;
        if let Ok(vault) = fs::canonicalize(&self.vault_dir) {
            if parent_canon.starts_with(&vault) {
                return Err(CommandError::invalid("Scegli una cartella fuori dall'archivio."));
            }
        }
        let db = self.heavy_db(&keys)?;
        let r = self.storage.export_patient_zip(&db, &keys, patient_id, dest)?;
        Ok(ExportDto { documents: r.documents, plain_bytes: r.plain_bytes })
    }

    /// Quarantena degli orfani (solo file più vecchi di 5 minuti) e purge del cestino scaduto (30 giorni).
    pub fn maintenance(&self) -> Res<MaintenanceReport> {
        let _op = self.begin_op();
        let keys = self.auth()?;
        let db = self.heavy_db(&keys)?;
        let quarantined = self.storage.quarantine_orphans(&db, ORPHAN_MIN_AGE)?;
        let purge = self.storage.purge_expired(&db, TRASH_RETENTION_DAYS)?;
        Ok(MaintenanceReport {
            quarantined_files: quarantined.len() as u32,
            purged_documents: purge.documents,
            purged_patients: purge.patients,
            failed_files: purge.failed_files,
        })
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

// ───────── TEST ─────────
#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }
    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("gestionale-cmd-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        d
    }
    fn core_with(idle: Duration) -> (PathBuf, AppCore) {
        let dir = tmpdir();
        let c = AppCore::new(&dir.join("vault"), &dir.join("gestionale.db"), idle)
            .unwrap()
            .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 });
        (dir, c)
    }
    fn core() -> (PathBuf, AppCore) {
        core_with(Duration::from_secs(600))
    }
    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }
    fn code<T: std::fmt::Debug>(r: Res<T>) -> ErrorCode {
        r.unwrap_err().code
    }

    #[test]
    fn flusso_completo_e_sblocco_successivo() {
        let (dir, c) = core();
        assert_eq!(c.status(), Status { initialized: false, unlocked: false });
        assert_eq!(code(c.search_patients("ross", 10)), ErrorCode::Locked);

        assert!(c.setup_vault(PW).unwrap().audit_ok);
        assert_eq!(c.status(), Status { initialized: true, unlocked: true });
        assert_eq!(code(c.setup_vault(PW)), ErrorCode::AlreadyInitialized);

        let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let f = dir.join("rx.jpg");
        fs::write(&f, data(5000)).unwrap();
        let mut progress = Vec::new();
        let rep = c.upload_documents(&pid, &[s(&f)], "Panoramica", |d, t| progress.push((d, t))).unwrap();
        assert_eq!((rep.uploaded.len(), rep.failed.len()), (1, 0));
        assert_eq!(progress, vec![(1, 1)]);

        let docs = c.list_documents(&pid, None).unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].mime_type, "image/jpeg");
        let (meta, bytes) = c.open_document(&docs[0].id).unwrap();
        assert_eq!(&bytes[..], &data(5000)[..]);
        assert_eq!(meta.original_filename, "rx.jpg");

        let zip = dir.join("out.zip");
        assert_eq!(c.export_patient_zip(&pid, &zip).unwrap().documents, 1);
        assert_eq!(c.get_patient(&pid).unwrap().last_name, "Rossi");

        assert!(c.lock().unwrap());
        assert_eq!(c.status(), Status { initialized: true, unlocked: false });
        assert_eq!(code(c.open_document(&docs[0].id)), ErrorCode::Locked);
        assert_eq!(code(c.unlock("password sbagliata")), ErrorCode::WrongPassword);
        let info = c.unlock(PW).unwrap();
        assert!(info.audit_ok, "{:?}", info.audit_message);
        assert_eq!(c.search_patients("ross", 10).unwrap().len(), 1);

        // l'audit è una catena unica anche se scritto da connessioni diverse
        let keys = c.storage.unlock(PW).unwrap();
        let db = Db::open(&c.db_path, &keys, "t").unwrap();
        assert!(db.verify_audit_chain(None).unwrap() >= 5); // paziente, upload, apertura, export, vista
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn il_blocco_chiude_la_connessione_e_azzera_la_sessione() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        assert!(c.lock_session().is_some());
        c.lock().unwrap();
        assert!(c.lock_session().is_none());
        assert!(!c.keystore.is_unlocked());
        assert!(!c.lock().unwrap()); // già bloccato
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn blocco_per_inattivita_con_e_senza_watcher() {
        let (dir, c) = core_with(Duration::from_millis(300));
        c.setup_vault(PW).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert!(c.expire_if_idle().unwrap()); // il thread di fondo blocca e può emettere vault-locked
        assert!(c.lock_session().is_none());
        assert!(!c.expire_if_idle().unwrap());

        c.unlock(PW).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        // senza watcher: il primo comando trova la sessione scaduta e la elimina
        assert_eq!(code(c.search_patients("abc", 5)), ErrorCode::Locked);
        assert!(c.lock_session().is_none());

        c.unlock(PW).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(c.status().unlocked, false); // anche status() chiude la sessione scaduta
        assert!(c.lock_session().is_none());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn lo_snapshot_periodico_non_rinvia_il_blocco() {
        let dir = tmpdir();
        let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_millis(400))
            .unwrap()
            .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
            .with_snapshot_dir(&dir.join("staging"));
        c.setup_vault(PW).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        c.snapshot_db().unwrap(); // non è attività dell'utente
        std::thread::sleep(Duration::from_millis(250));
        assert!(c.expire_if_idle().unwrap()); // 500 ms dall'ultima attività vera, nonostante lo snapshot a 250
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn i_comandi_rinviano_il_blocco() {
        let (dir, c) = core_with(Duration::from_millis(600));
        c.setup_vault(PW).unwrap();
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(250));
            assert!(c.search_patients("abc", 5).is_ok()); // ogni uso azzera il timer
        }
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn tentativi_di_sblocco_limitati() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        c.lock().unwrap();
        for _ in 0..4 {
            assert_eq!(code(c.unlock("sbagliata sbagliata")), ErrorCode::WrongPassword);
        }
        assert!(c.unlock(PW).is_ok()); // dopo 4 errori la password giusta passa e azzera il contatore
        c.lock().unwrap();
        for _ in 0..5 {
            assert_eq!(code(c.unlock("sbagliata sbagliata")), ErrorCode::WrongPassword);
        }
        let e = c.unlock(PW).unwrap_err(); // anche la password giusta viene rifiutata durante l'attesa
        assert_eq!(e.code, ErrorCode::TooManyAttempts);
        assert!(e.detail.unwrap().parse::<u64>().unwrap() >= 1);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cambio_password_dalla_sessione() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        assert_eq!(code(c.change_password("sbagliata sbagliata", "nuova password lunga")), ErrorCode::WrongPassword);
        assert_eq!(code(c.change_password(PW, "corta")), ErrorCode::InvalidInput);
        c.change_password(PW, "nuova password lunga").unwrap();
        assert!(c.search_patients("abc", 5).is_ok()); // la sessione resta valida
        c.lock().unwrap();
        assert_eq!(code(c.unlock(PW)), ErrorCode::WrongPassword);
        assert!(c.unlock("nuova password lunga").is_ok());
        c.lock().unwrap();
        assert_eq!(code(c.change_password(PW, "x")), ErrorCode::Locked);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn il_database_non_viene_mai_creato_allo_sblocco() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        c.lock().unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", s(&dir.join("gestionale.db"))));
        }
        assert_eq!(code(c.unlock(PW)), ErrorCode::DbMissing);
        assert!(!dir.join("gestionale.db").exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn setup_fallito_non_lascia_un_vault_senza_database() {
        let (dir, c) = core();
        fs::write(dir.join("gestionale.db"), b"qualcosa").unwrap(); // un file occupa già il posto del DB
        assert!(c.setup_vault(PW).is_err());
        assert!(!dir.join("vault").join("vault.meta").exists());
        assert_eq!(c.status(), Status { initialized: false, unlocked: false });
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn limite_di_ricerca_e_validazione_input() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        for i in 0..105 {
            c.create_patient(&format!("Prova{i:03}"), "Test", "1990-01-01", None).unwrap();
        }
        assert_eq!(c.search_patients("test", 5000).unwrap().len(), 100);
        assert_eq!(c.search_patients("test", 0).unwrap().len(), 1);
        assert_eq!(code(c.create_patient(&"x".repeat(101), "Test", "1990-01-01", None)), ErrorCode::InvalidInput);
        assert_eq!(code(c.create_patient("A", "Bbb", "2023-02-30", None)), ErrorCode::InvalidInput);
        let long = "a".repeat(10_000);
        assert!(c.search_patients(&long, 10).is_ok()); // la query viene troncata, non rifiutata
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn codice_fiscale_duplicato_riporta_l_id_esistente() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let a = c.create_patient("Mario", "Rossi", "1980-05-12", Some("RSSMRA80E12A944X")).unwrap();
        let e = c.create_patient("Altro", "Paziente", "1990-01-01", Some("rssmra80e12a944x")).unwrap_err();
        assert_eq!(e.code, ErrorCode::DuplicateFiscalCode);
        assert_eq!(e.detail.as_deref(), Some(a.as_str()));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn upload_di_cartelle_con_esclusioni_e_errori_per_file() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let root = dir.join("storico");
        fs::create_dir_all(root.join("2019/endorali")).unwrap();
        fs::write(root.join("pano.png"), data(3000)).unwrap();
        fs::write(root.join("2019/referto.pdf"), data(1000)).unwrap();
        fs::write(root.join("2019/endorali/e1.jpg"), data(500)).unwrap();
        fs::write(root.join(".DS_Store"), b"x").unwrap();
        fs::write(root.join("Thumbs.db"), b"x").unwrap();
        fs::create_dir_all(root.join(".nascosta")).unwrap();
        fs::write(root.join(".nascosta/x.jpg"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("pano.png"), root.join("collegamento.png")).unwrap();
        let vault_file = dir.join("vault").join("vault.meta");

        let mut calls = 0;
        let rep = c
            .upload_documents(&pid, &[s(&root), s(&dir.join("non-esiste.jpg")), s(&vault_file)], "Altro", |_, t| {
                calls += 1;
                assert_eq!(t, 3);
            })
            .unwrap();
        assert_eq!(rep.uploaded.len(), 3);
        assert_eq!(calls, 3);
        let names: Vec<&str> = rep.uploaded.iter().map(|u| u.name.as_str()).collect();
        assert!(names.contains(&"pano.png") && names.contains(&"referto.pdf") && names.contains(&"e1.jpg"));
        let failed: Vec<(&str, ErrorCode)> = rep.failed.iter().map(|f| (f.name.as_str(), f.code)).collect();
        assert!(failed.contains(&("non-esiste.jpg", ErrorCode::NotFound)));
        assert!(failed.contains(&("vault.meta", ErrorCode::InvalidInput)));
        #[cfg(unix)]
        assert!(failed.contains(&("collegamento.png", ErrorCode::InvalidInput)));

        // paziente nel cestino: ogni file fallisce con il codice giusto, nessun file lasciato
        c.delete_patient(&pid).unwrap();
        let rep2 = c.upload_documents(&pid, &[s(&root.join("pano.png"))], "Altro", |_, _| {}).unwrap();
        assert!(rep2.uploaded.is_empty());
        assert_eq!(rep2.failed[0].code, ErrorCode::PatientInTrash);
        // categoria non valida
        c.restore_patient(&pid).unwrap();
        let rep3 = c.upload_documents(&pid, &[s(&root.join("pano.png"))], "Boh", |_, _| {}).unwrap();
        assert_eq!(rep3.failed[0].code, ErrorCode::InvalidInput);
        assert_eq!(c.list_documents(&pid, None).unwrap().len(), 3);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn upload_si_ferma_se_l_archivio_si_blocca_a_meta() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let root = dir.join("lotto");
        fs::create_dir_all(&root).unwrap();
        for i in 0..4 {
            fs::write(root.join(format!("f{i}.jpg")), data(200)).unwrap();
        }
        let rep = c
            .upload_documents(&pid, &[s(&root)], "Altro", |done, _| {
                if done == 2 {
                    c.lock().unwrap(); // blocco manuale durante l'importazione
                }
            })
            .unwrap();
        assert_eq!(rep.uploaded.len(), 2);
        assert_eq!(rep.failed.len(), 2);
        assert!(rep.failed.iter().all(|f| f.code == ErrorCode::Locked));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn shutdown_aspetta_le_operazioni_pesanti() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let start = Instant::now();
        std::thread::scope(|sc| {
            let op = c.begin_op();
            sc.spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                drop(op);
            });
            c.shutdown(Duration::from_secs(5)).unwrap();
        });
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert_eq!(c.status(), Status { initialized: true, unlocked: false });
        assert_eq!(code(c.search_patients("x", 1)), ErrorCode::Locked);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn shutdown_con_operazione_bloccata_chiude_comunque_e_segnala() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let _op = c.begin_op();
        assert_eq!(code(c.shutdown(Duration::from_millis(50))), ErrorCode::Internal);
        assert!(c.lock_session().is_none());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn lock_segnala_lo_snapshot_fallito_ma_blocca() {
        let dir = tmpdir();
        // la "cartella" di snapshot è un file: create_dir_all fallisce
        let bad = dir.join("non-una-cartella");
        fs::write(&bad, b"x").unwrap();
        let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_secs(600))
            .unwrap()
            .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
            .with_snapshot_dir(&bad);
        c.setup_vault(PW).unwrap();
        assert_eq!(code(c.lock()), ErrorCode::IoError);
        assert!(c.lock_session().is_none());
        assert!(!c.lock().unwrap());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn viewer_rispetta_il_limite() {
        let dir = tmpdir();
        let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_secs(600))
            .unwrap()
            .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
            .with_viewer_limit(1000);
        c.setup_vault(PW).unwrap();
        let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let (small, big) = (dir.join("piccolo.jpg"), dir.join("grande.stl"));
        fs::write(&small, data(900)).unwrap();
        fs::write(&big, data(5000)).unwrap();
        c.upload_documents(&pid, &[s(&small), s(&big)], "Scan 3D", |_, _| {}).unwrap();
        for d in c.list_documents(&pid, None).unwrap() {
            if d.size_bytes == 5000 {
                assert_eq!(code(c.open_document(&d.id)), ErrorCode::TooLarge);
            } else {
                assert!(c.open_document(&d.id).is_ok());
            }
        }
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn export_valida_la_destinazione() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let f = dir.join("a.jpg");
        fs::write(&f, data(500)).unwrap();
        c.upload_documents(&pid, &[s(&f)], "Altro", |_, _| {}).unwrap();

        assert_eq!(code(c.export_patient_zip(&pid, &dir.join("a.txt"))), ErrorCode::InvalidInput);
        assert_eq!(code(c.export_patient_zip(&pid, &dir.join("manca/a.zip"))), ErrorCode::InvalidInput);
        assert_eq!(code(c.export_patient_zip(&pid, &dir.join("vault").join("a.zip"))), ErrorCode::InvalidInput); // dentro il vault
        assert_eq!(code(c.export_patient_zip(&pid, &dir.join("vault").join("tmp").join("a.zip"))), ErrorCode::InvalidInput);
        let ok = dir.join("export.ZIP");
        assert!(c.export_patient_zip(&pid, &ok).is_ok());
        assert_eq!(code(c.export_patient_zip(&pid, &ok)), ErrorCode::AlreadyExists);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cestino_ripristino_e_riassegnazione_via_comandi() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let a = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let b = c.create_patient("Luca", "Bianchi", "1975-01-02", None).unwrap();
        let f = dir.join("a.jpg");
        fs::write(&f, data(300)).unwrap();
        c.upload_documents(&a, &[s(&f)], "Altro", |_, _| {}).unwrap();
        let id = c.list_documents(&a, None).unwrap()[0].id.clone();

        c.reassign_document(&id, &b).unwrap();
        assert_eq!(c.list_documents(&a, None).unwrap().len(), 0);
        c.delete_document(&id).unwrap();
        c.delete_patient(&a).unwrap();
        let t = c.list_trash().unwrap();
        assert_eq!((t.patients.len(), t.documents.len()), (1, 1));
        assert_eq!(code(c.restore_document("00000000-0000-0000-0000-000000000000")), ErrorCode::NotFound);
        c.restore_document(&id).unwrap();
        c.restore_patient(&a).unwrap();
        assert!(c.list_trash().unwrap().documents.is_empty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn manutenzione_elimina_il_cestino_scaduto() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        let pid = c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let f = dir.join("a.jpg");
        fs::write(&f, data(300)).unwrap();
        c.upload_documents(&pid, &[s(&f)], "Altro", |_, _| {}).unwrap();
        let id = c.list_documents(&pid, None).unwrap()[0].id.clone();
        assert_eq!(c.maintenance().unwrap(), MaintenanceReport::default()); // nulla di scaduto
        c.delete_document(&id).unwrap();
        assert_eq!(c.maintenance().unwrap(), MaintenanceReport::default()); // cestinato da poco

        let keys = c.storage.unlock(PW).unwrap();
        let db = Db::open(&c.db_path, &keys, "t").unwrap();
        db.conn()
            .execute("UPDATE documents SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','-40 days')", [])
            .unwrap();
        drop(db);
        let r = c.maintenance().unwrap();
        assert_eq!((r.purged_documents, r.failed_files), (1, 0));
        assert!(!dir.join("vault").join(format!("{id}.enc")).exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn snapshot_e_checkpoint_alla_chiusura_della_sessione() {
        let dir = tmpdir();
        let staging = dir.join("staging");
        let c = AppCore::new(&dir.join("vault"), &dir.join("g.db"), Duration::from_secs(600))
            .unwrap()
            .with_kdf_params(KdfParams { m_kib: 8, t: 2, p: 1 })
            .with_snapshot_dir(&staging);
        c.setup_vault(PW).unwrap();
        c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        c.snapshot_db().unwrap(); // periodico
        assert!(staging.join("gestionale.db").exists());
        assert!(dir.join("vault").join("audit.checkpoint").exists());
        c.create_patient("Luca", "Bianchi", "1975-01-02", None).unwrap();
        c.lock().unwrap(); // chiusura: snapshot aggiornato (sostituisce il precedente) e checkpoint
        assert!(!staging.join("gestionale.db.new").exists());
        assert!(dir.join("vault").join("audit.checkpoint").exists());

        let keys = c.storage.unlock(PW).unwrap();
        let snap = Db::open(&staging.join("gestionale.db"), &keys, "t").unwrap();
        assert_eq!(snap.search_patients("bianchi", 5).unwrap().len(), 1); // contiene anche l'ultima modifica
        assert!(!fs::read(staging.join("gestionale.db")).unwrap().starts_with(b"SQLite format 3")); // cifrato
        assert!(c.snapshot_db().is_err()); // bloccato
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn troncamento_del_registro_accessi_segnalato_allo_sblocco() {
        let (dir, c) = core();
        c.setup_vault(PW).unwrap();
        c.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        c.lock().unwrap(); // scrive il checkpoint
        let keys = c.storage.unlock(PW).unwrap();
        {
            let db = Db::open(&c.db_path, &keys, "t").unwrap();
            db.conn()
                .execute_batch(
                    "DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;
                     DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log);",
                )
                .unwrap();
        }
        let info = c.unlock(PW).unwrap();
        assert!(!info.audit_ok);
        assert!(info.audit_message.is_some());
        assert!(c.search_patients("ross", 5).is_ok()); // l'accesso resta possibile: è un avviso
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn errori_serializzati_senza_dettagli_interni() {
        let e = CommandError::from(CryptoError::WrongPasswordOrCorrupted);
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["code"], "WRONG_PASSWORD");
        assert!(j.get("detail").is_none());

        let e = CommandError::from(DbError::DuplicateFiscalCode { existing_id: "abc".into() });
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!((j["code"].as_str(), j["detail"].as_str()), (Some("DUPLICATE_FISCAL_CODE"), Some("abc")));

        // un errore di SQLite non espone il testo originale (tabelle, query)
        let e = CommandError::from(DbError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(1),
            Some("UNIQUE constraint failed: patients.fiscal_code".into()),
        )));
        let text = serde_json::to_string(&e).unwrap();
        assert!(!text.contains("patients") && !text.contains("UNIQUE"));
        for c in [ErrorCode::TooManyAttempts, ErrorCode::DbMissing, ErrorCode::AuditTampered] {
            assert!(serde_json::to_string(&c).unwrap().chars().all(|ch| ch == '"' || ch == '_' || ch.is_ascii_uppercase()));
        }
        let dto = serde_json::to_value(&Status { initialized: true, unlocked: false }).unwrap();
        assert_eq!(dto["initialized"], true); // camelCase per il frontend
        let up = serde_json::to_value(&UploadedDto { id: "1".into(), name: "a".into() }).unwrap();
        assert!(up.get("id").is_some());
    }

    #[test]
    fn mime_e_file_ignorati() {
        assert_eq!(mime_for("RX.JPG"), "image/jpeg");
        assert_eq!(mime_for("scan.stl"), "model/stl");
        assert_eq!(mime_for("senza_estensione"), "application/octet-stream");
        assert!(is_ignored_child(".DS_Store") && is_ignored_child("THUMBS.DB") && is_ignored_child("desktop.ini"));
        assert!(!is_ignored_child("rx.jpg"));
    }
}