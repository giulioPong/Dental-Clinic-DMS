//! Struttura della cartella dati, lock di istanza e comando `--backup-db` per lo scheduler.
//!
//! # Perché il backup non presidiato non usa la chiave
//! La chiave nasce dalla password e uno scheduler alle 20:00 non può averla; salvarla da
//! qualche parte per lui indebolirebbe tutto il resto. Ma non serve: `gestionale.db` è già
//! cifrato da SQLCipher, quindi basta copiarlo quando nessuno ci scrive. Serve solo
//! sapere se l'app è aperta, e lo dice il lock di istanza:
//! - app CHIUSA (lock libero): si tiene il lock (l'app non può partire nel frattempo) e si
//!   copiano il DB cifrato e `vault/audit.checkpoint`. Alla chiusura l'app ha già fatto
//!   checkpoint del WAL e scritto il checkpoint dell'audit, quindi la coppia è coerente;
//! - app APERTA (lock occupato): si copia l'ultimo snapshot che l'app scrive da sola in
//!   `backup-staging/` (alla chiusura della sessione e ogni 30 minuti). Si legge prima il
//!   checkpoint e poi il DB: il DB può solo essere più recente, mai più vecchio.
//!
//! In `<staging>` finiscono sempre `gestionale.db` e `audit.checkpoint`, scritti via file
//! temporaneo + rename, prima il DB e poi il checkpoint. restic salva poi `<staging>` e
//! `vault/` (escluso `vault/tmp/`). Per il ripristino vedi `commands/mod.rs`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Deve coincidere con `identifier` in `tauri.conf.json` (verificato da un test): Tauri usa
/// questo nome per la cartella dati dell'app.
pub const APP_IDENTIFIER: &str = "com.p0ng.dental-clinic-dms";

pub const VAULT_DIR: &str = "vault";
pub const DB_FILE: &str = "gestionale.db";
pub const STAGING_DIR: &str = "backup-staging";
pub const LOCK_FILE: &str = "app.lock";
/// Presente mentre `--backup-db` tiene il lock: dice all'app che vale la pena aspettare.
pub const BACKUP_MARKER: &str = "backup.running";
pub const CHECKPOINT_FILE: &str = "audit.checkpoint";
const LOG_FILE: &str = "backup-db.log";

/// Codici di uscita di `--backup-db`, per lo scheduler.
pub mod exit {
    pub const OK: i32 = 0;
    /// Argomenti non validi.
    pub const USAGE: i32 = 2;
    /// Backup non eseguito: il motivo è in `<staging>/backup-db.log`.
    pub const FAILED: i32 = 1;
}

// ───────── Lock di istanza ─────────

/// Lock esclusivo su `<dati>/app.lock`, tenuto per tutta la vita del processo. Garantisce
/// una sola istanza dell'app e dice al backup se il DB può essere scritto. Il sistema
/// operativo lo rilascia anche se il processo termina in modo anomalo.
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// `Ok(None)` se un altro processo lo tiene.
    pub fn try_acquire(data_dir: &Path) -> std::io::Result<Option<InstanceLock>> {
        fs::create_dir_all(data_dir)?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(data_dir.join(LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(InstanceLock { _file: file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// Per l'avvio dell'app. Se il lock è del backup (c'è `backup.running`) aspetta fino a
    /// `wait`, che di solito dura pochi istanti; se è di un'altra istanza dell'app non ha senso
    /// aspettare e restituisce subito `None`.
    pub fn acquire_for_app(data_dir: &Path, wait: Duration) -> std::io::Result<Option<InstanceLock>> {
        if let Some(l) = Self::try_acquire(data_dir)? {
            return Ok(Some(l));
        }
        if !data_dir.join(BACKUP_MARKER).exists() {
            return Ok(None);
        }
        Self::acquire_waiting(data_dir, wait)
    }

    /// Riprova fino a `wait` (il backup tiene il lock per pochi istanti).
    pub fn acquire_waiting(data_dir: &Path, wait: Duration) -> std::io::Result<Option<InstanceLock>> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(l) = Self::try_acquire(data_dir)? {
                return Ok(Some(l));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

// ───────── Cartella dati ─────────

/// Cartella dati come la calcola Tauri (`app_data_dir`), senza avviare Tauri.
pub fn default_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library").join("Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")));
    base.map(|b| b.join(APP_IDENTIFIER))
}

// ───────── Backup ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupSource {
    /// App chiusa: copiati DB e checkpoint attuali.
    LiveDatabase,
    /// App aperta: copiato l'ultimo snapshot scritto dall'app.
    AppSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    pub source: BackupSource,
    pub bytes: u64,
    /// Età dello snapshot copiato (solo con app aperta).
    pub snapshot_age: Option<Duration>,
}

/// `backup.running`, rimosso alla drop (anche in caso di errore).
struct BackupMarker(PathBuf);

impl BackupMarker {
    fn create(data_dir: &Path) -> Self {
        let p = data_dir.join(BACKUP_MARKER);
        let _ = File::create(&p); // senza segnale l'app non aspetta: nessun danno, solo meno comoda
        BackupMarker(p)
    }
}

impl Drop for BackupMarker {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn copy_atomic(src: &Path, dest: &Path) -> Result<u64, String> {
    let tmp = dest.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let n = fs::copy(src, &tmp).map_err(|e| format!("copia di {} non riuscita: {e}", src.display()))?;
    // su Windows FlushFileBuffers richiede un handle aperto in scrittura
    OpenOptions::new()
        .write(true)
        .open(&tmp)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("sincronizzazione non riuscita: {e}"))?;
    fs::rename(&tmp, dest).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("impossibile sostituire {}: {e}", dest.display())
    })?;
    Ok(n)
}

fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = dest.with_extension("tmp");
    let r = (|| -> std::io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, dest)
    })();
    r.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("impossibile scrivere {}: {e}", dest.display())
    })
}

/// Un WAL non vuoto con l'app chiusa vuol dire una chiusura non pulita: il file del DB da
/// solo non contiene le ultime modifiche. Non si copia una coppia DB+WAL (un WAL rimasto
/// nello staging rovinerebbe il ripristino di uno snapshot successivo).
fn check_no_pending_wal(db: &Path) -> Result<(), String> {
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    match fs::metadata(PathBuf::from(wal)) {
        Ok(m) if m.len() > 0 => Err(
            "il database non è stato chiuso correttamente (WAL presente): apri e chiudi l'app, poi ripeti il backup".into(),
        ),
        _ => Ok(()),
    }
}

/// Mette in `staging` una coppia coerente `gestionale.db` + `audit.checkpoint`.
pub fn backup_db(data_dir: &Path, staging: &Path) -> Result<BackupOutcome, String> {
    let db = data_dir.join(DB_FILE);
    if !db.exists() {
        return Err(format!("database non trovato in {}", db.display()));
    }
    fs::create_dir_all(staging).map_err(|e| format!("cartella di staging non accessibile: {e}"))?;
    if let (Ok(s), Ok(d)) = (fs::canonicalize(staging), fs::canonicalize(data_dir)) {
        if s == d || s.starts_with(d.join(VAULT_DIR)) {
            return Err("la cartella di staging non può essere la cartella dati né stare dentro vault/".into());
        }
    }

    let lock = InstanceLock::try_acquire(data_dir).map_err(|e| format!("lock di istanza non accessibile: {e}"))?;
    let mut marker: Option<BackupMarker> = None;
    let (source, db_src, cp_bytes, snapshot_age) = match &lock {
        // app chiusa, e non può partire finché teniamo il lock
        Some(_) => {
            marker = Some(BackupMarker::create(data_dir));
            check_no_pending_wal(&db)?;
            let cp = fs::read(data_dir.join(VAULT_DIR).join(CHECKPOINT_FILE))
                .map_err(|e| format!("checkpoint dell'audit non leggibile: {e}"))?;
            (BackupSource::LiveDatabase, db, cp, None)
        }
        // app aperta: si usa il suo snapshot (prima il checkpoint, poi il DB)
        None => {
            let app_staging = data_dir.join(STAGING_DIR);
            let snap = app_staging.join(DB_FILE);
            let cp = fs::read(app_staging.join(CHECKPOINT_FILE)).map_err(|_| {
                "app aperta e nessuno snapshot ancora disponibile: verrà scritto al prossimo blocco o entro 30 minuti".to_string()
            })?;
            let age = fs::metadata(&snap)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok());
            (BackupSource::AppSnapshot, snap, cp, age)
        }
    };

    let same_place = fs::canonicalize(staging).ok() == fs::canonicalize(db_src.parent().unwrap_or(Path::new(""))).ok();
    let bytes = if same_place {
        // lo staging richiesto è quello dell'app: lo snapshot è già lì
        fs::metadata(&db_src).map(|m| m.len()).unwrap_or(0)
    } else {
        let n = copy_atomic(&db_src, &staging.join(DB_FILE))?;
        write_atomic(&staging.join(CHECKPOINT_FILE), &cp_bytes)?;
        n
    };
    drop(marker); // prima il segnale, poi il lock
    drop(lock);
    Ok(BackupOutcome { source, bytes, snapshot_age })
}

fn log_line(staging: &Path, line: &str) {
    let ts = humantime_utc(SystemTime::now());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(staging.join(LOG_FILE)) {
        let _ = writeln!(f, "{ts} {line}");
    }
    // in release l'eseguibile non ha console: il log è l'unica traccia per lo scheduler
    eprintln!("{line}");
}

/// `YYYY-MM-DDTHH:MM:SSZ` senza dipendenze esterne.
fn humantime_utc(t: SystemTime) -> String {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // algoritmo di Howard Hinnant (civil_from_days)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Riconosce `--backup-db <staging> [--data-dir <cartella>]`. `None`: nessun comando, si
/// avvia l'app. `Some(codice)`: comando eseguito, il processo deve terminare con quel codice.
pub fn cli_main(args: &[String]) -> Option<i32> {
    let pos = args.iter().position(|a| a == "--backup-db")?;
    let usage = "uso: dental-clinic-dms --backup-db <cartella_staging> [--data-dir <cartella_dati>]";
    let Some(staging) = args.get(pos + 1).filter(|s| !s.starts_with("--")) else {
        eprintln!("{usage}");
        return Some(exit::USAGE);
    };
    let staging = PathBuf::from(staging);
    let data_dir = match args.iter().position(|a| a == "--data-dir") {
        Some(i) => match args.get(i + 1) {
            Some(d) => PathBuf::from(d),
            None => {
                eprintln!("{usage}");
                return Some(exit::USAGE);
            }
        },
        None => match default_data_dir() {
            Some(d) => d,
            None => {
                eprintln!("cartella dati non determinabile: usa --data-dir");
                return Some(exit::USAGE);
            }
        },
    };
    if fs::create_dir_all(&staging).is_err() {
        eprintln!("cartella di staging non accessibile: {}", staging.display());
        return Some(exit::FAILED);
    }
    match backup_db(&data_dir, &staging) {
        Ok(o) => {
            let how = match o.source {
                BackupSource::LiveDatabase => "app chiusa, database attuale".to_string(),
                BackupSource::AppSnapshot => match o.snapshot_age {
                    Some(a) => format!("app aperta, snapshot di {} minuti fa", a.as_secs() / 60),
                    None => "app aperta, snapshot dell'app".to_string(),
                },
            };
            log_line(&staging, &format!("OK {} byte ({how})", o.bytes));
            Some(exit::OK)
        }
        Err(e) => {
            log_line(&staging, &format!("ERRORE {e}"));
            Some(exit::FAILED)
        }
    }
}

#[cfg(test)]
mod tests;
