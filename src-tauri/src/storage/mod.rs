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

// ───────── Errori ─────────

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

// ───────── Utilità di basso livello ─────────

/// `fsync` della cartella: solo su Unix. Su Windows con la sola std non è possibile
/// (e `rename` è comunque atomico sullo stesso volume).
/// Come `fs::remove_file`, ma un file già assente non è un errore.
fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// `<uuid>.enc` con uuid minuscolo a 36 caratteri.
fn is_enc_name(name: &str) -> bool {
    match name.strip_suffix(".enc") {
        Some(stem) => stem.len() == 36 && stem == stem.to_lowercase() && uuid::Uuid::parse_str(stem).is_ok(),
        None => false,
    }
}

/// Rimuove un file; "non trovato" conta come riuscito, ogni altro errore viene restituito.
fn remove_checked(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Da usare quando un'operazione è fallita e bisogna ripulire un file in chiaro: se anche
/// la pulizia fallisce, l'errore lo dice (percorso incluso) invece di tacerlo.
fn fail_with_cleanup(path: &Path, original: StorageError) -> StorageError {
    match remove_checked(path) {
        Ok(()) => original,
        Err(e) => StorageError::CleanupFailed { path: path.to_path_buf(), cause: original.to_string(), io: e.to_string() },
    }
}

/// Sposta `src` in `dest` SENZA mai sovrascrivere: prima riserva il nome con una creazione
/// esclusiva (atomica, funziona anche su exFAT/FAT dove non esistono hard link), poi
/// rinomina sopra il segnaposto. Se `dest` esiste già, errore `AlreadyExists` e `src` resta.
fn rename_no_clobber(src: &Path, dest: &Path) -> io::Result<()> {
    OpenOptions::new().write(true).create_new(true).open(dest)?;
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(dest); // il segnaposto è nostro
            Err(e)
        }
    }
}

fn has_enc_files(dir: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.file_name().to_string_lossy().ends_with(".enc") {
            return Ok(true);
        }
    }
    Ok(false)
}

struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: Sha256,
    count: u64,
}
impl<'a, W: Write> HashingWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self { Self { inner, hasher: Sha256::new(), count: 0 } }
    fn finish(self) -> (u64, String) { (self.count, hex(&self.hasher.finalize())) }
}
impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}

// ───────── Nomi file per l'export ─────────

const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Rende `raw` un nome file sicuro su Windows, macOS e Linux: toglie ogni percorso
/// (`../`, `C:\...`), sostituisce i caratteri non validi, rimuove punti e spazi finali,
/// prefissa i nomi riservati di Windows (anche con estensione: `CON.pdf`) e limita la
/// lunghezza mantenendo l'estensione.
pub fn sanitize_filename(raw: &str, max_bytes: usize) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let mut s: String = base
        .chars()
        .map(|c| if c.is_control() || "<>:\"/\\|?*".contains(c) { '_' } else { c })
        .collect();
    s = s.trim().trim_end_matches(['.', ' ']).to_string();
    if s.is_empty() {
        s = "file".to_string();
    }
    let stem = s.split('.').next().unwrap_or("").trim_end();
    if WINDOWS_RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        s = format!("_{s}");
    }
    if s.len() > max_bytes {
        let (stem, ext) = match s.rfind('.') {
            Some(i) if i > 0 && s.len() - i <= 16 => (s[..i].to_string(), s[i..].to_string()),
            _ => (s.clone(), String::new()),
        };
        let mut keep = max_bytes.saturating_sub(ext.len()).max(1);
        while !stem.is_char_boundary(keep) {
            keep -= 1;
        }
        s = format!("{}{}", stem[..keep].trim_end_matches(['.', ' ']), ext);
    }
    s
}

/// `YYYY-MM-DD_Tag_NomeFile`, con la data di caricamento del documento.
fn export_entry_name(d: &DocumentRecord) -> String {
    let date = d.created_at.get(..10).unwrap_or("0000-00-00");
    let tag = sanitize_filename(&d.category_tag.replace(' ', "-"), 30);
    let name = sanitize_filename(&d.original_filename, 120);
    format!("{date}_{tag}_{name}")
}

fn unique_name(used: &mut HashSet<String>, name: String) -> String {
    if used.insert(name.to_lowercase()) {
        return name;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()),
        _ => (name.clone(), String::new()),
    };
    let mut n = 2;
    loop {
        let candidate = format!("{stem}-{n}{ext}");
        if used.insert(candidate.to_lowercase()) {
            return candidate;
        }
        n += 1;
    }
}

/// I formati già compressi si memorizzano così come sono (niente CPU sprecata).
fn compression_for(name: &str) -> CompressionMethod {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "webp" | "pdf" | "zip" | "heic" => CompressionMethod::Stored,
        _ => CompressionMethod::Deflated,
    }
}

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

    // ───── upload ─────

    fn store_encrypted<R: Read>(&self, keys: &Keys, doc_id: &str, source: R) -> Result<EncryptedInfo> {
        let dest = self.enc_path(doc_id);
        if dest.exists() {
            return Err(StorageError::Io(io::Error::new(io::ErrorKind::AlreadyExists, "file già esistente")));
        }
        let part = self.tmp_dir().join(format!("{}.part", new_uuid()));
        let result = (|| -> Result<EncryptedInfo> {
            let file = OpenOptions::new().write(true).create_new(true).open(&part)?;
            let mut w = BufWriter::new(file);
            let info = crypto::encrypt_stream(keys.files_key(), doc_id, source, &mut w)?;
            let file = w.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            rename_no_clobber(&part, &dest)?;
            sync_dir(&self.root)?;
            Ok(info)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&part);
        }
        result
    }

    /// Cifra `source` e registra il documento. Restituisce l'id.
    pub fn upload_document<R: Read>(&self, db: &Db, keys: &Keys, req: &UploadRequest, source: R) -> Result<String> {
        if !CATEGORY_TAGS.contains(&req.category_tag) {
            return Err(StorageError::InvalidInput("categoria non valida"));
        }
        let name = req.original_filename.rsplit(['/', '\\']).next().unwrap_or("").trim().to_string();
        if name.is_empty() {
            return Err(StorageError::InvalidInput("nome file non valido"));
        }
        if !db.patient_active(req.patient_id)? {
            return Err(StorageError::Db(DbError::PatientInTrash));
        }
        let _guard = self.read_lock();
        let id = new_uuid();
        let info = match self.store_encrypted(keys, &id, source) {
            Ok(i) => i,
            // store_encrypted ripulisce da sé il proprio .part; un eventuale .enc già
            // rinominato resta come orfano (innocuo) e non si cancella qui.
            Err(e) => return Err(e),
        };
        let res = db.add_document(&NewDocument {
            id: &id,
            patient_id: req.patient_id,
            original_filename: &name,
            mime_type: req.mime_type,
            category_tag: req.category_tag,
            size_bytes: info.size_bytes,
            sha256: info.sha256,
        });
        if let Err(e) = res {
            let _ = fs::remove_file(self.enc_path(&id));
            return Err(e.into());
        }
        Ok(id)
    }

    // ───── lettura ─────

    fn check_file(&self, rec: &DocumentRecord) -> Result<()> {
        match crypto::verify_encrypted_file_len(&self.enc_path(&rec.id), rec.size_bytes) {
            Err(CryptoError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Err(StorageError::FileMissing(rec.id.clone())),
            r => Ok(r?),
        }
    }

    /// Viewer: decifra in RAM (mai su disco), verifica dimensione e SHA-256 contro il
    /// DB e registra OPEN_FILE. Se l'audit non si scrive, non restituisce i dati.
    pub fn open_document(
        &self, db: &Db, keys: &Keys, doc_id: &str, max_bytes: usize,
    ) -> Result<(DocumentRecord, Zeroizing<Vec<u8>>)> {
        let rec = db.get_document(doc_id)?;
        if rec.deleted_at.is_some() {
            return Err(StorageError::Db(DbError::InvalidState("il documento è nel cestino")));
        }
        if rec.size_bytes > max_bytes as u64 {
            return Err(StorageError::Crypto(CryptoError::TooLarge));
        }
        self.check_file(&rec)?;
        let f = File::open(self.enc_path(&rec.id))?;
        let hint = usize::try_from(rec.size_bytes).unwrap_or(usize::MAX);
        let plain = crypto::decrypt_to_vec(keys.files_key(), &rec.id, f, max_bytes, hint)?;
        if plain.len() as u64 != rec.size_bytes || hex(&Sha256::digest(&plain[..])) != rec.sha256 {
            return Err(StorageError::IntegrityMismatch(rec.id.clone()));
        }
        db.log_audit("OPEN_FILE", Some(&rec.id), None)?;
        Ok((rec, plain))
    }

    // ───── export ─────

    /// ZIP con tutti i documenti attivi del paziente, in CHIARO, con nomi
    /// `YYYY-MM-DD_Tag_NomeFile`. Costruito in `<dest>.part` accanto alla destinazione e
    /// rinominato solo a lavoro finito; se un solo file fallisce (anche per un troncamento
    /// scoperto all'ultimo blocco) il `.part` viene cancellato.
    pub fn export_patient_zip(&self, db: &Db, keys: &Keys, patient_id: &str, dest: &Path) -> Result<ExportReport> {
        if dest.exists() {
            return Err(StorageError::DestinationExists);
        }
        if !db.patient_active(patient_id)? {
            return Err(StorageError::Db(DbError::PatientInTrash));
        }
        let docs = db.list_documents(patient_id, None)?;
        if docs.is_empty() {
            return Err(StorageError::InvalidInput("nessun documento da esportare"));
        }
        for d in &docs {
            self.check_file(d)?; // controllo O(1) di tutti i file prima di creare lo ZIP
        }
        let mut part_name = dest.as_os_str().to_owned();
        part_name.push(".part");
        let part = PathBuf::from(part_name);

        let result = (|| -> Result<ExportReport> {
            let file = OpenOptions::new().write(true).create_new(true).open(&part)?;
            let mut zip = ZipWriter::new(BufWriter::new(file));
            let mut used = HashSet::new();
            let mut total = 0u64;
            for d in &docs {
                let name = unique_name(&mut used, export_entry_name(d));
                let opts = FileOptions::default()
                    .compression_method(compression_for(&name))
                    .large_file(d.size_bytes >= 0xFFFF_FFFF);
                zip.start_file(name, opts)?;
                let f = File::open(self.enc_path(&d.id))?;
                let mut hw = HashingWriter::new(&mut zip);
                crypto::decrypt_stream(keys.files_key(), &d.id, BufReader::new(f), &mut hw)?;
                let (count, sha) = hw.finish();
                if count != d.size_bytes || sha != d.sha256 {
                    return Err(StorageError::IntegrityMismatch(d.id.clone()));
                }
                total += count;
            }
            let mut w = zip.finish()?;
            w.flush()?;
            let file = w.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            rename_no_clobber(&part, dest)?;
            if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
                let _ = sync_dir(parent); // solo durabilità: non deve far fallire un export già completo
            }
            Ok(ExportReport { documents: docs.len() as u32, plain_bytes: total })
        })();

        match result {
            Ok(report) => {
                let details = format!("documents={}", report.documents);
                if let Err(e) = db.log_audit("EXPORT_ZIP", Some(patient_id), Some(&details)) {
                    // senza audit non si consegna l'export
                    return Err(fail_with_cleanup(dest, e.into()));
                }
                Ok(report)
            }
            Err(e) => Err(fail_with_cleanup(&part, e)),
        }
    }

    // ───── coerenza, quarantena, purge ─────

    pub fn check_consistency(&self, db: &Db) -> Result<ConsistencyReport> {
        let docs = db.all_documents()?;
        let known: HashSet<&str> = docs.iter().map(|d| d.id.as_str()).collect();
        let on_disk = self.list_enc_ids()?;
        let present: HashSet<&str> = on_disk.iter().map(|s| s.as_str()).collect();
        let mut report = ConsistencyReport::default();
        for id in &on_disk {
            if !known.contains(id.as_str()) {
                report.orphan_files.push(id.clone());
            }
        }
        for d in &docs {
            if !present.contains(d.id.as_str()) {
                report.missing_files.push(d.id.clone());
            } else if matches!(self.check_file(d), Err(StorageError::Crypto(CryptoError::SizeMismatch { .. }))) {
                report.size_mismatch.push(d.id.clone());
            }
        }
        Ok(report)
    }

    /// Sposta in `quarantine/` (non cancella) i `.enc` senza riga nel DB più vecchi di
    /// `min_age`. Non fa nulla mentre c'è un upload in corso.
    pub fn quarantine_orphans(&self, db: &Db, min_age: Duration) -> Result<Vec<String>> {
        // Lock in scrittura per tutta l'operazione: se c'è un upload in corso non si fa nulla.
        let _exclusive = match self.upload_lock.try_write() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return Ok(Vec::new()),
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
        };
        let mut moved = Vec::new();
        for id in self.check_consistency(db)?.orphan_files {
            let src = self.enc_path(&id);
            let age = fs::metadata(&src)?.modified()?.elapsed().unwrap_or(Duration::ZERO);
            if age < min_age {
                continue;
            }
            // creazione esclusiva del nome di destinazione: niente corsa exists()+rename
            let mut n = 1;
            loop {
                let name = if n == 1 { format!("{id}.enc") } else { format!("{id}-{n}.enc") };
                match rename_no_clobber(&src, &self.quarantine_dir().join(name)) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1,
                    Err(e) => return Err(e.into()),
                }
            }
            moved.push(id);
        }
        if !moved.is_empty() {
            sync_dir(&self.root)?; // rimozione dalla sorgente
            sync_dir(&self.quarantine_dir())?; // comparsa nella destinazione
        }
        Ok(moved)
    }

    /// Elimina definitivamente il cestino scaduto: prima il file, poi la riga.
    pub fn purge_expired(&self, db: &Db, retention_days: u32) -> Result<PurgeReport> {
        Ok(db.purge_expired(retention_days, |name| {
            if !is_enc_name(name) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "nome file non valido"));
            }
            fs::remove_file(self.root.join(name))
        })?)
    }
}

// ───────── TEST ─────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const PW: &str = "correct horse battery";
    const PW2: &str = "tutt'altra password 42";

    fn tp() -> KdfParams { KdfParams { m_kib: 8, t: 2, p: 1 } }
    fn data(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }
    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("gestionale-st-{}", new_uuid()));
        fs::create_dir_all(&d).unwrap();
        d
    }
    fn setup() -> (PathBuf, Storage, Db, Keys) {
        let dir = tmpdir();
        let st = Storage::open(&dir.join("vault")).unwrap();
        let keys = st.create_vault_with_params(PW, tp()).unwrap();
        let db = Db::open_in_memory(&keys, "admin").unwrap();
        (dir, st, db, keys)
    }
    fn up(st: &Storage, db: &Db, k: &Keys, pid: &str, name: &str, tag: &str, bytes: &[u8]) -> String {
        st.upload_document(
            db, k,
            &UploadRequest { patient_id: pid, original_filename: name, mime_type: "application/octet-stream", category_tag: tag },
            Cursor::new(bytes.to_vec()),
        )
        .unwrap()
    }
    fn files_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into()).collect();
        v.sort();
        v
    }
    fn enc_files(st: &Storage) -> Vec<String> {
        files_in(st.root()).into_iter().filter(|n| is_enc_name(n)).collect()
    }
    struct FailingReader(usize);
    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "disco USB scollegato"));
            }
            let n = buf.len().min(self.0).min(1000);
            buf[..n].fill(7);
            self.0 -= n;
            Ok(n)
        }
    }

    // ── vault.meta ──

    #[test]
    fn creazione_e_sblocco_del_vault() {
        let (dir, st, _db, keys) = setup();
        assert!(st.meta_path().exists());
        assert!(!st.meta_tmp().exists());
        let k2 = st.unlock(PW).unwrap();
        assert_eq!(k2.files_key(), keys.files_key());
        assert!(matches!(st.unlock("password sbagliata"), Err(StorageError::Crypto(CryptoError::WrongPasswordOrCorrupted))));
        assert!(matches!(st.create_vault_with_params(PW, tp()), Err(StorageError::VaultAlreadyExists)));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn non_si_crea_un_vault_sopra_file_cifrati_esistenti() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &data(100));
        fs::remove_file(st.meta_path()).unwrap(); // vault.meta perso
        assert!(matches!(st.unlock(PW), Err(StorageError::VaultMissing)));
        assert!(matches!(st.create_vault_with_params(PW, tp()), Err(StorageError::VaultNotEmpty)));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cambio_password_atomico_senza_residui_e_file_ancora_leggibili() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let id = up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &data(5000));

        st.change_password(PW, PW2).unwrap();
        assert!(!st.meta_bak().exists() && !st.meta_tmp().exists());
        assert!(matches!(st.unlock(PW), Err(StorageError::Crypto(CryptoError::WrongPasswordOrCorrupted))));
        let k2 = st.unlock(PW2).unwrap();
        let (_, plain) = st.open_document(&db, &k2, &id, 1 << 20).unwrap();
        assert_eq!(&plain[..], &data(5000)[..]);

        assert!(matches!(st.change_password("sbagliata sbagliata", PW2), Err(StorageError::Crypto(_))));
        assert!(matches!(st.change_password(PW2, "corta"), Err(StorageError::Crypto(CryptoError::PasswordTooShort))));
        assert!(st.unlock(PW2).is_ok()); // i tentativi falliti non hanno toccato il file
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn bak_residuo_viene_eliminato_e_meta_corrotto_si_ripristina_dal_bak() {
        let (dir, st, _db, _k) = setup();
        // crash dopo il rename ma prima di cancellare il .bak: la vecchia password non deve restare valida
        fs::copy(st.meta_path(), st.meta_bak()).unwrap();
        st.unlock(PW).unwrap();
        assert!(!st.meta_bak().exists());

        // vault.meta illeggibile + copia di riserva valida → ripristino
        let good = fs::read(st.meta_path()).unwrap();
        fs::write(st.meta_bak(), &good).unwrap();
        fs::write(st.meta_path(), vec![0u8; good.len()]).unwrap();
        st.unlock(PW).unwrap();
        assert_eq!(fs::read(st.meta_path()).unwrap(), good);
        assert!(!st.meta_bak().exists());

        // password errata non ripristina nulla né cancella il bak
        fs::write(st.meta_bak(), &good).unwrap();
        fs::write(st.meta_path(), vec![0u8; good.len()]).unwrap();
        assert!(st.unlock("password sbagliata").is_err());
        assert!(st.meta_bak().exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unlock_non_ignora_il_fallimento_rimozione_backup() {
        let (dir, st, _db, _k) = setup();
        fs::create_dir(st.meta_bak()).unwrap();

        assert!(matches!(st.unlock(PW), Err(StorageError::Io(_))));
        assert!(st.meta_bak().is_dir());

        fs::remove_dir_all(dir).ok();
    }

    // ── upload / viewer ──

    #[test]
    fn upload_e_apertura_con_file_multi_blocco() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let big = data(2 * 1024 * 1024 + 123_456);
        let id = up(&st, &db, &keys, &pid, "C:\\Users\\papa\\scan 3d.stl", "Scan 3D", &big);

        assert_eq!(enc_files(&st), vec![format!("{id}.enc")]);
        assert!(files_in(&st.tmp_dir()).is_empty());
        let rec = db.get_document(&id).unwrap();
        assert_eq!(rec.original_filename, "scan 3d.stl"); // solo il nome, niente percorso
        assert_eq!(rec.size_bytes, big.len() as u64);
        assert_eq!(rec.sha256, hex(&Sha256::digest(&big)));

        let (_, plain) = st.open_document(&db, &keys, &id, 10 << 20).unwrap();
        assert_eq!(&plain[..], &big[..]);
        assert_eq!(db.verify_audit_chain(None).unwrap(), 3); // CREATE_PATIENT, UPLOAD_FILE, OPEN_FILE
        assert!(matches!(st.open_document(&db, &keys, &id, 1000), Err(StorageError::Crypto(CryptoError::TooLarge))));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn upload_fallito_non_lascia_ne_file_ne_righe() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let req = |tag| UploadRequest { patient_id: &pid, original_filename: "rx.jpg", mime_type: "image/jpeg", category_tag: tag };

        // sorgente che si interrompe a metà (chiavetta staccata)
        assert!(st.upload_document(&db, &keys, &req("Altro"), FailingReader(5_000_000)).is_err());
        assert!(files_in(&st.tmp_dir()).is_empty());
        assert!(enc_files(&st).is_empty());
        assert!(st.upload_lock.try_write().is_ok()); // nessun lock rimasto preso

        // input rifiutati prima di cifrare
        assert!(matches!(st.upload_document(&db, &keys, &req("Boh"), Cursor::new(vec![1])), Err(StorageError::InvalidInput(_))));
        let bad_name = UploadRequest { original_filename: "  ", ..req("Altro") };
        assert!(matches!(st.upload_document(&db, &keys, &bad_name, Cursor::new(vec![1])), Err(StorageError::InvalidInput(_))));
        let ghost = UploadRequest { patient_id: &new_uuid(), ..req("Altro") };
        assert!(matches!(st.upload_document(&db, &keys, &ghost, Cursor::new(vec![1])), Err(StorageError::Db(DbError::NotFound))));
        db.soft_delete_patient(&pid).unwrap();
        assert!(matches!(st.upload_document(&db, &keys, &req("Altro"), Cursor::new(vec![1])), Err(StorageError::Db(DbError::PatientInTrash))));
        assert!(enc_files(&st).is_empty() && files_in(&st.tmp_dir()).is_empty());
        assert_eq!(db.all_documents().unwrap().len(), 0);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn open_all_avvio_svuota_tmp() {
        let (dir, st, _db, _k) = setup();
        fs::write(st.tmp_dir().join("residuo.part"), b"parziale").unwrap();
        fs::write(st.tmp_dir().join("altro.part"), b"parziale").unwrap();
        let st2 = Storage::open(st.root()).unwrap();
        assert!(files_in(&st2.tmp_dir()).is_empty());
        assert!(st2.meta_path().exists()); // il resto non si tocca
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn apertura_rileva_file_alterati_troncati_scambiati_o_mancanti() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let a = up(&st, &db, &keys, &pid, "a.jpg", "Panoramica", &data(5000));
        let b = up(&st, &db, &keys, &pid, "b.jpg", "Endorale", &data(5000));
        let open = |id: &str| st.open_document(&db, &keys, id, 1 << 20).map(|(_, p)| p.len());
        assert_eq!(open(&a).unwrap(), 5000);

        let good = fs::read(st.enc_path(&a)).unwrap();
        // troncato di 1 byte → scoperto dal controllo O(1), senza decifrare
        fs::write(st.enc_path(&a), &good[..good.len() - 1]).unwrap();
        assert!(matches!(open(&a), Err(StorageError::Crypto(CryptoError::SizeMismatch { .. }))));
        // un byte alterato a lunghezza invariata → scoperto dal tag GCM
        let mut flipped = good.clone();
        flipped[40] ^= 1;
        fs::write(st.enc_path(&a), &flipped).unwrap();
        assert!(matches!(open(&a), Err(StorageError::Crypto(CryptoError::FileCorrupted))));
        // il file di un altro documento (stessa lunghezza) copiato sopra → l'AAD non coincide
        fs::copy(st.enc_path(&b), st.enc_path(&a)).unwrap();
        assert!(matches!(open(&a), Err(StorageError::Crypto(CryptoError::FileCorrupted))));
        // file mancante
        fs::remove_file(st.enc_path(&a)).unwrap();
        assert!(matches!(open(&a), Err(StorageError::FileMissing(_))));
        // il DB non coincide col contenuto (hash diverso)
        db.conn().execute("UPDATE documents SET sha256 = ?1 WHERE id = ?2", rusqlite::params!["f".repeat(64), b]).unwrap();
        assert!(matches!(open(&b), Err(StorageError::IntegrityMismatch(_))));
        // cestinato
        db.soft_delete_document(&b).unwrap();
        assert!(matches!(open(&b), Err(StorageError::Db(DbError::InvalidState(_)))));
        fs::remove_dir_all(dir).ok();
    }

    // ── export ZIP ──

    fn read_zip(path: &Path) -> Vec<(String, Vec<u8>, CompressionMethod)> {
        let mut z = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        (0..z.len())
            .map(|i| {
                let mut f = z.by_index(i).unwrap();
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).unwrap();
                (f.name().to_string(), buf, f.compression())
            })
            .collect()
    }

    #[test]
    fn export_zip_nomi_contenuti_compressione_e_audit() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let (j1, j2, t, gone) = (data(3000), data(4000), b"referto di testo ".repeat(200), data(10));
        let id1 = up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &j1);
        up(&st, &db, &keys, &pid, "RX.JPG", "Panoramica", &j2); // stesso nome (maiuscole diverse)
        up(&st, &db, &keys, &pid, "../../etc/passwd", "Consenso", &t);
        let trashed = up(&st, &db, &keys, &pid, "scartato.png", "Altro", &gone);
        db.soft_delete_document(&trashed).unwrap();
        let date = db.get_document(&id1).unwrap().created_at[..10].to_string();

        let dest = dir.join("export.zip");
        let rep = st.export_patient_zip(&db, &keys, &pid, &dest).unwrap();
        assert_eq!(rep, ExportReport { documents: 3, plain_bytes: (j1.len() + j2.len() + t.len()) as u64 });
        assert!(!dir.join("export.zip.part").exists());

        let mut entries = read_zip(&dest);
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let names: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
        // i due file con lo stesso nome (maiuscole a parte) hanno lo stesso created_at:
        // quale dei due riceve il suffisso "-2" dipende dall'ordine, quindi si confronta in minuscolo
        let mut got: Vec<String> = names.iter().map(|s| s.to_lowercase()).collect();
        got.sort();
        let mut expected = vec![
            format!("{date}_consenso_passwd").replace("consenso", "Consenso").to_lowercase(),
            format!("{date}_panoramica_rx.jpg"),
            format!("{date}_panoramica_rx-2.jpg"),
        ];
        expected.sort();
        assert_eq!(got, expected);
        for (name, content, method) in &entries {
            if name.ends_with("passwd") {
                assert_eq!(content, &t);
                assert_eq!(*method, CompressionMethod::Deflated);
            } else {
                assert_eq!(*method, CompressionMethod::Stored); // jpg già compresso
                assert!(content == &j1 || content == &j2);
            }
        }
        assert!(db.verify_audit_chain(None).unwrap() > 0);
        let n: i64 = db.conn().query_row("SELECT count(*) FROM audit_log WHERE action='EXPORT_ZIP'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);

        // non sovrascrive
        assert!(matches!(st.export_patient_zip(&db, &keys, &pid, &dest), Err(StorageError::DestinationExists)));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn export_fallito_non_lascia_zip_parziali() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let a = up(&st, &db, &keys, &pid, "a.jpg", "Panoramica", &data(5000));
        up(&st, &db, &keys, &pid, "b.jpg", "Endorale", &data(5000));
        let dest = dir.join("out.zip");

        // alterazione a lunghezza invariata: si scopre solo durante la decifratura
        let mut bytes = fs::read(st.enc_path(&a)).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(st.enc_path(&a), &bytes).unwrap();
        assert!(st.export_patient_zip(&db, &keys, &pid, &dest).is_err());
        assert!(!dest.exists() && !dir.join("out.zip.part").exists());

        // file troncato: scoperto prima ancora di creare lo ZIP
        fs::write(st.enc_path(&a), &bytes[..bytes.len() - 3]).unwrap();
        assert!(matches!(st.export_patient_zip(&db, &keys, &pid, &dest), Err(StorageError::Crypto(CryptoError::SizeMismatch { .. }))));
        assert!(!dest.exists() && !dir.join("out.zip.part").exists());

        // nessun documento / paziente nel cestino
        let empty = db.create_patient("Luca", "Bianchi", "1975-01-02", None).unwrap();
        assert!(matches!(st.export_patient_zip(&db, &keys, &empty, &dest), Err(StorageError::InvalidInput(_))));
        db.soft_delete_patient(&pid).unwrap();
        assert!(matches!(st.export_patient_zip(&db, &keys, &pid, &dest), Err(StorageError::Db(DbError::PatientInTrash))));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sanitizzazione_nomi_file() {
        let s = |x: &str| sanitize_filename(x, 120);
        assert_eq!(s("../../etc/passwd"), "passwd");
        assert_eq!(s("C:\\Users\\papa\\rx.jpg"), "rx.jpg");
        assert_eq!(s("a<b>c:d\"e|f?g*h.jpg"), "a_b_c_d_e_f_g_h.jpg");
        assert_eq!(s("referto.pdf. . "), "referto.pdf");
        assert_eq!(s("  rx.jpg  "), "rx.jpg");
        assert_eq!(s(""), "file");
        assert_eq!(s(".."), "file");
        assert_eq!(s("..."), "file");
        assert_eq!(s("tab\there\n.txt"), "tab_here_.txt");
        // nomi riservati di Windows, anche con estensione e in qualsiasi maiuscola
        for n in ["CON", "con.pdf", "NUL.jpg", "Com1.txt", "LPT9.png", "aux", "PRN.tar.gz", "CON .txt"] {
            assert!(s(n).starts_with('_'), "{n} → {}", s(n));
        }
        assert_eq!(s("CONSENSO.pdf"), "CONSENSO.pdf");
        assert_eq!(s("COM10.txt"), "COM10.txt");
        // lunghezza: si accorcia il nome, non l'estensione
        let long = format!("{}.jpg", "è".repeat(200));
        let out = sanitize_filename(&long, 50);
        assert!(out.len() <= 50 && out.ends_with(".jpg") && out.is_char_boundary(out.len()));
        assert!(sanitize_filename(&"x".repeat(500), 40).len() <= 40);
    }

    #[test]
    fn nomi_duplicati_nello_zip() {
        let mut used = HashSet::new();
        assert_eq!(unique_name(&mut used, "a.jpg".into()), "a.jpg");
        assert_eq!(unique_name(&mut used, "A.JPG".into()), "A-2.JPG");
        assert_eq!(unique_name(&mut used, "a.jpg".into()), "a-3.jpg");
        assert_eq!(unique_name(&mut used, "senza_estensione".into()), "senza_estensione");
        assert_eq!(unique_name(&mut used, "senza_estensione".into()), "senza_estensione-2");
    }

    // ── coerenza, quarantena, purge ──

    #[test]
    fn coerenza_orfani_mancanti_e_quarantena() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let ok = up(&st, &db, &keys, &pid, "ok.jpg", "Altro", &data(2000));
        let missing = up(&st, &db, &keys, &pid, "manca.jpg", "Altro", &data(2000));
        let short = up(&st, &db, &keys, &pid, "corto.jpg", "Altro", &data(2000));
        fs::remove_file(st.enc_path(&missing)).unwrap();
        let b = fs::read(st.enc_path(&short)).unwrap();
        fs::write(st.enc_path(&short), &b[..b.len() - 4]).unwrap();
        let orphan = new_uuid();
        fs::copy(st.enc_path(&ok), st.enc_path(&orphan)).unwrap(); // simula un upload il cui DB è stato perso
        fs::write(st.root().join("note.txt"), b"altro").unwrap(); // file estranei ignorati

        let rep = st.check_consistency(&db).unwrap();
        assert_eq!(rep, ConsistencyReport {
            orphan_files: vec![orphan.clone()], missing_files: vec![missing.clone()], size_mismatch: vec![short.clone()],
        });

        {
            let _busy = st.read_lock(); // upload in corso: non si tocca nulla
            assert!(st.quarantine_orphans(&db, Duration::ZERO).unwrap().is_empty());
            assert!(st.enc_path(&orphan).exists());
        }
        assert!(st.quarantine_orphans(&db, Duration::from_secs(3600)).unwrap().is_empty()); // troppo recente
        assert!(st.enc_path(&orphan).exists());

        assert_eq!(st.quarantine_orphans(&db, Duration::ZERO).unwrap(), vec![orphan.clone()]);
        assert!(!st.enc_path(&orphan).exists());
        assert!(st.quarantine_dir().join(format!("{orphan}.enc")).exists()); // spostato, non cancellato
        assert!(st.check_consistency(&db).unwrap().orphan_files.is_empty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn purge_elimina_prima_il_file_poi_la_riga() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let old = up(&st, &db, &keys, &pid, "vecchio.jpg", "Altro", &data(500));
        let recent = up(&st, &db, &keys, &pid, "recente.jpg", "Altro", &data(500));
        let live = up(&st, &db, &keys, &pid, "attivo.jpg", "Altro", &data(500));
        db.soft_delete_document(&old).unwrap();
        db.soft_delete_document(&recent).unwrap();
        db.conn()
            .execute(
                "UPDATE documents SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','-40 days') WHERE id = ?1",
                rusqlite::params![old],
            )
            .unwrap();
        let rep = st.purge_expired(&db, 30).unwrap();
        assert_eq!(rep, PurgeReport { documents: 1, patients: 0, failed_files: 0 });
        assert!(!st.enc_path(&old).exists());
        assert!(st.enc_path(&recent).exists() && st.enc_path(&live).exists());
        assert_eq!(st.check_consistency(&db).unwrap(), ConsistencyReport::default());
        assert!(db.verify_audit_chain(None).is_ok());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn quarantena_non_sovrascrive_file_gia_presenti() {
        let (dir, st, db, _k) = setup();
        let orphan = new_uuid();
        fs::write(st.enc_path(&orphan), b"nuovo").unwrap();
        fs::write(st.quarantine_dir().join(format!("{orphan}.enc")), b"vecchio").unwrap();
        assert_eq!(st.quarantine_orphans(&db, Duration::ZERO).unwrap(), vec![orphan.clone()]);
        assert_eq!(fs::read(st.quarantine_dir().join(format!("{orphan}.enc"))).unwrap(), b"vecchio");
        assert_eq!(fs::read(st.quarantine_dir().join(format!("{orphan}-2.enc"))).unwrap(), b"nuovo");
        assert!(!st.enc_path(&orphan).exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn creazione_vault_rifiutata_anche_con_file_in_quarantena() {
        let (dir, st, _db, _k) = setup();
        fs::remove_file(st.meta_path()).unwrap();
        fs::write(st.quarantine_dir().join(format!("{}.enc", new_uuid())), b"x").unwrap();
        assert!(matches!(st.create_vault_with_params(PW, tp()), Err(StorageError::VaultNotEmpty)));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rename_senza_sovrascrittura() {
        let dir = tmpdir();
        let (src, dest) = (dir.join("a.part"), dir.join("a.enc"));
        fs::write(&src, b"nuovo").unwrap();
        fs::write(&dest, b"esistente").unwrap();
        let e = rename_no_clobber(&src, &dest).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&dest).unwrap(), b"esistente"); // intatto
        assert!(src.exists()); // la sorgente resta
        fs::remove_file(&dest).unwrap();
        rename_no_clobber(&src, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"nuovo");
        assert!(!src.exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn errori_di_pulizia_non_vengono_ignorati() {
        let dir = tmpdir();
        assert!(remove_checked(&dir.join("non-esiste")).is_ok());
        let blocked = dir.join("export.zip.part");
        fs::create_dir_all(blocked.join("dentro")).unwrap(); // una cartella non si rimuove con remove_file
        assert!(remove_checked(&blocked).is_err());
        match fail_with_cleanup(&blocked, StorageError::VaultMissing) {
            StorageError::CleanupFailed { path, cause, .. } => {
                assert_eq!(path, blocked);
                assert!(cause.contains("vault.meta"));
            }
            other => panic!("atteso CleanupFailed, trovato {other:?}"),
        }
        assert!(matches!(fail_with_cleanup(&dir.join("x"), StorageError::VaultMissing), StorageError::VaultMissing));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn senza_audit_ne_viewer_ne_export_consegnano_dati() {
        let (dir, st, db, keys) = setup();
        let pid = db.create_patient("Mario", "Rossi", "1980-05-12", None).unwrap();
        let id = up(&st, &db, &keys, &pid, "rx.jpg", "Panoramica", &data(3000));
        db.conn().execute_batch("DROP TABLE audit_log;").unwrap(); // l'audit non può più scrivere

        assert!(matches!(st.open_document(&db, &keys, &id, 1 << 20), Err(StorageError::Db(_))));
        let dest = dir.join("out.zip");
        assert!(st.export_patient_zip(&db, &keys, &pid, &dest).is_err());
        assert!(!dest.exists() && !dir.join("out.zip.part").exists()); // nessuno ZIP in chiaro rimasto
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn nomi_enc_validi() {
        assert!(is_enc_name(&format!("{}.enc", new_uuid())));
        for bad in ["abc.enc", "vault.meta", "../x.enc", &format!("{}.enc", new_uuid().to_uppercase()),
                    &format!("{}.enc.part", new_uuid()), &format!("{{{}}}.enc", new_uuid())] {
            assert!(!is_enc_name(bad), "{bad}");
        }
    }
}
