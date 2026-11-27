//! Modulo crittografico.
//!
//! Cargo.toml:
//! ```toml
//! aes-gcm = { version = "0.10", features = ["stream", "zeroize"] }
//! argon2  = "0.5"
//! hkdf    = "0.12"
//! sha2    = "0.10"
//! zeroize = "1"
//! rand    = "0.8"
//!
//! # Argon2 in debug è lentissimo: ottimizza almeno le dipendenze
//! [profile.dev.package."*"]
//! opt-level = 3
//! ```
//!
//! # Gerarchia delle chiavi
//! ```text
//! password ──Argon2id(salt, m/t/p)──► KEK (32 B)
//! KEK ──AES-256-GCM unwrap──► master key (32 B, casuale, in vault.meta)
//! master ──HKDF-SHA256──► chiave DB (SQLCipher) | chiave file | chiave audit
//! chiave file + salt del file ──HKDF──► chiave del singolo file
//! ```
//! Cambiare password = ri-cifrare 32 byte di master key: DB e file non si toccano.
//!
//! # vault.meta (93 byte, versione 1)
//! ```text
//! "DVLT" | ver u8 | m_kib u32 LE | t u32 LE | p u32 LE | salt[16]   ← header (33 B)
//! nonce[12] | master key cifrata + tag GCM (48 B)
//! ```
//! L'header è AAD del wrap: se qualcuno altera salt o parametri, l'apertura
//! fallisce. I parametri Argon2 letti dal file sono comunque limitati a un
//! intervallo ragionevole (niente downgrade, niente richieste da 50 GB di RAM).
//! `vault.meta` e il DB vanno sempre salvati e ripristinati INSIEME.
//!
//! # File `.enc` (versione 1, cifratura a blocchi STREAM-BE32)
//! ```text
//! "DENC" | ver u8 | chunk_size u32 LE | file_salt[16] | nonce_prefix[7]   ← header (32 B)
//! blocco_0 | blocco_1 | ... | blocco_ultimo     (ognuno: ciphertext + tag GCM da 16 B)
//! ```
//! - Chiave per file: HKDF(chiave file, salt = file_salt). Nessun riuso di nonce possibile.
//! - Nonce del blocco = prefix(7) ‖ contatore u32 BE ‖ flag "ultimo blocco": riordinare,
//!   togliere o aggiungere blocchi (anche troncando a un confine di blocco) fa fallire il tag.
//! - AAD di ogni blocco = header ‖ document_id. Il document_id è lo stem del nome
//!   `<document_id>.enc`, quindi i file restano decifrabili anche senza DB.
//!   L'id del paziente NON è nell'AAD: spostare un documento tra pazienti non richiede
//!   di ricifrare il file.
//! - Il tag GCM sta inline in ogni blocco (formato standard del crate `aes-gcm`).

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

// ───────── Errori ─────────

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

// ───────── Costanti ─────────

const MAGIC_VAULT: &[u8; 4] = b"DVLT";
const MAGIC_FILE: &[u8; 4] = b"DENC";
const FORMAT_VERSION: u8 = 1;

pub const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const STREAM_PREFIX_LEN: usize = 7;

pub const MIN_PASSWORD_CHARS: usize = 10;

const VM_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN; // 33
pub const VAULT_META_LEN: usize = VM_HEADER_LEN + NONCE_LEN + KEY_LEN + TAG_LEN; // 93

const FH_LEN: usize = 4 + 1 + 4 + SALT_LEN + STREAM_PREFIX_LEN; // 32
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 4096;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

// Limiti dei parametri Argon2 accettati da vault.meta. In test il minimo di
// memoria è abbassato per tenere veloci i test; il test `limiti_parametri_*`
// verifica comunque il rifiuto dei valori fuori intervallo.
#[cfg(not(test))]
const MIN_M_KIB: u32 = 19 * 1024;
#[cfg(test)]
const MIN_M_KIB: u32 = 8;
const MAX_M_KIB: u32 = 512 * 1024;
const MIN_T: u32 = 2;
const MAX_T: u32 = 10;
const MIN_P: u32 = 1;
const MAX_P: u32 = 8;

// ───────── Parametri Argon2 ─────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passate, 1 thread: ~0,2–0,5 s su un PC da studio. Da tarare
    /// misurando sul PC reale (più alto = meglio, finché lo sblocco resta < ~1 s).
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };

    fn validate(&self) -> Result<()> {
        let ok = (MIN_M_KIB..=MAX_M_KIB).contains(&self.m_kib)
            && (MIN_T..=MAX_T).contains(&self.t)
            && (MIN_P..=MAX_P).contains(&self.p)
            && self.m_kib >= 8 * self.p;
        if ok { Ok(()) } else { Err(CryptoError::InvalidMeta("parametri Argon2 fuori dai limiti")) }
    }
}

fn derive_kek(password: &str, salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out[..])
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

// ───────── Chiavi derivate dalla master key ─────────

#[derive(Clone)]
pub struct Keys {
    db: Zeroizing<[u8; KEY_LEN]>,
    files: Zeroizing<[u8; KEY_LEN]>,
    audit: Zeroizing<[u8; KEY_LEN]>,
}

impl Keys {
    fn derive(master: &[u8; KEY_LEN]) -> Keys {
        let hk = Hkdf::<Sha256>::new(Some(b"gestionale-vault-v1"), master);
        let expand = |info: &[u8]| {
            let mut k = Zeroizing::new([0u8; KEY_LEN]);
            hk.expand(info, &mut k[..]).expect("32 byte sono una lunghezza valida per HKDF-SHA256");
            k
        };
        Keys {
            db: expand(b"gestionale/v1/db"),
            files: expand(b"gestionale/v1/files"),
            audit: expand(b"gestionale/v1/audit"),
        }
    }

    pub fn files_key(&self) -> &[u8; KEY_LEN] { &self.files }
    pub fn audit_key(&self) -> &[u8; KEY_LEN] { &self.audit }

    /// Valore per `PRAGMA key = "<valore>"` di SQLCipher (chiave grezza, niente KDF interna).
    pub fn sqlcipher_key_pragma_value(&self) -> Zeroizing<String> {
        let mut s = String::with_capacity(2 + KEY_LEN * 2 + 1);
        s.push_str("x'");
        for b in self.db.iter() {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('\'');
        Zeroizing::new(s)
    }
}

// ───────── Vault: creazione, sblocco, cambio password ─────────

pub struct NewVault {
    /// Contenuto da scrivere in `vault.meta` (e duplicare nel backup).
    pub meta_bytes: Vec<u8>,
    pub keys: Keys,
}

fn check_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS { Err(CryptoError::PasswordTooShort) } else { Ok(()) }
}

pub fn create_vault(password: &str) -> Result<NewVault> {
    create_vault_with_params(password, KdfParams::DEFAULT)
}

pub fn create_vault_with_params(password: &str, params: KdfParams) -> Result<NewVault> {
    check_password(password)?;
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut master[..]);
    let meta_bytes = seal_master(&master, password, params)?;
    Ok(NewVault { meta_bytes, keys: Keys::derive(&master) })
}

pub fn unlock_vault(meta_bytes: &[u8], password: &str) -> Result<Keys> {
    let master = open_master(meta_bytes, password)?;
    Ok(Keys::derive(&master))
}

/// Verifica la vecchia password e ri-cifra la master key con la nuova
/// (nuovo salt, stessi parametri Argon2 del file esistente).
pub fn change_password(meta_bytes: &[u8], old_password: &str, new_password: &str) -> Result<Vec<u8>> {
    check_password(new_password)?;
    let params = parse_vault_meta(meta_bytes)?.params;
    let master = open_master(meta_bytes, old_password)?;
    seal_master(&master, new_password, params)
}

fn vault_header(params: &KdfParams, salt: &[u8; SALT_LEN]) -> [u8; VM_HEADER_LEN] {
    let mut h = [0u8; VM_HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC_VAULT);
    h[4] = FORMAT_VERSION;
    h[5..9].copy_from_slice(&params.m_kib.to_le_bytes());
    h[9..13].copy_from_slice(&params.t.to_le_bytes());
    h[13..17].copy_from_slice(&params.p.to_le_bytes());
    h[17..33].copy_from_slice(salt);
    h
}

struct ParsedMeta<'a> {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    header: &'a [u8],
    wrapped: &'a [u8],
}

fn parse_vault_meta(b: &[u8]) -> Result<ParsedMeta<'_>> {
    if b.len() != VAULT_META_LEN {
        return Err(CryptoError::InvalidMeta("dimensione errata"));
    }
    if &b[0..4] != MAGIC_VAULT {
        return Err(CryptoError::InvalidMeta("magic errato"));
    }
    if b[4] != FORMAT_VERSION {
        return Err(CryptoError::InvalidMeta("versione non supportata"));
    }
    let le = |r: std::ops::Range<usize>| u32::from_le_bytes(b[r].try_into().unwrap());
    let params = KdfParams { m_kib: le(5..9), t: le(9..13), p: le(13..17) };
    params.validate()?;
    Ok(ParsedMeta {
        params,
        salt: b[17..33].try_into().unwrap(),
        nonce: b[33..45].try_into().unwrap(),
        header: &b[0..VM_HEADER_LEN],
        wrapped: &b[45..VAULT_META_LEN],
    })
}

fn seal_master(master: &[u8; KEY_LEN], password: &str, params: KdfParams) -> Result<Vec<u8>> {
    params.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let kek = derive_kek(password, &salt, &params)?;
    let header = vault_header(&params, &salt);
    let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| CryptoError::Internal)?;
    let wrapped = cipher
        .encrypt(GenericArray::from_slice(&nonce), Payload { msg: &master[..], aad: &header })
        .map_err(|_| CryptoError::Internal)?;
    let mut out = Vec::with_capacity(VAULT_META_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&wrapped);
    debug_assert_eq!(out.len(), VAULT_META_LEN);
    Ok(out)
}

fn open_master(meta_bytes: &[u8], password: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let m = parse_vault_meta(meta_bytes)?;
    let kek = derive_kek(password, &m.salt, &m.params)?;
    let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| CryptoError::Internal)?;
    let pt = cipher
        .decrypt(GenericArray::from_slice(&m.nonce), Payload { msg: m.wrapped, aad: m.header })
        .map_err(|_| CryptoError::WrongPasswordOrCorrupted)?;
    let pt = Zeroizing::new(pt);
    if pt.len() != KEY_LEN {
        return Err(CryptoError::InvalidMeta("master key di lunghezza errata"));
    }
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    master.copy_from_slice(&pt);
    Ok(master)
}

// ───────── Sessione in RAM con blocco per inattività ─────────

struct Session {
    keys: Keys,
    last_activity: Instant,
}

/// Tiene le chiavi solo in RAM. Va messo nello stato di Tauri (`app.manage`).
/// Un thread di fondo deve chiamare `expire_if_idle()` ogni pochi secondi, così
/// le chiavi vengono azzerate anche se l'interfaccia non fa più richieste.
/// Quando l'archivio si blocca, chiudi anche la connessione SQLCipher.
pub struct KeyStore {
    inner: Mutex<Option<Session>>,
    idle_timeout: Duration,
}

impl KeyStore {
    pub fn new(idle_timeout: Duration) -> Self {
        Self { inner: Mutex::new(None), idle_timeout }
    }

    fn guard(&self) -> MutexGuard<'_, Option<Session>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn unlock(&self, keys: Keys) {
        *self.guard() = Some(Session { keys, last_activity: Instant::now() });
    }

    /// Azzera subito le chiavi (Zeroize alla drop).
    pub fn lock(&self) {
        *self.guard() = None;
    }

    /// Copia delle chiavi per una singola operazione (la copia si azzera alla drop).
    /// Ogni chiamata conta come attività e rinvia il blocco.
    pub fn keys(&self) -> Result<Keys> {
        let mut g = self.guard();
        let expired = match g.as_ref() {
            Some(s) => s.last_activity.elapsed() >= self.idle_timeout,
            None => return Err(CryptoError::Locked),
        };
        if expired {
            *g = None;
            return Err(CryptoError::Locked);
        }
        let s = g.as_mut().expect("controllato sopra");
        s.last_activity = Instant::now();
        Ok(s.keys.clone())
    }

    /// Non conta come attività.
    pub fn is_unlocked(&self) -> bool {
        let mut g = self.guard();
        let expired = matches!(g.as_ref(), Some(s) if s.last_activity.elapsed() >= self.idle_timeout);
        if expired {
            *g = None;
        }
        g.is_some()
    }

    /// Da chiamare periodicamente. Restituisce true se ha appena bloccato la sessione.
    pub fn expire_if_idle(&self) -> bool {
        let mut g = self.guard();
        let expired = matches!(g.as_ref(), Some(s) if s.last_activity.elapsed() >= self.idle_timeout);
        if expired {
            *g = None;
        }
        expired
    }
}

// ───────── Cifratura file a blocchi ─────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedInfo {
    /// Dimensione del file in chiaro.
    pub size_bytes: u64,
    /// SHA-256 del file in chiaro.
    pub sha256: [u8; 32],
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lunghezza attesa di un `.enc` per un file in chiaro di `plain_len` byte:
/// permette di controllare `std::fs::metadata(..).len()` contro `documents.size_bytes`
/// senza decifrare nulla. `chunk_size` si legge dal header del file (di default 1 MiB).
pub fn encrypted_len(plain_len: u64, chunk_size: usize) -> u64 {
    let cs = chunk_size as u64;
    let chunks = if plain_len == 0 { 1 } else { (plain_len + cs - 1) / cs };
    FH_LEN as u64 + plain_len + chunks * TAG_LEN as u64
}

fn file_aad(header: &[u8; FH_LEN], doc_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FH_LEN + doc_id.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(doc_id.as_bytes());
    aad
}

fn file_cipher(files_key: &[u8; KEY_LEN], file_salt: &[u8; SALT_LEN]) -> Result<Aes256Gcm> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), files_key);
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(b"gestionale/v1/file", &mut k[..]).map_err(|_| CryptoError::Internal)?;
    Aes256Gcm::new_from_slice(&k[..]).map_err(|_| CryptoError::Internal)
}

struct FileHeader {
    chunk_size: usize,
    salt: [u8; SALT_LEN],
    prefix: [u8; STREAM_PREFIX_LEN],
}

/// Unico punto che conosce il layout del header (offset compresi).
fn parse_file_header(header: &[u8; FH_LEN]) -> Result<FileHeader> {
    if &header[0..4] != MAGIC_FILE {
        return Err(CryptoError::InvalidFormat("magic errato"));
    }
    if header[4] != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat("versione non supportata"));
    }
    let chunk_size = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CryptoError::InvalidFormat("dimensione blocco fuori limite"));
    }
    Ok(FileHeader {
        chunk_size,
        salt: header[9..25].try_into().unwrap(),
        prefix: header[25..32].try_into().unwrap(),
    })
}

fn read_header<R: Read>(input: &mut R) -> Result<[u8; FH_LEN]> {
    let mut header = [0u8; FH_LEN];
    input.read_exact(&mut header).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof { CryptoError::InvalidFormat("header troncato") } else { CryptoError::Io(e) }
    })?;
    Ok(header)
}

/// Controllo O(1), senza decifrare: la lunghezza del `.enc` deve corrispondere a
/// `documents.size_bytes`. Intercetta troncamenti e aggiunte, NON le alterazioni a
/// lunghezza invariata (quelle le scopre solo la decifratura).
pub fn verify_encrypted_file_len(path: &Path, expected_plain_len: u64) -> Result<()> {
    let mut f = std::fs::File::open(path)?;
    let actual = f.metadata()?.len();
    let header = read_header(&mut f)?;
    let h = parse_file_header(&header)?;
    let expected = encrypted_len(expected_plain_len, h.chunk_size);
    if expected != actual {
        return Err(CryptoError::SizeMismatch { expected, actual });
    }
    Ok(())
}

/// Legge fino a riempire `buf`; restituisce meno solo a fine stream.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub fn encrypt_stream<R: Read, W: Write>(
    files_key: &[u8; KEY_LEN],
    doc_id: &str,
    input: R,
    output: W,
) -> Result<EncryptedInfo> {
    encrypt_stream_with_chunk_size(files_key, doc_id, input, output, DEFAULT_CHUNK_SIZE)
}

/// Cifra `input` in `output`. Scrivi su un file temporaneo, fai `sync_all()` e
/// solo dopo `rename`; inserisci la riga nel DB per ultima.
pub fn encrypt_stream_with_chunk_size<R: Read, W: Write>(
    files_key: &[u8; KEY_LEN],
    doc_id: &str,
    mut input: R,
    mut output: W,
    chunk_size: usize,
) -> Result<EncryptedInfo> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CryptoError::InvalidFormat("dimensione blocco fuori limite"));
    }
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; STREAM_PREFIX_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut prefix);

    let mut header = [0u8; FH_LEN];
    header[0..4].copy_from_slice(MAGIC_FILE);
    header[4] = FORMAT_VERSION;
    header[5..9].copy_from_slice(&(chunk_size as u32).to_le_bytes());
    header[9..25].copy_from_slice(&salt);
    header[25..32].copy_from_slice(&prefix);
    output.write_all(&header)?;

    let aad = file_aad(&header, doc_id);
    let mut enc = EncryptorBE32::from_aead(file_cipher(files_key, &salt)?, GenericArray::from_slice(&prefix));
    let mut hasher = Sha256::new();
    let mut total = 0u64;

    // Si legge un blocco in anticipo per sapere se quello corrente è l'ultimo.
    let mut cur = Zeroizing::new(vec![0u8; chunk_size]);
    let mut next = Zeroizing::new(vec![0u8; chunk_size]);
    let mut cur_len = read_full(&mut input, &mut cur)?;
    loop {
        let next_len = read_full(&mut input, &mut next)?;
        hasher.update(&cur[..cur_len]);
        total += cur_len as u64;
        let payload = Payload { msg: &cur[..cur_len], aad: &aad };
        if next_len == 0 {
            let ct = enc.encrypt_last(payload).map_err(|_| CryptoError::Internal)?;
            output.write_all(&ct)?;
            break;
        }
        let ct = enc.encrypt_next(payload).map_err(|_| CryptoError::Internal)?;
        output.write_all(&ct)?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    output.flush()?;
    Ok(EncryptedInfo { size_bytes: total, sha256: hasher.finalize().into() })
}

/// Decifra `input` in `output` e restituisce i byte in chiaro scritti.
///
/// ATTENZIONE: i blocchi vengono scritti man mano che sono autenticati, ma la
/// completezza del file (niente troncamenti) si verifica solo all'ultimo blocco.
/// In caso di `Err` l'output è parziale e va scartato (per esempio cancellando
/// lo ZIP in costruzione). Per il viewer usa `decrypt_to_vec`.
pub fn decrypt_stream<R: Read, W: Write>(
    files_key: &[u8; KEY_LEN],
    doc_id: &str,
    mut input: R,
    mut output: W,
) -> Result<u64> {
    let header = read_header(&mut input)?;
    let FileHeader { chunk_size, salt, prefix } = parse_file_header(&header)?;

    let aad = file_aad(&header, doc_id);
    let mut dec = DecryptorBE32::from_aead(file_cipher(files_key, &salt)?, GenericArray::from_slice(&prefix));

    let ct_chunk = chunk_size + TAG_LEN;
    let mut cur = vec![0u8; ct_chunk];
    let mut next = vec![0u8; ct_chunk];
    let mut cur_len = read_full(&mut input, &mut cur)?;
    let mut total = 0u64;
    loop {
        let next_len = read_full(&mut input, &mut next)?;
        let payload = Payload { msg: &cur[..cur_len], aad: &aad };
        if next_len == 0 {
            let pt = Zeroizing::new(dec.decrypt_last(payload).map_err(|_| CryptoError::FileCorrupted)?);
            output.write_all(&pt)?;
            total += pt.len() as u64;
            break;
        }
        let pt = Zeroizing::new(dec.decrypt_next(payload).map_err(|_| CryptoError::FileCorrupted)?);
        output.write_all(&pt)?;
        total += pt.len() as u64;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    output.flush()?;
    Ok(total)
}

struct LimitedVec {
    buf: Zeroizing<Vec<u8>>,
    max: usize,
    exceeded: bool,
}

impl Write for LimitedVec {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > self.max {
            self.exceeded = true;
            return Err(io::Error::new(io::ErrorKind::Other, "limite di dimensione superato"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Per il viewer in memoria: restituisce il contenuto SOLO se tutto il file è
/// autentico e completo. `size_hint` (es. `documents.size_bytes`) preallocata il
/// buffer: se il file è più grande, la crescita del Vec può lasciare in RAM
/// copie non azzerate dei buffer precedenti.
pub fn decrypt_to_vec<R: Read>(
    files_key: &[u8; KEY_LEN],
    doc_id: &str,
    input: R,
    max_bytes: usize,
    size_hint: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut w = LimitedVec {
        buf: Zeroizing::new(Vec::with_capacity(size_hint.min(max_bytes))),
        max: max_bytes,
        exceeded: false,
    };
    match decrypt_stream(files_key, doc_id, input, &mut w) {
        Ok(_) => Ok(w.buf),
        Err(_) if w.exceeded => Err(CryptoError::TooLarge),
        Err(e) => Err(e),
    }
}

// ───────── TEST ─────────
#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";
    const PW2: &str = "tutt'altra password 42";

    fn tp() -> KdfParams { KdfParams { m_kib: 8, t: 2, p: 1 } }
    fn fkey() -> [u8; KEY_LEN] { [7u8; KEY_LEN] }
    fn data(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }

    fn enc(k: &[u8; KEY_LEN], id: &str, d: &[u8], cs: usize) -> (Vec<u8>, EncryptedInfo) {
        let mut out = Vec::new();
        let info = encrypt_stream_with_chunk_size(k, id, d, &mut out, cs).unwrap();
        (out, info)
    }
    fn dec(k: &[u8; KEY_LEN], id: &str, ct: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_stream(k, id, ct, &mut out)?;
        Ok(out)
    }
    fn set_u32(buf: &mut [u8], off: usize, v: u32) { buf[off..off + 4].copy_from_slice(&v.to_le_bytes()); }

    // ── vault ──

    #[test]
    fn vault_roundtrip_e_password_errata() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        assert_eq!(v.meta_bytes.len(), VAULT_META_LEN);
        let k = unlock_vault(&v.meta_bytes, PW).unwrap();
        assert_eq!(k.files_key(), v.keys.files_key());
        assert_eq!(*k.sqlcipher_key_pragma_value(), *v.keys.sqlcipher_key_pragma_value());
        assert!(matches!(unlock_vault(&v.meta_bytes, "password sbagliata"), Err(CryptoError::WrongPasswordOrCorrupted)));
    }

    #[test]
    fn vault_con_parametri_di_default() {
        let v = create_vault(PW).unwrap();
        assert_eq!(parse_vault_meta(&v.meta_bytes).unwrap().params, KdfParams::DEFAULT);
        assert!(unlock_vault(&v.meta_bytes, PW).is_ok());
    }

    #[test]
    fn password_troppo_corta_rifiutata() {
        assert!(matches!(create_vault_with_params("corta", tp()), Err(CryptoError::PasswordTooShort)));
    }

    #[test]
    fn qualsiasi_byte_alterato_in_vault_meta_impedisce_lo_sblocco() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        for i in 0..VAULT_META_LEN {
            let mut m = v.meta_bytes.clone();
            m[i] ^= 0x01;
            assert!(unlock_vault(&m, PW).is_err(), "byte {i} alterato ma sblocco riuscito");
        }
    }

    #[test]
    fn limiti_parametri_argon2_letti_dal_file() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        let try_with = |off: usize, val: u32| {
            let mut m = v.meta_bytes.clone();
            set_u32(&mut m, off, val);
            unlock_vault(&m, PW)
        };
        assert!(matches!(try_with(5, u32::MAX), Err(CryptoError::InvalidMeta(_)))); // memoria enorme
        assert!(matches!(try_with(5, 1), Err(CryptoError::InvalidMeta(_)))); // troppo poca
        assert!(matches!(try_with(9, 1), Err(CryptoError::InvalidMeta(_)))); // t troppo basso
        assert!(matches!(try_with(9, 1000), Err(CryptoError::InvalidMeta(_)))); // t enorme
        assert!(matches!(try_with(13, 64), Err(CryptoError::InvalidMeta(_)))); // p enorme
        assert!(create_vault_with_params(PW, KdfParams { m_kib: 4, t: 2, p: 1 }).is_err());
    }

    #[test]
    fn cambio_password_non_cambia_le_chiavi() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        let (ct, _) = enc(v.keys.files_key(), "doc-1", &data(5000), 4096);

        let new_meta = change_password(&v.meta_bytes, PW, PW2).unwrap();
        assert_ne!(new_meta, v.meta_bytes);
        assert!(unlock_vault(&new_meta, PW).is_err());
        let k2 = unlock_vault(&new_meta, PW2).unwrap();
        assert_eq!(dec(k2.files_key(), "doc-1", &ct).unwrap(), data(5000)); // niente da ricifrare

        assert!(matches!(change_password(&v.meta_bytes, "sbagliata sbagliata", PW2), Err(CryptoError::WrongPasswordOrCorrupted)));
        assert!(matches!(change_password(&v.meta_bytes, PW, "corta"), Err(CryptoError::PasswordTooShort)));
    }

    #[test]
    fn sottochiavi_distinte_e_formato_pragma_sqlcipher() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        assert_ne!(v.keys.files_key(), v.keys.audit_key());
        let p = v.keys.sqlcipher_key_pragma_value();
        assert_eq!(p.len(), 67);
        assert!(p.starts_with("x'") && p.ends_with('\''));
        assert!(p[2..66].chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(&p[2..66], hex(v.keys.files_key()));
    }

    // ── file .enc ──

    #[test]
    fn roundtrip_a_confini_di_blocco() {
        for n in [0usize, 1, 4095, 4096, 4097, 8192, 10_000, 3 * 4096] {
            let d = data(n);
            let (ct, info) = enc(&fkey(), "doc-A", &d, 4096);
            assert_eq!(info.size_bytes, n as u64);
            assert_eq!(info.sha256.to_vec(), Sha256::digest(&d).to_vec());
            assert_eq!(dec(&fkey(), "doc-A", &ct).unwrap(), d, "n = {n}");
        }
    }

    #[test]
    fn encrypted_len_coincide_con_la_lunghezza_reale() {
        for n in [0usize, 1, 4095, 4096, 4097, 8192, 10_000] {
            let (ct, _) = enc(&fkey(), "doc-A", &data(n), 4096);
            assert_eq!(ct.len() as u64, encrypted_len(n as u64, 4096), "n = {n}");
        }
    }

    #[test]
    fn roundtrip_con_blocco_di_default() {
        let d = data(2 * DEFAULT_CHUNK_SIZE + DEFAULT_CHUNK_SIZE / 2);
        let mut ct = Vec::new();
        let info = encrypt_stream(&fkey(), "doc-big", &d[..], &mut ct).unwrap();
        assert_eq!(info.size_bytes as usize, d.len());
        assert_eq!(ct.len(), FH_LEN + d.len() + 3 * TAG_LEN);
        assert_eq!(dec(&fkey(), "doc-big", &ct).unwrap(), d);
    }

    #[test]
    fn due_cifrature_dello_stesso_file_sono_diverse_e_senza_testo_in_chiaro() {
        let d = b"RADIOGRAFIA-SEGRETA".repeat(500);
        let (a, _) = enc(&fkey(), "doc-A", &d, 4096);
        let (b, _) = enc(&fkey(), "doc-A", &d, 4096);
        assert_ne!(a, b);
        assert_eq!(&a[0..4], b"DENC");
        assert!(!a.windows(10).any(|w| w == b"RADIOGRAFI"));
    }

    #[test]
    fn chiave_o_document_id_sbagliati_falliscono() {
        let (ct, _) = enc(&fkey(), "doc-A", &data(9000), 4096);
        assert!(matches!(dec(&fkey(), "doc-B", &ct), Err(CryptoError::FileCorrupted)));
        assert!(matches!(dec(&[8u8; KEY_LEN], "doc-A", &ct), Err(CryptoError::FileCorrupted)));
    }

    #[test]
    fn alterazioni_del_file_vengono_rilevate() {
        let (ct, _) = enc(&fkey(), "doc-A", &data(3 * 4096 + 100), 4096);
        let chunk = 4096 + TAG_LEN;

        for pos in [0, 4, 6, 12, 30, FH_LEN + 5, FH_LEN + chunk + 7, ct.len() - 1] {
            let mut m = ct.clone();
            m[pos] ^= 0x01;
            assert!(dec(&fkey(), "doc-A", &m).is_err(), "byte {pos}");
        }
        // troncamento esattamente a un confine di blocco
        assert!(dec(&fkey(), "doc-A", &ct[..FH_LEN + 3 * chunk]).is_err());
        // troncamento a metà blocco, a solo header, a header incompleto
        assert!(dec(&fkey(), "doc-A", &ct[..ct.len() - 5]).is_err());
        assert!(dec(&fkey(), "doc-A", &ct[..FH_LEN]).is_err());
        assert!(matches!(dec(&fkey(), "doc-A", &ct[..10]), Err(CryptoError::InvalidFormat(_))));
        // dati aggiunti in coda
        let mut ext = ct.clone();
        ext.extend_from_slice(&[0u8; 10]);
        assert!(dec(&fkey(), "doc-A", &ext).is_err());
        // blocchi scambiati
        let mut sw = ct.clone();
        let (a, b) = (FH_LEN, FH_LEN + chunk);
        for i in 0..chunk {
            sw.swap(a + i, b + i);
        }
        assert!(dec(&fkey(), "doc-A", &sw).is_err());
    }

    #[test]
    fn verify_encrypted_file_len_su_file_reali() {
        let dir = std::env::temp_dir().join(format!("crypto-len-{}", hex(&data(4)[..4]) + &std::process::id().to_string()));
        std::fs::create_dir_all(&dir).unwrap();
        let (ct, _) = enc(&fkey(), "doc-A", &data(10_000), 4096);
        let p = dir.join("a.enc");
        std::fs::write(&p, &ct).unwrap();
        assert!(verify_encrypted_file_len(&p, 10_000).is_ok());
        assert!(matches!(verify_encrypted_file_len(&p, 10_001), Err(CryptoError::SizeMismatch { .. })));
        std::fs::write(&p, &ct[..ct.len() - 1]).unwrap();
        assert!(matches!(verify_encrypted_file_len(&p, 10_000), Err(CryptoError::SizeMismatch { .. })));
        std::fs::write(&p, &ct[..10]).unwrap();
        assert!(matches!(verify_encrypted_file_len(&p, 10_000), Err(CryptoError::InvalidFormat(_))));
        std::fs::write(&p, b"questo non e' un file cifrato, ma e' abbastanza lungo").unwrap();
        assert!(matches!(verify_encrypted_file_len(&p, 10), Err(CryptoError::InvalidFormat(_))));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn dimensione_blocco_nel_header_validata() {
        let (ct, _) = enc(&fkey(), "doc-A", &data(100), 4096);
        for v in [1u32, 100, u32::MAX] {
            let mut m = ct.clone();
            set_u32(&mut m, 5, v);
            assert!(matches!(dec(&fkey(), "doc-A", &m), Err(CryptoError::InvalidFormat(_))), "cs = {v}");
        }
    }

    #[test]
    fn decrypt_to_vec_rispetta_il_limite_e_non_restituisce_dati_parziali() {
        let d = data(10_000);
        let (ct, _) = enc(&fkey(), "doc-A", &d, 4096);
        let ok = decrypt_to_vec(&fkey(), "doc-A", &ct[..], 20_000, d.len()).unwrap();
        assert_eq!(&ok[..], &d[..]);
        assert!(matches!(decrypt_to_vec(&fkey(), "doc-A", &ct[..], 5_000, 0), Err(CryptoError::TooLarge)));
        assert!(matches!(decrypt_to_vec(&fkey(), "doc-B", &ct[..], 20_000, 0), Err(CryptoError::FileCorrupted)));
    }

    // ── KeyStore ──

    #[test]
    fn keystore_lock_unlock() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        let ks = KeyStore::new(Duration::from_secs(60));
        assert!(matches!(ks.keys(), Err(CryptoError::Locked)));
        ks.unlock(v.keys.clone());
        assert!(ks.is_unlocked());
        assert_eq!(ks.keys().unwrap().files_key(), v.keys.files_key());
        ks.lock();
        assert!(!ks.is_unlocked());
        assert!(matches!(ks.keys(), Err(CryptoError::Locked)));
    }

    #[test]
    fn keystore_blocco_per_inattivita_e_attivita_che_rinvia_il_blocco() {
        let v = create_vault_with_params(PW, tp()).unwrap();
        let ks = KeyStore::new(Duration::from_millis(400));
        ks.unlock(v.keys.clone());
        std::thread::sleep(Duration::from_millis(250));
        assert!(ks.keys().is_ok()); // attività: azzera il timer
        std::thread::sleep(Duration::from_millis(250));
        assert!(ks.keys().is_ok()); // 250 ms dall'ultima attività, non 500
        std::thread::sleep(Duration::from_millis(600));
        assert!(ks.expire_if_idle()); // il thread di fondo blocca anche senza richieste
        assert!(matches!(ks.keys(), Err(CryptoError::Locked)));
        assert!(!ks.expire_if_idle());
    }
}