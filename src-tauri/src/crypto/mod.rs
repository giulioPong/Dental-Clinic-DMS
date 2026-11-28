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

mod error;
mod keystore;
mod file_enc;

pub use error::*;
pub use keystore::*;
pub use file_enc::*;

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

#[cfg(test)]
mod tests;
