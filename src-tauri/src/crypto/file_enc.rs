//! Cifratura dei file a blocchi (AES-256-GCM in streaming, formato `.enc`).

use super::*;

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

pub(super) fn file_aad(header: &[u8; FH_LEN], doc_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FH_LEN + doc_id.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(doc_id.as_bytes());
    aad
}

pub(super) fn file_cipher(files_key: &[u8; KEY_LEN], file_salt: &[u8; SALT_LEN]) -> Result<Aes256Gcm> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), files_key);
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(b"gestionale/v1/file", &mut k[..]).map_err(|_| CryptoError::Internal)?;
    Aes256Gcm::new_from_slice(&k[..]).map_err(|_| CryptoError::Internal)
}

pub(super) struct FileHeader {
    chunk_size: usize,
    salt: [u8; SALT_LEN],
    prefix: [u8; STREAM_PREFIX_LEN],
}

/// Unico punto che conosce il layout del header (offset compresi).
pub(super) fn parse_file_header(header: &[u8; FH_LEN]) -> Result<FileHeader> {
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

pub(super) fn read_header<R: Read>(input: &mut R) -> Result<[u8; FH_LEN]> {
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
pub(super) fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
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

pub(super) struct LimitedVec {
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
