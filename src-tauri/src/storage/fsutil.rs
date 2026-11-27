//! Utilità di basso livello sul file system: scritture sincronizzate, rimozioni
//! controllate, rename senza sovrascrittura, hashing in scrittura.

use super::*;

/// `fsync` della cartella: solo su Unix. Su Windows con la sola std non è possibile
/// (e `rename` è comunque atomico sullo stesso volume).
/// Come `fs::remove_file`, ma un file già assente non è un errore.
pub(super) fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
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

pub(super) fn write_new_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// `<uuid>.enc` con uuid minuscolo a 36 caratteri.
pub(super) fn is_enc_name(name: &str) -> bool {
    match name.strip_suffix(".enc") {
        Some(stem) => stem.len() == 36 && stem == stem.to_lowercase() && uuid::Uuid::parse_str(stem).is_ok(),
        None => false,
    }
}

/// Rimuove un file; "non trovato" conta come riuscito, ogni altro errore viene restituito.
pub(super) fn remove_checked(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Da usare quando un'operazione è fallita e bisogna ripulire un file in chiaro: se anche
/// la pulizia fallisce, l'errore lo dice (percorso incluso) invece di tacerlo.
pub(super) fn fail_with_cleanup(path: &Path, original: StorageError) -> StorageError {
    match remove_checked(path) {
        Ok(()) => original,
        Err(e) => StorageError::CleanupFailed { path: path.to_path_buf(), cause: original.to_string(), io: e.to_string() },
    }
}

/// Sposta `src` in `dest` SENZA mai sovrascrivere: prima riserva il nome con una creazione
/// esclusiva (atomica, funziona anche su exFAT/FAT dove non esistono hard link), poi
/// rinomina sopra il segnaposto. Se `dest` esiste già, errore `AlreadyExists` e `src` resta.
pub(super) fn rename_no_clobber(src: &Path, dest: &Path) -> io::Result<()> {
    OpenOptions::new().write(true).create_new(true).open(dest)?;
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(dest); // il segnaposto è nostro
            Err(e)
        }
    }
}

pub(super) fn has_enc_files(dir: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.file_name().to_string_lossy().ends_with(".enc") {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: Sha256,
    count: u64,
}
impl<'a, W: Write> HashingWriter<'a, W> {
    pub(super) fn new(inner: &'a mut W) -> Self { Self { inner, hasher: Sha256::new(), count: 0 } }
    pub(super) fn finish(self) -> (u64, String) { (self.count, hex(&self.hasher.finalize())) }
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
