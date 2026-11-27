//! Utilità condivise: nomi e tipi MIME, scritture sincronizzate, snapshot del DB.

use super::*;

/// Destinazione di un export in chiaro: estensione attesa, cartella esistente e non dentro
/// il vault (finirebbe nel raggio del backup).
pub(super) fn check_export_dest(vault_dir: &Path, dest: &Path, ext: &str) -> Res<()> {
    let ok_ext = dest.extension().map(|e| e.eq_ignore_ascii_case(ext)).unwrap_or(false);
    if !ok_ext {
        return Err(CommandError::new(
            ErrorCode::InvalidInput,
            &format!("Il file di destinazione deve avere estensione .{ext}."),
        ));
    }
    let parent = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent_canon = fs::canonicalize(&parent).map_err(|_| CommandError::invalid("La cartella di destinazione non esiste."))?;
    if let Ok(vault) = fs::canonicalize(vault_dir) {
        if parent_canon.starts_with(&vault) {
            return Err(CommandError::invalid("Scegli una cartella fuori dall'archivio."));
        }
    }
    Ok(())
}

pub(super) fn display_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.to_string_lossy().into_owned())
}

pub(super) fn mime_for(name: &str) -> &'static str {
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
pub(super) fn is_ignored_child(name: &str) -> bool {
    name.starts_with('.') || name.eq_ignore_ascii_case("thumbs.db") || name.eq_ignore_ascii_case("desktop.ini")
}

pub(super) fn check_len(s: &str, max: usize) -> Res<()> {
    if s.chars().count() > max { Err(CommandError::invalid("Testo troppo lungo.")) } else { Ok(()) }
}

pub(super) fn write_replace_synced(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dest)
}

/// Snapshot cifrato del DB in `dir/gestionale.db` più il suo checkpoint in
/// `dir/audit.checkpoint`. Il checkpoint si legge PRIMA della copia e si scrive DOPO: lo
/// snapshot contiene sempre almeno le righe del checkpoint accanto, anche se un'operazione
/// pesante scrive nel frattempo su un'altra connessione o se il processo si interrompe tra i
/// due passi. Per ripristinare si usano i due file di questa cartella insieme.
pub(super) fn write_snapshot(db: &Db, keys: &Keys, dir: &Path) -> Res<()> {
    fs::create_dir_all(dir).map_err(|_| CommandError::new(ErrorCode::IoError, "Cartella di backup non accessibile."))?;
    let cp = db.audit_checkpoint()?;
    let tmp = dir.join("gestionale.db.new");
    let _ = fs::remove_file(&tmp);
    db.backup_to(&tmp, keys)?;
    fs::rename(&tmp, dir.join(SNAPSHOT_DB)).map_err(|_| CommandError::new(ErrorCode::IoError, "Impossibile salvare lo snapshot del database."))?;
    write_replace_synced(&dir.join(SNAPSHOT_CHECKPOINT), cp.to_line().as_bytes())
        .map_err(|_| CommandError::new(ErrorCode::IoError, "Impossibile salvare il checkpoint dello snapshot."))
}

pub(super) const SNAPSHOT_DB: &str = crate::backup::DB_FILE;
pub(super) const SNAPSHOT_CHECKPOINT: &str = crate::backup::CHECKPOINT_FILE;
