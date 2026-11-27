//! Utilità condivise: nomi e tipi MIME, scritture sincronizzate, snapshot del DB.

use super::*;

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

pub(super) fn write_snapshot(db: &Db, keys: &Keys, dir: &Path) -> Res<()> {
    fs::create_dir_all(dir).map_err(|_| CommandError::new(ErrorCode::IoError, "Cartella di backup non accessibile."))?;
    let tmp = dir.join("gestionale.db.new");
    let _ = fs::remove_file(&tmp);
    db.backup_to(&tmp, keys)?;
    fs::rename(&tmp, dir.join("gestionale.db")).map_err(|_| CommandError::new(ErrorCode::IoError, "Impossibile salvare lo snapshot del database."))
}
