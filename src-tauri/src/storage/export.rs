//! Export ZIP in chiaro dei documenti di un paziente e nomi file sicuri.

use super::*;

pub(super) const WINDOWS_RESERVED: [&str; 22] = [
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
pub(super) fn export_entry_name(d: &DocumentRecord) -> String {
    let date = d.created_at.get(..10).unwrap_or("0000-00-00");
    let tag = sanitize_filename(&d.category_tag.replace(' ', "-"), 30);
    let name = sanitize_filename(&d.original_filename, 120);
    format!("{date}_{tag}_{name}")
}

pub(super) fn unique_name(used: &mut HashSet<String>, name: String) -> String {
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
pub(super) fn compression_for(name: &str) -> CompressionMethod {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "webp" | "pdf" | "zip" | "heic" => CompressionMethod::Stored,
        _ => CompressionMethod::Deflated,
    }
}

impl Storage {
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
}
