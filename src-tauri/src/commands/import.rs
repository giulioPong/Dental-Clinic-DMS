//! Import dello storico: cartelle di pazienti già presenti sul PC dello studio.
//!
//! Struttura attesa sotto la cartella scelta:
//! ```text
//! <radice>/
//!   Rossi_Mario_1980-05-12/                 Cognome_Nome_Data[_CodiceFiscale]
//!     Panoramica/rx.jpg                     sottocartella con il nome di una categoria
//!     referto.pdf                           tutto il resto → "Altro"
//!   De Luca_Maria Grazia_12-05-1980_DLCMGR80E52H501X/
//! ```
//! Il separatore è `_` perché cognomi e nomi possono contenere spazi. Data `AAAA-MM-GG`,
//! `GG-MM-AAAA` o `GG.MM.AAAA`.
//!
//! Flusso: `preview_import` mostra cosa succederà senza scrivere nulla; `import_directory`
//! lo esegue. Rieseguirlo sulla stessa cartella non crea doppioni: i pazienti si abbinano
//! (codice fiscale, poi cognome + nome + data) e i file già presenti per quel paziente si
//! riconoscono dallo SHA-256 del contenuto. Ogni paziente e ogni file passano dagli stessi
//! controlli e dallo stesso audit dell'inserimento a mano.

use super::*;
use crate::db::{PatientMatch, CATEGORY_TAGS};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Una cartella di paziente letta e validata.
struct PlannedPatient {
    folder: String,
    last: String,
    first: String,
    birth: String,
    fiscal_code: Option<String>,
    existing_id: Option<String>,
    /// (percorso assoluto, percorso relativo da mostrare, categoria)
    files: Vec<(PathBuf, String, &'static str)>,
    bytes: u64,
}

fn issue(folder: &str, file: Option<&str>, code: ErrorCode, message: &str) -> ImportIssueDto {
    ImportIssueDto { folder: folder.to_string(), file: file.map(str::to_string), code, message: message.to_string() }
}

/// `AAAA-MM-GG`, `GG-MM-AAAA` o `GG.MM.AAAA` → `AAAA-MM-GG` (la validità del calendario la
/// controlla il database).
pub(super) fn parse_folder_date(s: &str) -> Option<String> {
    let digits = |p: &str, n: usize| p.len() == n && p.chars().all(|c| c.is_ascii_digit());
    let parts: Vec<&str> = s.split(['-', '.']).collect();
    match parts.as_slice() {
        [y, m, d] if digits(y, 4) && digits(m, 2) && digits(d, 2) && s.contains('-') => Some(format!("{y}-{m}-{d}")),
        [d, m, y] if digits(d, 2) && digits(m, 2) && digits(y, 4) => Some(format!("{y}-{m}-{d}")),
        _ => None,
    }
}

/// `Cognome_Nome_Data[_CF]` → (cognome, nome, data, cf).
pub(super) fn parse_folder_name(name: &str) -> std::result::Result<(String, String, String, Option<String>), &'static str> {
    let parts: Vec<&str> = name.split('_').map(str::trim).collect();
    if !(3..=4).contains(&parts.len()) {
        return Err("Nome cartella non riconosciuto: usa Cognome_Nome_AAAA-MM-GG (codice fiscale facoltativo in fondo).");
    }
    let (last, first) = (parts[0], parts[1]);
    if last.is_empty() || first.is_empty() {
        return Err("Cognome e nome obbligatori nel nome della cartella.");
    }
    let birth = parse_folder_date(parts[2]).ok_or("Data di nascita non riconosciuta (AAAA-MM-GG, GG-MM-AAAA o GG.MM.AAAA).")?;
    let cf = parts.get(3).filter(|s| !s.is_empty()).map(|s| s.to_string());
    Ok((last.to_string(), first.to_string(), birth, cf))
}

/// Categoria dalla prima sottocartella (senza distinguere maiuscole), altrimenti "Altro".
fn category_for(rel: &Path) -> &'static str {
    let mut comps = rel.components();
    let first = comps.next().map(|c| c.as_os_str().to_string_lossy().to_lowercase());
    if comps.next().is_none() {
        return "Altro"; // file direttamente nella cartella del paziente
    }
    CATEGORY_TAGS.iter().copied().find(|t| Some(t.to_lowercase()) == first).unwrap_or("Altro")
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = BufReader::new(File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(crate::crypto::hex(&h.finalize()))
}

impl AppCore {
    /// Legge la cartella e prepara il piano: pazienti validi (con l'eventuale scheda già
    /// presente) e problemi. Non scrive nulla.
    fn plan_import(&self, db: &Db, root: &Path) -> Res<(Vec<PlannedPatient>, Vec<ImportIssueDto>)> {
        let meta = fs::symlink_metadata(root).map_err(|_| CommandError::invalid("Cartella da importare non trovata."))?;
        if !meta.is_dir() {
            return Err(CommandError::invalid("Scegli una cartella, non un file."));
        }
        let vault = fs::canonicalize(&self.vault_dir).ok();
        if let (Some(v), Ok(r)) = (&vault, fs::canonicalize(root)) {
            if r.starts_with(v) || v.starts_with(&r) {
                return Err(CommandError::invalid("La cartella da importare non può contenere l'archivio né stare al suo interno."));
            }
        }
        let mut entries: Vec<PathBuf> = Vec::new();
        let mut problems = Vec::new();
        for e in fs::read_dir(root).map_err(|_| CommandError::new(ErrorCode::IoError, "Cartella non leggibile."))? {
            match e {
                Ok(e) => entries.push(e.path()),
                Err(_) => problems.push(issue("", None, ErrorCode::IoError, "Elemento della cartella non leggibile: ignorato.")),
            }
        }
        entries.sort();

        let mut planned = Vec::new();
        for path in entries {
            let folder = display_name(&path);
            if is_ignored_child(&folder) {
                continue;
            }
            let Ok(m) = fs::symlink_metadata(&path) else {
                problems.push(issue(&folder, None, ErrorCode::IoError, "Non leggibile: ignorato."));
                continue;
            };
            if !m.is_dir() || m.file_type().is_symlink() {
                problems.push(issue(&folder, None, ErrorCode::InvalidInput, "Non è la cartella di un paziente: ignorato."));
                continue;
            }
            let (last, first, birth, cf) = match parse_folder_name(&folder) {
                Ok(p) => p,
                Err(msg) => {
                    problems.push(issue(&folder, None, ErrorCode::InvalidInput, msg));
                    continue;
                }
            };
            if let Err(e) = Self::check_patient_fields(&first, &last, cf.as_deref(), "") {
                problems.push(issue(&folder, None, e.code, &e.message));
                continue;
            }
            if !db.is_valid_birth_date(&birth)? {
                problems.push(issue(&folder, None, ErrorCode::InvalidInput, "Data di nascita non valida o nel futuro."));
                continue;
            }
            let existing_id = match db.find_patient_for_import(&first, &last, &birth, cf.as_deref())? {
                PatientMatch::None => None,
                PatientMatch::Active(id) => Some(id),
                PatientMatch::InTrash(_) => {
                    problems.push(issue(&folder, None, ErrorCode::PatientInTrash, "Il paziente è nel cestino: ripristinalo prima di importare."));
                    continue;
                }
                PatientMatch::Ambiguous => {
                    problems.push(issue(&folder, None, ErrorCode::InvalidState, "Più schede con stessi dati: importa questa cartella a mano."));
                    continue;
                }
            };
            if existing_id.is_none() {
                if let Some(cf) = &cf {
                    let n = crate::db::normalize_fiscal_code(Some(cf)).unwrap_or_default();
                    if n.len() != 16 || !n.chars().all(|c| c.is_ascii_alphanumeric()) {
                        problems.push(issue(&folder, None, ErrorCode::InvalidInput, "Codice fiscale non valido."));
                        continue;
                    }
                }
            }

            let mut found = Vec::new();
            let mut failures = Vec::new();
            match self.walk(&path, 0, &vault, &mut found, &mut failures) {
                Ok(()) => {}
                Err(e) => {
                    problems.push(issue(&folder, None, e.code, &e.message));
                    continue;
                }
            }
            for f in failures {
                problems.push(issue(&folder, Some(&f.name), f.code, &f.message));
            }
            let mut files = Vec::new();
            let mut bytes = 0u64;
            for p in found {
                let rel = p.strip_prefix(&path).unwrap_or(&p).to_path_buf();
                bytes += fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                files.push((p.clone(), rel.to_string_lossy().replace('\\', "/"), category_for(&rel)));
            }
            planned.push(PlannedPatient { folder, last, first, birth, fiscal_code: cf, existing_id, files, bytes });
        }
        Ok((planned, problems))
    }

    /// Anteprima dell'import: nessuna scrittura, nessun audit.
    pub fn preview_import(&self, root: &Path) -> Res<ImportPreviewDto> {
        let _op = self.begin_op();
        let (keys, _) = self.op_session()?;
        let db = self.heavy_db(&keys)?;
        let (planned, problems) = self.plan_import(&db, root)?;
        let mut out = ImportPreviewDto { problems, ..Default::default() };
        for p in planned {
            out.total_files += p.files.len() as u32;
            out.total_bytes += p.bytes;
            out.patients.push(ImportPatientDto {
                folder: p.folder,
                last_name: p.last,
                first_name: p.first,
                birth_date: p.birth,
                fiscal_code: p.fiscal_code,
                existing_id: p.existing_id,
                files: p.files.len() as u32,
                bytes: p.bytes,
            });
        }
        Ok(out)
    }

    /// Esegue l'import. Un errore su un paziente o su un file non ferma gli altri; se
    /// l'archivio si blocca, i file restanti finiscono tra i falliti e basta rilanciare
    /// l'import dopo lo sblocco (i file già importati vengono riconosciuti e saltati).
    /// `on_progress(file fatti, file totali)` dopo ogni file.
    pub fn import_directory(&self, root: &Path, mut on_progress: impl FnMut(usize, usize)) -> Res<ImportReportDto> {
        let _op = self.begin_op();
        let (keys, epoch) = self.op_session()?;
        let db = self.heavy_db(&keys)?;
        let (planned, problems) = self.plan_import(&db, root)?;
        let mut report = ImportReportDto { failed: problems, ..Default::default() };
        let total: usize = planned.iter().map(|p| p.files.len()).sum();
        let mut done = 0usize;
        let mut stopped: Option<CommandError> = None;

        for p in planned {
            if stopped.is_none() {
                if let Err(e) = self.auth().and_then(|_| if self.still_current(epoch) { Ok(()) } else { Err(CommandError::locked()) }) {
                    stopped = Some(e);
                }
            }
            if let Some(e) = &stopped {
                // file per file: il wizard deve poter dire esattamente cosa manca
                for (_, rel, _) in &p.files {
                    report.failed.push(issue(&p.folder, Some(rel), e.code, &e.message));
                }
                done += p.files.len();
                continue;
            }
            // si cerca di nuovo: una cartella precedente può aver appena creato la stessa scheda
            let pid = match db.find_patient_for_import(&p.first, &p.last, &p.birth, p.fiscal_code.as_deref()) {
                Ok(PatientMatch::Active(id)) => {
                    report.patients_matched += 1;
                    id
                }
                Ok(PatientMatch::None) => match db.create_patient(&p.first, &p.last, &p.birth, p.fiscal_code.as_deref()) {
                    Ok(id) => {
                        report.patients_created += 1;
                        id
                    }
                    Err(e) => {
                        let e = CommandError::from(e);
                        report.failed.push(issue(&p.folder, None, e.code, &e.message));
                        done += p.files.len();
                        continue;
                    }
                },
                Ok(_) => {
                    report.failed.push(issue(&p.folder, None, ErrorCode::InvalidState, "Scheda nel cestino o ambigua: cartella saltata."));
                    done += p.files.len();
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            let mut budget = MAX_UPLOAD_BATCH_BYTES; // per paziente: lo storico intero può superarlo
            for (path, rel, tag) in &p.files {
                done += 1;
                if stopped.is_none() {
                    if let Err(e) = self.auth().and_then(|_| if self.still_current(epoch) { Ok(()) } else { Err(CommandError::locked()) }) {
                        stopped = Some(e);
                    }
                }
                if let Some(e) = &stopped {
                    report.failed.push(issue(&p.folder, Some(rel), e.code, &e.message));
                    on_progress(done, total);
                    continue;
                }
                let sha = match sha256_file(path) {
                    Ok(h) => h,
                    Err(_) => {
                        report.failed.push(issue(&p.folder, Some(rel), ErrorCode::IoError, "File non leggibile."));
                        on_progress(done, total);
                        continue;
                    }
                };
                match db.has_document_with_hash(&pid, &sha) {
                    Ok(true) => {
                        report.duplicates.push(issue(&p.folder, Some(rel), ErrorCode::AlreadyExists, "Già presente: saltato."));
                    }
                    Ok(false) => {
                        let name = display_name(path);
                        match self.upload_one(&db, &keys, &pid, path, &name, tag, epoch, &mut budget) {
                            Ok(_) => report.uploaded += 1,
                            Err(e) => {
                                if e.code == ErrorCode::Locked {
                                    stopped = Some(e.clone());
                                }
                                report.failed.push(issue(&p.folder, Some(rel), e.code, &e.message));
                            }
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                on_progress(done, total);
            }
        }
        Ok(report)
    }
}
