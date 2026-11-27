//! Registro degli accessi lato applicazione: export CSV per ispezioni e controlli interni.

use super::*;
use std::fs::OpenOptions;
use std::io::BufWriter;

const CSV_SEP: char = ';'; // separatore che Excel in italiano riconosce aprendo il file

/// Ogni quante righe l'export ricontrolla che la sessione sia ancora aperta.
const CSV_CHECK_EVERY: u64 = 1000;

/// Campo CSV: tra virgolette se contiene separatore, virgolette o a capo; un apostrofo
/// davanti a `= + - @` impedisce che un foglio di calcolo lo interpreti come formula.
pub(super) fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    if s.contains([CSV_SEP, ',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn csv_line(fields: &[&str]) -> String {
    let mut line = fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(&CSV_SEP.to_string());
    line.push_str("\r\n");
    line
}

fn io_err(_: std::io::Error) -> CommandError {
    CommandError::new(ErrorCode::IoError, "Errore durante la scrittura del file.")
}

impl AppCore {
    /// Esporta il registro in CSV UTF-8. `date_from` e `date_to` (`YYYY-MM-DD`, incluse e
    /// facoltative) sono giorni locali del computer, come li intende chi usa l'app; nel file
    /// ci sono sia il timestamp UTC salvato sia l'ora locale.
    /// Il file non deve esistere. Contiene solo ID e conteggi: l'abbinamento ID → paziente si
    /// fa dall'applicazione. Le righe si scrivono una alla volta (il log cresce negli anni).
    /// L'export stesso viene registrato (EXPORT_AUDIT); se la registrazione fallisce, o se
    /// l'archivio viene bloccato mentre si scrive, il file viene cancellato. L'esito della
    /// verifica della catena è nel risultato: il CSV si produce anche se la catena risulta
    /// alterata, perché serve proprio a esaminarla.
    pub fn export_audit_csv(&self, dest: &Path, date_from: Option<&str>, date_to: Option<&str>) -> Res<AuditExportDto> {
        let _op = self.begin_op();
        let (keys, epoch) = self.op_session()?;
        check_export_dest(&self.vault_dir, dest, "csv")?;
        let db = self.heavy_db(&keys)?;

        let mut f = OpenOptions::new().write(true).create_new(true).open(dest).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                CommandError::new(ErrorCode::AlreadyExists, "Esiste già un file con questo nome.")
            } else {
                CommandError::new(ErrorCode::IoError, "Impossibile creare il file di destinazione.")
            }
        })?;

        let written = (|| -> Res<u64> {
            let mut w = BufWriter::new(&mut f);
            w.write_all("\u{feff}".as_bytes()).map_err(io_err)?; // BOM: Excel apre il file come UTF-8
            w.write_all(
                csv_line(&["id", "timestamp_utc", "ora_locale", "actor", "action", "target_id", "details", "prev_hash", "row_hash"])
                    .as_bytes(),
            )
            .map_err(io_err)?;
            let mut n = 0u64;
            let rows = db.for_each_audit_entry(date_from, date_to, |e| -> Res<()> {
                n += 1;
                if n % CSV_CHECK_EVERY == 0 && !self.still_current(epoch) {
                    return Err(CommandError::locked());
                }
                let id = e.id.to_string();
                let line = csv_line(&[
                    &id, &e.timestamp, &e.timestamp_local, &e.actor, &e.action,
                    e.target_id.as_deref().unwrap_or(""), e.details.as_deref().unwrap_or(""),
                    &e.prev_hash, &e.row_hash,
                ]);
                w.write_all(line.as_bytes()).map_err(io_err)
            })?;
            w.flush().map_err(io_err)?;
            drop(w);
            f.sync_all().map_err(io_err)?;
            Ok(rows)
        })();
        drop(f);

        let result = written.and_then(|rows| {
            // archivio bloccato mentre si scriveva: il file in chiaro non si consegna
            if !self.still_current(epoch) {
                return Err(CommandError::locked());
            }
            let mut details = format!("rows={rows}");
            for (k, v) in [("from", date_from), ("to", date_to)] {
                if let Some(v) = v {
                    details.push_str(&format!(";{k}={v}"));
                }
            }
            db.log_audit("EXPORT_AUDIT", None, Some(&details))?;
            Ok(rows)
        });
        let rows = match result {
            Ok(r) => r,
            Err(e) => {
                if fs::remove_file(dest).is_err() {
                    return Err(CommandError::new(
                        ErrorCode::CleanupFailed,
                        "Export non riuscito e file parziale non rimosso: cancellalo a mano.",
                    )
                    .with_detail(e.message));
                }
                return Err(e);
            }
        };
        // verifica DOPO l'inserimento di EXPORT_AUDIT: l'esito riguarda il registro com'è ora
        let check = self.audit_info(&db);
        Ok(AuditExportDto { rows: rows as u32, audit_ok: check.audit_ok, audit_message: check.audit_message })
    }
}
