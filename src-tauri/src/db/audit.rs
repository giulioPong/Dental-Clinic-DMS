//! Audit log a catena HMAC: scrittura, verifica e checkpoint esterno.

use super::*;

pub(super) const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ───────── Audit: HMAC e checkpoint ─────────

pub(super) type HmacSha256 = Hmac<Sha256>;

pub(super) fn mac_field(m: &mut HmacSha256, s: &str) {
    m.update(&(s.len() as u32).to_be_bytes());
    m.update(s.as_bytes());
}

pub(super) fn mac_opt(m: &mut HmacSha256, s: Option<&str>) {
    match s {
        Some(v) => { m.update(&[1]); mac_field(m, v); }
        None => m.update(&[0]),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn audit_mac(
    key: &[u8; 32], id: i64, ts: &str, actor: &str, action: &str,
    target: Option<&str>, details: Option<&str>, prev_hash: &str,
) -> String {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accetta chiavi di qualsiasi lunghezza");
    m.update(b"gestionale-audit-v1");
    m.update(&id.to_be_bytes());
    mac_field(&mut m, ts);
    mac_field(&mut m, actor);
    mac_field(&mut m, action);
    mac_opt(&mut m, target);
    mac_opt(&mut m, details);
    mac_field(&mut m, prev_hash);
    hex(&m.finalize().into_bytes())
}

pub(super) fn checkpoint_mac(key: &[u8; 32], last_id: i64, last_hash: &str) -> String {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accetta chiavi di qualsiasi lunghezza");
    m.update(b"gestionale-audit-checkpoint-v1");
    m.update(&last_id.to_be_bytes());
    m.update(last_hash.as_bytes());
    hex(&m.finalize().into_bytes())
}

/// Punto di controllo dell'audit da conservare FUORI dal database (es. in
/// `vault/audit.checkpoint`): senza di esso un troncamento in coda al log non
/// è rilevabile. Aggiornalo al logout, ai backup e periodicamente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheckpoint {
    pub last_id: i64,
    pub last_hash: String,
    pub mac: String,
}

impl AuditCheckpoint {
    pub fn to_line(&self) -> String { format!("{}:{}:{}", self.last_id, self.last_hash, self.mac) }
    pub fn from_line(s: &str) -> Option<Self> {
        let mut it = s.trim().split(':');
        let last_id = it.next()?.parse().ok()?;
        let last_hash = it.next()?.to_string();
        let mac = it.next()?.to_string();
        if it.next().is_some() { return None; }
        Some(Self { last_id, last_hash, mac })
    }
}

/// Verifica l'intera catena in streaming (una riga alla volta in memoria). Non parte dal
/// checkpoint: le righe precedenti potrebbero essere state alterate dopo, e ricalcolare
/// l'HMAC di decine di migliaia di righe richiede pochi millisecondi.
pub(super) fn verify_chain(conn: &Connection, key: &[u8; 32], cp: Option<&AuditCheckpoint>) -> Result<u64> {
    let bad = |row_id: Option<i64>, reason: String| Err(DbError::AuditTampered { row_id, reason });
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, actor, action, target_id, details, prev_hash, row_hash
         FROM audit_log ORDER BY id",
    )?;
    let mut rows = stmt.query([])?;

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut prev_id = 0i64;
    let mut hash_at_checkpoint: Option<String> = None;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let (ts, actor, action): (String, String, String) = (r.get(1)?, r.get(2)?, r.get(3)?);
        let (target, details): (Option<String>, Option<String>) = (r.get(4)?, r.get(5)?);
        let (prev_hash, row_hash): (String, String) = (r.get(6)?, r.get(7)?);
        if id != prev_id + 1 {
            return bad(Some(id), format!("numerazione interrotta prima della riga {id}"));
        }
        if prev_hash != expected_prev {
            return bad(Some(id), format!("catena spezzata alla riga {id}"));
        }
        let m = audit_mac(key, id, &ts, &actor, &action, target.as_deref(), details.as_deref(), &prev_hash);
        if m != row_hash {
            return bad(Some(id), format!("contenuto della riga {id} alterato"));
        }
        if cp.is_some_and(|c| c.last_id == id) {
            hash_at_checkpoint = Some(row_hash.clone());
        }
        expected_prev = row_hash;
        prev_id = id;
    }

    if let Some(cp) = cp {
        if checkpoint_mac(key, cp.last_id, &cp.last_hash) != cp.mac {
            return bad(None, "checkpoint non valido".into());
        }
        if cp.last_id > prev_id {
            return bad(
                Some(prev_id + 1),
                format!("log troncato: il checkpoint arriva alla riga {}, il log alla {prev_id}", cp.last_id),
            );
        }
        if cp.last_id > 0 && hash_at_checkpoint.as_deref() != Some(cp.last_hash.as_str()) {
            return bad(Some(cp.last_id), "il log non coincide con il checkpoint".into());
        }
    }
    Ok(prev_id as u64)
}

/// `target_id`: solo UUID (o comunque solo esadecimali e trattini).
fn check_target(t: &str) -> Result<()> {
    if t.is_empty() || t.len() > 64 || !t.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(DbError::InvalidInput("target_id dell'audit: ammessi solo identificativi"));
    }
    Ok(())
}

/// `details`: coppie `chiave=valore` separate da `;`, chiavi `[a-z_]`, valori fatti solo di
/// cifre, esadecimali e trattini (UUID, conteggi, date). Nessun nome, codice fiscale o
/// percorso può passare: il log deve restare privo di dati personali.
fn check_details(d: &str) -> Result<()> {
    let ok = d.len() <= 512
        && d.split(';').all(|kv| match kv.split_once('=') {
            Some((k, v)) => {
                !k.is_empty()
                    && k.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                    && !v.is_empty()
                    && v.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f' | '-'))
            }
            None => false,
        });
    if ok { Ok(()) } else { Err(DbError::InvalidInput("details dell'audit: ammessi solo ID e conteggi")) }
}

/// Riga dell'audit per l'export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    /// ISO 8601 UTC, come salvato (ed entra nell'HMAC).
    pub timestamp: String,
    /// Ora locale del computer, `YYYY-MM-DD HH:MM:SS`: solo per la lettura.
    pub timestamp_local: String,
    pub actor: String,
    pub action: String,
    pub target_id: Option<String>,
    pub details: Option<String>,
    pub prev_hash: String,
    pub row_hash: String,
}

impl Db {
    /// Da chiamare dentro una transazione.
    pub(super) fn audit_append(&self, c: &Connection, action: &str, target: Option<&str>, details: Option<&str>) -> Result<()> {
        let last: Option<String> = c
            .query_row("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .optional()?;
        // Il contatore AUTOINCREMENT sopravvive alle cancellazioni in coda: un
        // troncamento diventa un "buco" nella numerazione alla scrittura successiva.
        let seq: Option<i64> = c
            .query_row("SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'", [], |r| r.get(0))
            .optional()?;
        let id = seq.unwrap_or(0) + 1;
        let prev = last.unwrap_or_else(|| GENESIS_HASH.to_string());
        if let Some(t) = target {
            check_target(t)?;
        }
        if let Some(d) = details {
            check_details(d)?;
        }
        let ts = now(c)?;
        let h = audit_mac(&self.audit_key, id, &ts, &self.actor, action, target, details, &prev);
        c.execute(
            "INSERT INTO audit_log (id, timestamp, actor, action, target_id, details, prev_hash, row_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, ts, self.actor, action, target, details, prev, h],
        )?;
        Ok(())
    }

    /// Per azioni di sola lettura (VIEW_PATIENT, OPEN_FILE, EXPORT_ZIP...). `details`: solo ID/conteggi.
    pub fn log_audit(&self, action: &str, target_id: Option<&str>, details: Option<&str>) -> Result<()> {
        self.tx(|c| self.audit_append(c, action, target_id, details))
    }

    pub fn verify_audit_chain(&self, checkpoint: Option<&AuditCheckpoint>) -> Result<u64> {
        verify_chain(&self.conn, &self.audit_key, checkpoint)
    }

    pub fn audit_checkpoint(&self) -> Result<AuditCheckpoint> {
        let last: Option<(i64, String)> = self
            .conn
            .query_row("SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (last_id, last_hash) = last.unwrap_or((0, GENESIS_HASH.to_string()));
        let mac = checkpoint_mac(&self.audit_key, last_id, &last_hash);
        Ok(AuditCheckpoint { last_id, last_hash, mac })
    }

    /// Righe dell'audit in ordine, con data tra `from` e `to` inclusi (`YYYY-MM-DD`). Le date
    /// sono giorni LOCALI del computer: "27 novembre" comprende anche le righe salvate in UTC
    /// la sera del 26, e la sera del 27 fino a mezzanotte locale.
    /// Le righe si leggono una alla volta: `f` riceve ciascuna e può interrompere con un
    /// errore. Restituisce il numero di righe passate a `f`.
    pub fn for_each_audit_entry<E: From<DbError>>(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        mut f: impl FnMut(AuditEntry) -> std::result::Result<(), E>,
    ) -> std::result::Result<u64, E> {
        for d in [from, to].into_iter().flatten() {
            let ok: bool = self.conn.query_row("SELECT date(?1, '+0 days') IS NOT NULL AND date(?1, '+0 days') = ?1", params![d], |r| r.get(0)).map_err(DbError::from)?;
            if !ok {
                return Err(DbError::InvalidInput("data non valida (YYYY-MM-DD)").into());
            }
        }
        let mut st = self.conn.prepare(
            "SELECT id, timestamp, strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime'),
                    actor, action, target_id, details, prev_hash, row_hash
             FROM audit_log
             WHERE (?1 IS NULL OR date(timestamp, 'localtime') >= ?1)
               AND (?2 IS NULL OR date(timestamp, 'localtime') <= ?2)
             ORDER BY id",
        ).map_err(DbError::from)?;
        let mut rows = st.query(params![from, to]).map_err(DbError::from)?;
        let mut n = 0u64;
        while let Some(r) = rows.next().map_err(DbError::from)? {
            let e = (|| -> rusqlite::Result<AuditEntry> {
                Ok(AuditEntry {
                    id: r.get(0)?, timestamp: r.get(1)?, timestamp_local: r.get(2)?, actor: r.get(3)?, action: r.get(4)?,
                    target_id: r.get(5)?, details: r.get(6)?, prev_hash: r.get(7)?, row_hash: r.get(8)?,
                })
            })()
            .map_err(DbError::from)?;
            f(e)?;
            n += 1;
        }
        Ok(n)
    }

    /// Tutte le righe filtrate in un vettore (solo test).
    #[cfg(test)]
    pub fn audit_entries(&self, from: Option<&str>, to: Option<&str>) -> Result<Vec<AuditEntry>> {
        let mut out = Vec::new();
        self.for_each_audit_entry(from, to, |e| -> Result<()> {
            out.push(e);
            Ok(())
        })?;
        Ok(out)
    }
}
