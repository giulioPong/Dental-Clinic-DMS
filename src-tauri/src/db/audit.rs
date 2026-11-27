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

pub(super) type AuditRow = (i64, String, String, String, Option<String>, Option<String>, String, String);

pub(super) fn verify_chain(conn: &Connection, key: &[u8; 32], cp: Option<&AuditCheckpoint>) -> Result<u64> {
    let bad = |m: String| Err(DbError::AuditTampered(m));
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, actor, action, target_id, details, prev_hash, row_hash
         FROM audit_log ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        })?
        .collect::<rusqlite::Result<Vec<AuditRow>>>()?;

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut prev_id = 0i64;
    for (id, ts, actor, action, target, details, prev_hash, row_hash) in &rows {
        if *id != prev_id + 1 {
            return bad(format!("numerazione interrotta prima della riga {id}"));
        }
        if *prev_hash != expected_prev {
            return bad(format!("catena spezzata alla riga {id}"));
        }
        let m = audit_mac(key, *id, ts, actor, action, target.as_deref(), details.as_deref(), prev_hash);
        if m != *row_hash {
            return bad(format!("contenuto della riga {id} alterato"));
        }
        expected_prev = row_hash.clone();
        prev_id = *id;
    }

    if let Some(cp) = cp {
        if checkpoint_mac(key, cp.last_id, &cp.last_hash) != cp.mac {
            return bad("checkpoint non valido".into());
        }
        if cp.last_id > prev_id {
            return bad(format!("log troncato: il checkpoint arriva alla riga {}, il log alla {prev_id}", cp.last_id));
        }
        if cp.last_id > 0 {
            let h = &rows[(cp.last_id - 1) as usize].7;
            if *h != cp.last_hash {
                return bad("il log non coincide con il checkpoint".into());
            }
        }
    }
    Ok(rows.len() as u64)
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
}
