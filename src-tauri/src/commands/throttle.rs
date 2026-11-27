//! Limite ai tentativi di sblocco con attesa crescente, persistente su disco.
//!
//! Lo stato (`tentativi falliti:fine del blocco in secondi Unix`) sta in `vault/unlock.throttle`,
//! così chiudere e riaprire l'app non azzera l'attesa. Non è un segreto né una difesa contro
//! chi attacca una COPIA del vault: lì contano solo la password e Argon2id.

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const THROTTLE_FILE: &str = "unlock.throttle";

pub(super) struct Throttle {
    failures: u32,
    blocked_until: Option<SystemTime>,
    path: PathBuf,
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Throttle {
    /// Stato salvato, oppure nessun blocco se il file manca o è illeggibile.
    pub(super) fn load(path: PathBuf) -> Self {
        let mut t = Throttle { failures: 0, blocked_until: None, path };
        if let Ok(s) = fs::read_to_string(&t.path) {
            if let Some((f, until)) = s.trim().split_once(':') {
                if let (Ok(f), Ok(until)) = (f.parse::<u32>(), until.parse::<u64>()) {
                    t.failures = f;
                    t.blocked_until = (until > 0).then(|| UNIX_EPOCH + Duration::from_secs(until));
                }
            }
        }
        t
    }

    pub(super) fn check(&self) -> Res<()> {
        if let Some(t) = self.blocked_until {
            if let Ok(left) = t.duration_since(SystemTime::now()) {
                // tetto all'attesa: un orologio spostato indietro non blocca per giorni
                let secs = left.as_secs().min(THROTTLE_MAX_SECS) + 1;
                return Err(CommandError::new(ErrorCode::TooManyAttempts, &format!("Troppi tentativi: riprova tra {secs} secondi."))
                    .with_detail(secs.to_string()));
            }
        }
        Ok(())
    }

    pub(super) fn fail(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= THROTTLE_FREE_ATTEMPTS {
            let exp = (self.failures - THROTTLE_FREE_ATTEMPTS).min(8);
            let secs = (THROTTLE_BASE_SECS << exp).min(THROTTLE_MAX_SECS);
            self.blocked_until = Some(SystemTime::now() + Duration::from_secs(secs));
        }
        self.save();
    }

    pub(super) fn reset(&mut self) {
        if self.failures == 0 && self.blocked_until.is_none() {
            return;
        }
        self.failures = 0;
        self.blocked_until = None;
        self.save();
    }

    /// Best effort: se il disco non è scrivibile il limite resta comunque in memoria.
    fn save(&self) {
        let line = format!("{}:{}", self.failures, self.blocked_until.map(unix).unwrap_or(0));
        if let Err(e) = write_replace_synced(&self.path, line.as_bytes()) {
            eprintln!("[dms] impossibile salvare lo stato dei tentativi di sblocco: {e}");
        }
    }
}
