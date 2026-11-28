//! Chiavi in RAM con blocco per inattività.

use super::*;

pub(super) struct Session {
    keys: Keys,
    last_activity: Instant,
}

/// Tiene le chiavi solo in RAM. Va messo nello stato di Tauri (`app.manage`).
/// Un thread di fondo deve chiamare `expire_if_idle()` ogni pochi secondi, così
/// le chiavi vengono azzerate anche se l'interfaccia non fa più richieste.
/// Quando l'archivio si blocca, chiudi anche la connessione SQLCipher.
pub struct KeyStore {
    inner: Mutex<Option<Session>>,
    idle_timeout: Duration,
}

impl KeyStore {
    pub fn new(idle_timeout: Duration) -> Self {
        Self { inner: Mutex::new(None), idle_timeout }
    }

    pub(super) fn guard(&self) -> MutexGuard<'_, Option<Session>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn unlock(&self, keys: Keys) {
        *self.guard() = Some(Session { keys, last_activity: Instant::now() });
    }

    /// Azzera subito le chiavi (Zeroize alla drop).
    pub fn lock(&self) {
        *self.guard() = None;
    }

    /// Copia delle chiavi per una singola operazione (la copia si azzera alla drop).
    /// Ogni chiamata conta come attività e rinvia il blocco.
    pub fn keys(&self) -> Result<Keys> {
        let mut g = self.guard();
        let expired = match g.as_ref() {
            Some(s) => s.last_activity.elapsed() >= self.idle_timeout,
            None => return Err(CryptoError::Locked),
        };
        if expired {
            *g = None;
            return Err(CryptoError::Locked);
        }
        let s = g.as_mut().expect("controllato sopra");
        s.last_activity = Instant::now();
        Ok(s.keys.clone())
    }

    /// Non conta come attività.
    pub fn is_unlocked(&self) -> bool {
        let mut g = self.guard();
        let expired = matches!(g.as_ref(), Some(s) if s.last_activity.elapsed() >= self.idle_timeout);
        if expired {
            *g = None;
        }
        g.is_some()
    }

    /// Da chiamare periodicamente. Restituisce true se ha appena bloccato la sessione.
    pub fn expire_if_idle(&self) -> bool {
        let mut g = self.guard();
        let expired = matches!(g.as_ref(), Some(s) if s.last_activity.elapsed() >= self.idle_timeout);
        if expired {
            *g = None;
        }
        expired
    }
}
