//! Limite ai tentativi di sblocco con attesa crescente.

use super::*;

#[derive(Default)]
pub(super) struct Throttle {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl Throttle {
    pub(super) fn check(&self) -> Res<()> {
        if let Some(t) = self.blocked_until {
            let now = Instant::now();
            if t > now {
                let secs = (t - now).as_secs() + 1;
                return Err(CommandError::new(ErrorCode::TooManyAttempts, &format!("Troppi tentativi: riprova tra {secs} secondi."))
                    .with_detail(secs.to_string()));
            }
        }
        Ok(())
    }
    pub(super) fn fail(&mut self) {
        self.failures += 1;
        if self.failures >= THROTTLE_FREE_ATTEMPTS {
            let exp = (self.failures - THROTTLE_FREE_ATTEMPTS).min(8);
            let secs = (THROTTLE_BASE_SECS << exp).min(THROTTLE_MAX_SECS);
            self.blocked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }
    pub(super) fn reset(&mut self) {
        *self = Throttle::default();
    }
}
