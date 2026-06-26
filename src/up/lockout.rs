use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct LockoutTracker {
    state: Mutex<LockoutState>,
    max_failures: u32,
    lockout_duration: Duration,
}

struct LockoutState {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

impl LockoutTracker {
    pub fn new(max_failures: u32, lockout_secs: u64) -> Self {
        Self {
            state: Mutex::new(LockoutState {
                consecutive_failures: 0,
                locked_until: None,
            }),
            max_failures,
            lockout_duration: Duration::from_secs(lockout_secs),
        }
    }

    /// Returns Some(remaining) if locked, None if ok to proceed.
    pub fn check_locked(&self) -> Option<Duration> {
        let state = self.state.lock().ok()?;
        if let Some(until) = state.locked_until {
            let now = Instant::now();
            if now < until {
                return Some(until - now);
            }
        }
        None
    }

    pub fn record_failure(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.consecutive_failures += 1;
            tracing::warn!(
                failures = state.consecutive_failures,
                max = self.max_failures,
                "UV failure recorded"
            );
            if state.consecutive_failures >= self.max_failures {
                state.locked_until = Some(Instant::now() + self.lockout_duration);
                tracing::error!(
                    lockout_secs = self.lockout_duration.as_secs(),
                    "UV lockout activated"
                );
            }
        }
    }

    pub fn record_success(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.consecutive_failures = 0;
            state.locked_until = None;
        }
    }
}
