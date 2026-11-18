//! Bounds on guessing secrets: an address that fails to sign in too often in a while is
//! refused until the while is over, whatever it sends.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Failed sign-ins an address may make in [`WINDOW`].
pub const MAX_FAILURES: u32 = 10;
/// How long failures count against an address.
pub const WINDOW: Duration = Duration::from_mins(10);
/// The most addresses remembered; past it, those whose window is over are forgotten.
const MAX_ADDRESSES: usize = 100_000;

/// Failed sign-ins by address, shared by a gateway's connections.
#[derive(Debug, Default)]
pub struct Attempts {
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Attempts {
    /// Whether `ip` may try to sign in now.
    pub fn allowed(&self, ip: IpAddr) -> bool {
        let failures = self.lock();
        failures
            .get(&ip)
            .is_none_or(|(count, since)| *count < MAX_FAILURES || since.elapsed() >= WINDOW)
    }

    /// Counts a failed sign-in from `ip`.
    pub fn failed(&self, ip: IpAddr) {
        let mut failures = self.lock();
        if failures.len() >= MAX_ADDRESSES {
            failures.retain(|_, (_, since)| since.elapsed() < WINDOW);
        }
        let entry = failures.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, (u32, Instant)>> {
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn an_address_is_refused_after_too_many_failures() {
        let attempts = Attempts::default();
        let (one, two): (IpAddr, IpAddr) =
            ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        for _ in 0..MAX_FAILURES {
            assert!(attempts.allowed(one));
            attempts.failed(one);
        }
        assert!(!attempts.allowed(one));
        assert!(attempts.allowed(two), "other addresses aren't affected");
    }
}
