//! Sign-in sessions, kept in memory only (a restart signs everyone out), and the limit
//! on failed sign-ins.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use base64::Engine as _;
use zeroize::Zeroizing;

/// The longest a session lasts, however busy.
pub(crate) const LONGEST: Duration = Duration::from_hours(12);
/// How long a session lasts unused.
pub(crate) const IDLE: Duration = Duration::from_hours(1);
/// The most sessions open at once; a new one ends the least recently used.
pub(crate) const MAX_SESSIONS: usize = 1024;

/// Failed sign-ins one address may make within [`FAILURE_WINDOW`].
pub(crate) const MAX_FAILURES: u32 = 10;
pub(crate) const FAILURE_WINDOW: Duration = Duration::from_mins(10);
/// The most addresses whose failures are remembered.
const MAX_REMEMBERED: usize = 4096;

/// The key a session signs requests with: the one its person signed in with.
pub(crate) struct Key {
    pub(crate) id: String,
    pub(crate) secret: Zeroizing<String>,
    /// A session token, when the key is temporary credentials.
    pub(crate) token: Option<Zeroizing<String>>,
}

/// One signed-in person.
pub(crate) struct Session {
    pub(crate) key: Key,
    /// Whom the key is (STS `GetCallerIdentity`).
    pub(crate) arn: String,
    pub(crate) account: String,
    started: Instant,
}

impl Session {
    pub(crate) fn new(key: Key, arn: String, account: String) -> Self {
        Self {
            key,
            arn,
            account,
            started: Instant::now(),
        }
    }

    /// How long until it ends at the latest.
    pub(crate) fn left(&self) -> Duration {
        LONGEST.saturating_sub(self.started.elapsed())
    }
}

struct Entry {
    session: Arc<Session>,
    used: Instant,
}

/// The open sessions, by their token's SHA-256 (the token itself is only in the cookie).
pub(crate) struct Sessions {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

impl Default for Sessions {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

fn digest(token: &str) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// A new session's token: 256 random bits, base64url.
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("the operating system provides randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn open(entry: &Entry, now: Instant) -> bool {
    now.saturating_duration_since(entry.session.started) < LONGEST
        && now.saturating_duration_since(entry.used) < IDLE
}

impl Sessions {
    /// Opens a session: the token its cookie carries.
    pub(crate) fn start(&self, session: Session) -> String {
        self.start_at(session, Instant::now())
    }

    fn start_at(&self, session: Session, now: Instant) -> String {
        let token = new_token();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, entry| open(entry, now));
        if entries.len() >= MAX_SESSIONS
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(id, _)| *id)
        {
            entries.remove(&oldest);
        }
        entries.insert(
            digest(&token),
            Entry {
                session: Arc::new(session),
                used: now,
            },
        );
        token
    }

    /// The open session `token` names, now used.
    pub(crate) fn find(&self, token: &str) -> Option<Arc<Session>> {
        self.find_at(token, Instant::now())
    }

    fn find_at(&self, token: &str, now: Instant) -> Option<Arc<Session>> {
        let id = digest(token);
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get_mut(&id)?;
        if !open(entry, now) {
            entries.remove(&id);
            return None;
        }
        entry.used = now;
        Some(Arc::clone(&entry.session))
    }

    /// Ends the session `token` names, if it's open.
    pub(crate) fn end(&self, token: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&digest(token));
    }
}

/// Failed sign-ins by address, so a key can't be guessed at speed.
#[derive(Default)]
pub(crate) struct Attempts {
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Attempts {
    /// Whether `ip` may try to sign in now; `Err` is how long it must wait.
    pub(crate) fn allowed(&self, ip: IpAddr) -> Result<(), Duration> {
        self.allowed_at(ip, Instant::now())
    }

    fn allowed_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        match failures.get(&ip.to_canonical()) {
            Some(&(count, since)) if count >= MAX_FAILURES => {
                let waited = now.saturating_duration_since(since);
                if waited < FAILURE_WINDOW {
                    Err(FAILURE_WINDOW.saturating_sub(waited))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn failed(&self, ip: IpAddr) {
        self.failed_at(ip, Instant::now());
    }

    fn failed_at(&self, ip: IpAddr, now: Instant) {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if failures.len() >= MAX_REMEMBERED {
            failures.retain(|_, (_, since)| now.saturating_duration_since(*since) < FAILURE_WINDOW);
        }
        let entry = failures.entry(ip.to_canonical()).or_insert((0, now));
        if now.saturating_duration_since(entry.1) >= FAILURE_WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
    }

    pub(crate) fn succeeded(&self, ip: IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ip.to_canonical());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::new(
            Key {
                id: "AKIAEXAMPLE".into(),
                secret: Zeroizing::new("not-a-real-secret".into()),
                token: None,
            },
            "arn:aws:iam::123456789012:user/ana".into(),
            "123456789012".into(),
        )
    }

    #[test]
    fn tokens_are_long_random_and_url_safe() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn a_session_is_found_by_its_token_only_until_it_ends() {
        let sessions = Sessions::default();
        let token = sessions.start(session());
        assert!(sessions.find(&token).is_some());
        assert!(sessions.find("not-the-token").is_none());
        sessions.end(&token);
        assert!(sessions.find(&token).is_none());
    }

    #[test]
    fn sessions_end_when_idle_and_when_old() {
        let sessions = Sessions::default();
        let now = Instant::now();
        let token = sessions.start_at(session(), now);
        // Used within the idle time, it lasts…
        let almost = IDLE.saturating_sub(Duration::from_secs(1));
        let later = now + almost;
        assert!(sessions.find_at(&token, later).is_some());
        // …and the idle time starts again from that use.
        assert!(sessions.find_at(&token, later + almost).is_some());
        // Unused for the idle time, it's gone.
        let token = sessions.start_at(session(), now);
        assert!(sessions.find_at(&token, now + IDLE).is_none());
        assert!(
            sessions.find_at(&token, now).is_none(),
            "an ended session stays ended"
        );
    }

    #[test]
    fn sessions_end_at_the_longest_however_busy() {
        let sessions = Sessions::default();
        let start = Instant::now();
        let token = sessions.start_at(session(), Instant::now());
        let mut now = start;
        while now < start + LONGEST.saturating_sub(IDLE) {
            now += IDLE / 2;
            assert!(sessions.find_at(&token, now).is_some());
        }
        assert!(
            sessions
                .find_at(&token, start + LONGEST + Duration::from_secs(1))
                .is_none()
        );
    }

    #[test]
    fn the_least_recently_used_session_makes_room() {
        let sessions = Sessions::default();
        let now = Instant::now();
        let first = sessions.start_at(session(), now);
        let mut last = String::new();
        for i in 1..MAX_SESSIONS {
            last = sessions.start_at(session(), now + Duration::from_millis(i as u64));
        }
        // Full: the next one ends the first.
        let newest = sessions.start_at(session(), now + Duration::from_secs(5));
        let at = now + Duration::from_secs(6);
        assert!(sessions.find_at(&first, at).is_none());
        assert!(sessions.find_at(&last, at).is_some());
        assert!(sessions.find_at(&newest, at).is_some());
    }

    #[test]
    fn failed_sign_ins_are_limited_per_address_for_a_while() {
        let attempts = Attempts::default();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES {
            assert!(attempts.allowed_at(ip, now).is_ok());
            attempts.failed_at(ip, now);
        }
        let wait = attempts.allowed_at(ip, now).unwrap_err();
        assert_eq!(wait, FAILURE_WINDOW);
        assert!(
            attempts.allowed_at(other, now).is_ok(),
            "only that address waits"
        );
        assert!(attempts.allowed_at(ip, now + FAILURE_WINDOW).is_ok());
        // An IPv4-mapped IPv6 address is the same client.
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert!(attempts.allowed_at(mapped, now).is_err());
        attempts.succeeded(ip);
        assert!(attempts.allowed_at(ip, now).is_ok());
    }
}
