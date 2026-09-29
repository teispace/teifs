//! OpenID Connect providers' signing keys, fetched as OpenID Connect Discovery says (the
//! provider's `/.well-known/openid-configuration` names its `jwks_uri`) and kept in
//! memory.
//!
//! A provider's keys are kept as long as its answer's `Cache-Control: max-age` says,
//! within five minutes and a day (an hour when it doesn't say). A token signed with a
//! key that isn't known yet fetches them again, since providers rotate keys, but no
//! provider is asked more than once in [`RETRY`]: a flood of made-up key ids can't
//! make TeiFS flood the provider. When a provider can't be reached, the keys it last
//! gave are used for up to a day. Only one fetch per provider runs at a time; requests
//! that arrive meanwhile wait for its answer. The provider's certificate is trusted as
//! [`super::tls`] says: by the system, or by one of the provider's thumbprints.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use reqwest::{Client, Url, header};
use teifs_policy::Json;

use super::{jwt, same_issuer};
use crate::rules;

/// The shortest and longest time keys are kept before they're fetched again, and how
/// long when the provider doesn't say.
const SHORTEST: Duration = Duration::from_mins(5);
const LONGEST: Duration = Duration::from_hours(24);
const DEFAULT: Duration = Duration::from_hours(1);
/// How long keys are still used when the provider can't be reached to refresh them.
const STALE: Duration = Duration::from_hours(24);
/// The least time between two fetches from one provider.
pub(crate) const RETRY: Duration = Duration::from_secs(30);
/// How long a fetch may take, and the largest document it reads.
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DOCUMENT: usize = 256 * 1024;

/// What's known of one provider's keys.
#[derive(Debug)]
struct Entry {
    /// Its keys, and when they were fetched.
    keys: Option<(Arc<[jwt::Jwk]>, Instant)>,
    /// Until when they're used without asking again.
    fresh_until: Instant,
    /// When they were last asked for, successfully or not.
    attempted: Instant,
    /// Why the last fetch failed, if it did.
    error: Option<String>,
}

impl Entry {
    fn has(&self, kid: &str) -> bool {
        self.keys
            .as_ref()
            .is_some_and(|(keys, _)| keys.iter().any(|k| k.kid() == Some(kid)))
    }
}

/// Every provider's keys, by the provider's URL.
#[derive(Debug, Default)]
pub(crate) struct KeyCache {
    /// An HTTP client for each set of thumbprints providers have.
    clients: Mutex<HashMap<Vec<String>, Client>>,
    entries: Mutex<HashMap<String, Entry>>,
    /// One lock per provider, held while its keys are fetched.
    fetches: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl KeyCache {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the keys of the provider at `url` should be fetched for a token signed
    /// with the key `kid`: they're missing, out of date, or don't have that key, and
    /// the provider wasn't asked in the last [`RETRY`].
    fn wants(&self, url: &str, kid: Option<&str>, now: Instant) -> bool {
        self.entries().get(url).is_none_or(|entry| {
            let stale = entry.keys.is_none() || now >= entry.fresh_until;
            let unknown = kid.is_some_and(|kid| !entry.has(kid));
            (stale || unknown) && now.saturating_duration_since(entry.attempted) >= RETRY
        })
    }

    /// Makes sure the keys of the provider at `url` (with the certificate `thumbprints`)
    /// are known, and have the key `kid` if the provider does, fetching them if they
    /// need to be. A failure is kept, for [`Self::keys`] to report.
    pub(crate) async fn refresh(&self, url: &str, thumbprints: &[String], kid: Option<&str>) {
        if !self.wants(url, kid, Instant::now()) {
            return;
        }
        let gate = Arc::clone(
            self.fetches
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(url.to_owned())
                .or_default(),
        );
        let _fetching = gate.lock().await;
        // Another request may have fetched them while this one waited.
        if !self.wants(url, kid, Instant::now()) {
            return;
        }
        let fetched = match self.client(thumbprints) {
            Ok(client) => fetch(&client, url).await,
            Err(err) => Err(err),
        };
        if let Err(err) = &fetched {
            tracing::warn!(provider = url, error = %err, "an OpenID Connect provider's keys couldn't be fetched");
        }
        self.record(url, fetched, Instant::now());
    }

    /// The client for providers with these `thumbprints` (a client is cheap to clone).
    fn client(&self, thumbprints: &[String]) -> Result<Client, String> {
        let mut key = thumbprints.to_vec();
        key.sort_unstable();
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        let client = Client::builder()
            .tls_backend_preconfigured(super::tls::config(&key)?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(TIMEOUT)
            .timeout(TIMEOUT)
            .user_agent(concat!("teifs/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("no HTTP client: {e}"))?;
        clients.insert(key, client.clone());
        Ok(client)
    }

    /// Keeps what a fetch from the provider at `url` gave: its keys and how long to keep
    /// them, or why it failed (the keys it gave before are kept).
    fn record(&self, url: &str, fetched: Result<(Vec<jwt::Jwk>, Duration), String>, now: Instant) {
        let mut entries = self.entries();
        let entry = entries.entry(url.to_owned()).or_insert(Entry {
            keys: None,
            fresh_until: now,
            attempted: now,
            error: None,
        });
        entry.attempted = now;
        match fetched {
            Ok((keys, lifetime)) => {
                entry.keys = Some((keys.into(), now));
                entry.fresh_until = now + lifetime;
                entry.error = None;
            }
            Err(err) => entry.error = Some(err),
        }
    }

    /// The keys of the provider at `url`, as last fetched (within a day); or why there
    /// are none.
    pub(crate) fn keys(&self, url: &str) -> Result<Arc<[jwt::Jwk]>, String> {
        self.keys_at(url, Instant::now())
    }

    fn keys_at(&self, url: &str, now: Instant) -> Result<Arc<[jwt::Jwk]>, String> {
        let entries = self.entries();
        let Some(entry) = entries.get(url) else {
            return Err("its keys haven't been fetched".into());
        };
        match &entry.keys {
            Some((keys, fetched)) if now.saturating_duration_since(*fetched) < STALE => {
                Ok(Arc::clone(keys))
            }
            _ => Err(entry
                .error
                .clone()
                .unwrap_or_else(|| "its keys are out of date".into())),
        }
    }

    /// Makes `keys` the provider's at `url`, as if just fetched.
    #[cfg(test)]
    pub(crate) fn insert(&self, url: &str, keys: Vec<jwt::Jwk>) {
        self.record(url, Ok((keys, DEFAULT)), Instant::now());
    }
}

/// The keys of the provider at `url`, and how long to keep them.
async fn fetch(client: &Client, url: &str) -> Result<(Vec<jwt::Jwk>, Duration), String> {
    let discovery = format!(
        "{}/.well-known/openid-configuration",
        url.trim_end_matches('/')
    );
    let (text, _) = get(client, &discovery).await?;
    let config = Json::parse(&text).map_err(|e| format!("its discovery document is {e}"))?;
    match config.get("issuer").and_then(Json::as_str) {
        Some(issuer) if same_issuer(issuer, url) => {}
        Some(issuer) => {
            return Err(format!(
                "its discovery document is for another issuer, {issuer}"
            ));
        }
        None => return Err("its discovery document names no issuer".into()),
    }
    let Some(jwks_uri) = config.get("jwks_uri").and_then(Json::as_str) else {
        return Err("its discovery document names no jwks_uri".into());
    };
    key_set_url(jwks_uri)?;
    let (text, max_age) = get(client, jwks_uri).await?;
    let keys = jwt::key_set(&text)?;
    if keys.is_empty() {
        return Err(format!(
            "its key set at {jwks_uri} has no key for RS, PS or ES signatures"
        ));
    }
    Ok((keys, lifetime(max_age)))
}

/// Checks the key set's URL: `https`, or `http` to this computer, with no user name.
fn key_set_url(text: &str) -> Result<(), String> {
    let url = Url::parse(text).map_err(|e| format!("its jwks_uri {text} isn't a URL: {e}"))?;
    let secure = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return Err(format!("its jwks_uri {text} isn't an https URL")),
    };
    let Some(host) = url.host_str() else {
        return Err(format!("its jwks_uri {text} has no host"));
    };
    if !secure && !rules::is_loopback(host) {
        return Err(format!("its jwks_uri {text} isn't an https URL"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("its jwks_uri {text} has a user name"));
    }
    Ok(())
}

/// How long to keep keys the provider says to keep for `max_age` seconds.
fn lifetime(max_age: Option<u64>) -> Duration {
    max_age.map_or(DEFAULT, |seconds| {
        Duration::from_secs(seconds).clamp(SHORTEST, LONGEST)
    })
}

/// `max-age` of a `Cache-Control` header; `no-cache` and `no-store` are none at all.
fn max_age(value: &str) -> Option<u64> {
    let mut max_age = None;
    for directive in value.split(',').map(str::trim) {
        let (name, argument) = directive.split_once('=').unwrap_or((directive, ""));
        if name.eq_ignore_ascii_case("no-cache") || name.eq_ignore_ascii_case("no-store") {
            return Some(0);
        }
        if name.eq_ignore_ascii_case("max-age") {
            max_age = argument.trim_matches('"').parse().ok();
        }
    }
    max_age
}

/// A JSON document at `url`, and its `Cache-Control` `max-age`.
async fn get(client: &Client, url: &str) -> Result<(String, Option<u64>), String> {
    let failed = |e: reqwest::Error| {
        // reqwest's own message is terse ("error sending request"); its causes say why.
        let e = e.without_url();
        let mut why = e.to_string();
        let mut cause = std::error::Error::source(&e);
        while let Some(err) = cause {
            why = format!("{why}: {err}");
            cause = err.source();
        }
        format!("{url} couldn't be read: {why}")
    };
    let mut response = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(failed)?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let too_large = || format!("{url} is larger than {} KiB", MAX_DOCUMENT / 1024);
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DOCUMENT as u64)
    {
        return Err(too_large());
    }
    let max_age = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(max_age);
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(failed)? {
        if body.len() + chunk.len() > MAX_DOCUMENT {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(body).map_err(|_| format!("{url} isn't UTF-8 text"))?;
    Ok((text, max_age))
}

#[cfg(test)]
pub(crate) mod tests {
    //! A provider served from this computer, as a test's identity provider.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::oidc::jwt::tests::Signer;

    /// What the provider answers a request for a path with: status, headers, body.
    pub(crate) type Route = Arc<dyn Fn(&str) -> (u16, String, String) + Send + Sync>;

    /// An identity provider on a loopback port; its URL, and how many requests it had.
    pub(crate) struct Provider {
        pub(crate) url: String,
        pub(crate) requests: Arc<AtomicUsize>,
    }

    /// Headers a route gives for an answer with no `content-length`.
    pub(crate) const UNSIZED: &str = "unsized";

    /// Serves `route` on a loopback port.
    pub(crate) async fn serve(route: Route) -> Provider {
        serve_with(route, None).await
    }

    /// Serves `route` on a loopback port, over TLS with `tls` if given (its URL is then
    /// `https://localhost:…`).
    pub(crate) async fn serve_with(
        route: Route,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Provider {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = if tls.is_some() {
            format!("https://localhost:{port}")
        } else {
            format!("http://127.0.0.1:{port}")
        };
        let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
        let requests = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let route = Arc::clone(&route);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(socket) = acceptor.accept(socket).await {
                                answer(socket, &route).await;
                            }
                        }
                        None => answer(socket, &route).await,
                    }
                });
            }
        });
        Provider { url, requests }
    }

    /// Reads one request from `socket` and answers it as `route` says.
    async fn answer(mut socket: impl AsyncRead + AsyncWrite + Unpin, route: &Route) {
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(n) => request.extend_from_slice(&buffer[..n]),
            }
        }
        let request = String::from_utf8_lossy(&request);
        let path = request.split(' ').nth(1).unwrap_or("/").to_owned();
        let (status, headers, body) = route(&path);
        // `unsized` headers: no length, the body ends when the connection closes.
        let length = if headers == UNSIZED {
            String::new()
        } else {
            format!("content-length: {}\r\n", body.len())
        };
        let headers = if headers == UNSIZED { "" } else { &headers };
        let response =
            format!("HTTP/1.1 {status} X\r\n{length}connection: close\r\n{headers}\r\n{body}");
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    }

    /// A provider that publishes `keys` (JWKs) as OpenID Connect Discovery says, its
    /// key set with `headers`; its URL is `{url}/idp`.
    pub(crate) async fn publishing(keys: Vec<String>, headers: &str) -> Provider {
        publishing_with(keys, headers, None).await
    }

    /// [`publishing`], over TLS with `tls` if given.
    pub(crate) async fn publishing_with(
        keys: Vec<String>,
        headers: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Provider {
        let keys = format!(r#"{{"keys":[{}]}}"#, keys.join(","));
        let headers = headers.to_owned();
        let base = Arc::new(Mutex::new(String::new()));
        let own = Arc::clone(&base);
        let provider = serve_with(
            Arc::new(move |path: &str| {
                let base = own.lock().unwrap().clone();
                match path {
                    "/idp/.well-known/openid-configuration" => (
                        200,
                        String::new(),
                        format!(r#"{{"issuer":"{base}/idp","jwks_uri":"{base}/keys"}}"#),
                    ),
                    "/keys" => (200, headers.clone(), keys.clone()),
                    _ => (404, String::new(), String::new()),
                }
            }),
            tls,
        )
        .await;
        base.lock().unwrap().clone_from(&provider.url);
        provider
    }

    #[tokio::test]
    async fn keys_are_fetched_as_discovery_says_and_kept() {
        let signer = Signer::rsa();
        let provider =
            publishing(vec![signer.jwk("k1", "")], "cache-control: max-age=600\r\n").await;
        let url = format!("{}/idp", provider.url);
        let cache = KeyCache::default();
        assert_eq!(
            cache.keys(&url).unwrap_err(),
            "its keys haven't been fetched"
        );
        cache.refresh(&url, &[], Some("k1")).await;
        assert_eq!(cache.keys(&url).unwrap().len(), 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
        // Kept: neither a known key nor an unknown one asks again straight away.
        cache.refresh(&url, &[], Some("k1")).await;
        cache.refresh(&url, &[], Some("k2")).await;
        cache.refresh(&url, &[], None).await;
        assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
        let entries = cache.entries();
        let entry = &entries[&url];
        assert_eq!(
            entry.fresh_until - entry.attempted,
            Duration::from_secs(600)
        );
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_fetch() {
        let signer = Signer::rsa();
        let provider = publishing(vec![signer.jwk("k1", "")], "").await;
        let url = format!("{}/idp", provider.url);
        let cache = Arc::new(KeyCache::default());
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (cache, url) = (Arc::clone(&cache), url.clone());
                tokio::spawn(async move { cache.refresh(&url, &[], Some("k1")).await })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
        assert!(cache.keys(&url).is_ok());
    }

    #[tokio::test]
    async fn providers_that_answer_badly_are_reported() {
        let cases: [(&str, &str, &str); 7] = [
            ("{}", "", "names no issuer"),
            (r#"{"issuer":"https://elsewhere"}"#, "", "another issuer"),
            (r#"{"issuer":"ISSUER"}"#, "", "names no jwks_uri"),
            (
                r#"{"issuer":"ISSUER","jwks_uri":"http://example.com/k"}"#,
                "",
                "isn't an https URL",
            ),
            (
                r#"{"issuer":"ISSUER","jwks_uri":"https://u:p@example.com/k"}"#,
                "",
                "has a user name",
            ),
            (
                r#"{"issuer":"ISSUER","jwks_uri":"BASE/keys"}"#,
                r#"{"keys":[]}"#,
                "has no key",
            ),
            (
                r#"{"issuer":"ISSUER","jwks_uri":"BASE/keys"}"#,
                "[]",
                "no `keys` list",
            ),
        ];
        for (config, keys, expected) in cases {
            let base = Arc::new(Mutex::new(String::new()));
            let own = Arc::clone(&base);
            let (served, keys) = (config.to_owned(), keys.to_owned());
            let provider = serve(Arc::new(move |path: &str| {
                let base = own.lock().unwrap().clone();
                match path {
                    "/.well-known/openid-configuration" => (
                        200,
                        String::new(),
                        served.replace("ISSUER", &base).replace("BASE", &base),
                    ),
                    "/keys" => (200, String::new(), keys.clone()),
                    _ => (404, String::new(), String::new()),
                }
            }))
            .await;
            base.lock().unwrap().clone_from(&provider.url);
            let cache = KeyCache::default();
            cache.refresh(&provider.url, &[], None).await;
            let err = cache.keys(&provider.url).unwrap_err();
            assert!(err.contains(expected), "{config}: {err}");
        }

        // Not found, too large, and nothing listening.
        let big = "x".repeat(MAX_DOCUMENT + 1);
        let provider = serve(Arc::new(move |path: &str| match path {
            "/big/.well-known/openid-configuration" => (200, String::new(), big.clone()),
            "/stream/.well-known/openid-configuration" => (200, UNSIZED.to_owned(), big.clone()),
            _ => (404, String::new(), String::new()),
        }))
        .await;
        let cache = KeyCache::default();
        for (path, expected) in [
            ("/none", "answered 404"),
            ("/big", "larger than 256 KiB"),
            ("/stream", "larger than 256 KiB"),
        ] {
            let url = format!("{}{path}", provider.url);
            cache.refresh(&url, &[], None).await;
            let err = cache.keys(&url).unwrap_err();
            assert!(err.contains(expected), "{path}: {err}");
        }
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        cache.refresh(&url, &[], None).await;
        assert!(cache.keys(&url).unwrap_err().contains("couldn't be read"));
    }

    #[test]
    fn keys_are_refetched_when_out_of_date_or_unknown_and_kept_through_failures() {
        let signer = Signer::rsa();
        let keys = || jwt::key_set(&format!(r#"{{"keys":[{}]}}"#, signer.jwk("k1", ""))).unwrap();
        let cache = KeyCache::default();
        let url = "https://idp.example.com";
        let t0 = Instant::now();
        assert!(cache.wants(url, None, t0));
        cache.record(url, Ok((keys(), SHORTEST)), t0);
        assert!(!cache.wants(url, Some("k1"), t0 + RETRY));
        // An unknown key asks again, but not within RETRY of the last fetch.
        assert!(!cache.wants(
            url,
            Some("k2"),
            t0 + Duration::from_secs(RETRY.as_secs() - 1)
        ));
        assert!(cache.wants(url, Some("k2"), t0 + RETRY));
        // Out of date: fetched again.
        assert!(cache.wants(url, Some("k1"), t0 + SHORTEST));
        // A failure keeps the keys, which are used for a day after they were fetched.
        let t1 = t0 + SHORTEST;
        cache.record(url, Err("down".into()), t1);
        assert!(!cache.wants(url, None, t1 + Duration::from_secs(1)));
        assert!(cache.wants(url, None, t1 + RETRY));
        assert!(
            cache
                .keys_at(url, t0 + Duration::from_secs(STALE.as_secs() - 1))
                .is_ok()
        );
        assert_eq!(cache.keys_at(url, t0 + STALE).unwrap_err(), "down");
        // Recovered.
        cache.record(url, Ok((keys(), DEFAULT)), t1 + RETRY);
        assert!(cache.entries()[url].error.is_none());
    }

    #[test]
    fn cache_control_sets_how_long_keys_are_kept() {
        assert_eq!(max_age("public, max-age=3600"), Some(3600));
        assert_eq!(max_age("Max-Age=\"60\", must-revalidate"), Some(60));
        assert_eq!(max_age("no-store"), Some(0));
        assert_eq!(max_age("max-age=100, no-cache"), Some(0));
        assert_eq!(max_age("public"), None);
        assert_eq!(max_age("max-age=soon"), None);
        assert_eq!(lifetime(None), DEFAULT);
        assert_eq!(lifetime(Some(0)), SHORTEST);
        assert_eq!(lifetime(Some(7200)), Duration::from_secs(7200));
        assert_eq!(lifetime(Some(u64::MAX)), LONGEST);
    }
}
