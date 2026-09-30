//! Webhooks: a URL things are `POST`ed to, with an optional token, shared by the audit
//! log and bucket notifications.

use std::{fmt, time::Duration};

use zeroize::Zeroizing;

/// How long a webhook has to answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A webhook: `POST`s to its URL.
#[derive(Clone)]
pub struct Webhook {
    /// Its URL: `http` or `https`.
    pub url: reqwest::Url,
    /// Its `Authorization`: as given if it names a scheme (`Basic …`), else sent as
    /// `Bearer TOKEN`.
    pub token: Option<Zeroizing<String>>,
}

impl Webhook {
    /// A webhook at `url`, which must be `http` or `https` with a host.
    ///
    /// # Errors
    ///
    /// When `url` isn't such a URL.
    pub fn new(url: &str, token: Option<Zeroizing<String>>) -> Result<Self, String> {
        let url = reqwest::Url::parse(url.trim()).map_err(|e| format!("not a URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err("give an http or https URL".to_owned());
        }
        Ok(Self { url, token })
    }

    /// Its URL without what could be a secret in it: a user and password, or a query.
    #[must_use]
    pub fn shown(&self) -> String {
        let mut url = self.url.clone();
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        url.to_string()
    }

    /// `POST`s `body`; anything but a `2xx` is a failure, said without the URL.
    ///
    /// # Errors
    ///
    /// Why it wasn't taken.
    pub async fn post(
        &self,
        client: &reqwest::Client,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> Result<(), String> {
        let mut request = client
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        if let Some(token) = &self.token {
            let value = if token.contains(' ') {
                Zeroizing::new(token.to_string())
            } else {
                Zeroizing::new(format!("Bearer {}", token.as_str()))
            };
            let mut value = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|_| "the token isn't a valid header value".to_owned())?;
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let response = request.send().await.map_err(described)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("it answered {status}"))
        }
    }
}

/// What went wrong, with its causes (`error sending request: … connection refused`),
/// without the URL.
fn described(err: reqwest::Error) -> String {
    let err = err.without_url();
    let mut text = err.to_string();
    let mut cause = std::error::Error::source(&err);
    while let Some(err) = cause {
        text.push_str(": ");
        text.push_str(&err.to_string());
        cause = err.source();
    }
    text
}

impl fmt::Debug for Webhook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Webhook")
            .field("url", &self.shown())
            .finish_non_exhaustive()
    }
}

/// The client webhooks are sent with: a timeout, and no redirects (a redirect could
/// take the token elsewhere).
///
/// # Errors
///
/// When TLS can't be set up.
pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// The pauses between tries of something that failed: half a second, doubling to 30.
#[derive(Debug, Clone)]
pub struct Backoff {
    pause: Duration,
}

impl Backoff {
    const FIRST: Duration = Duration::from_millis(500);
    const MAX: Duration = Duration::from_secs(30);

    /// Starts at the first pause.
    #[must_use]
    pub const fn new() -> Self {
        Self { pause: Self::FIRST }
    }

    /// The next pause.
    pub fn next_pause(&mut self) -> Duration {
        let pause = self.pause;
        self.pause = (pause * 2).min(Self::MAX);
        pause
    }

    /// Starts again from the first pause, after a success.
    pub const fn reset(&mut self) {
        self.pause = Self::FIRST;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_webhook_is_shown_without_its_secrets() {
        let hook = Webhook::new(
            "https://user:pass@hooks.example.com/in?token=abc#frag",
            Some(Zeroizing::new("secret".into())),
        )
        .unwrap();
        assert_eq!(hook.shown(), "https://hooks.example.com/in");
        let debug = format!("{hook:?}");
        assert!(!debug.contains("pass") && !debug.contains("abc") && !debug.contains("secret"));
        for bad in ["ftp://example.com/", "not a url", "http://"] {
            assert!(Webhook::new(bad, None).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_failure_says_why_without_the_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/in?key=secret", listener.local_addr().unwrap());
        drop(listener);
        let hook = Webhook::new(&url, None).unwrap();
        let err = hook
            .post(&client().unwrap(), "application/json", Vec::new())
            .await
            .unwrap_err();
        assert!(err.to_lowercase().contains("connect"), "{err}");
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn pauses_double_to_half_a_minute() {
        let mut backoff = Backoff::new();
        let pauses: Vec<Duration> = (0..8).map(|_| backoff.next_pause()).collect();
        let ms = |ms: &[u64]| {
            ms.iter()
                .map(|&m| Duration::from_millis(m))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            pauses,
            ms(&[500, 1000, 2000, 4000, 8000, 16_000, 30_000, 30_000])
        );
        backoff.reset();
        assert_eq!(backoff.next_pause(), Duration::from_millis(500));
    }
}
