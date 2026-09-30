//! Elasticsearch (and `OpenSearch`) targets, as `MinIO`'s: each event is a document,
//! `{"Records":[record]}`, in an index the target creates when it's missing. In the
//! `namespace` format there's a document per object (its id a hash of `BUCKET/KEY`),
//! replaced by each event and removed with the object; in the `access` format, a
//! document per event.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::Engine as _;
use reqwest::{Method, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use teifs_types::notify::EventMessage;
use zeroize::Zeroizing;

use crate::{Format, webhook::described};

/// The events that remove an object's document in the `namespace` format.
const REMOVALS: &[&str] = &["s3:ObjectRemoved:Delete", "s3:LifecycleExpiration:Delete"];

/// An index events are written to.
#[derive(Clone)]
pub struct Elasticsearch {
    /// The cluster's URL: `http` or `https`, perhaps with a path before the API's.
    pub url: Url,
    /// The index.
    pub index: String,
    /// A document per object or per event.
    pub format: Format,
    /// Basic authentication's user; its password is [`Self::password`].
    pub username: Option<String>,
    /// Basic authentication's password.
    pub password: Option<Zeroizing<String>>,
    /// An API key, sent as `Authorization: ApiKey KEY` (instead of a user).
    pub api_key: Option<Zeroizing<String>>,
    /// Whether the index is known to exist.
    ready: Arc<AtomicBool>,
}

impl Elasticsearch {
    /// Events for `index` at `url`, which must be `http` or `https` with a host and no
    /// query.
    ///
    /// # Errors
    ///
    /// When `url` isn't such a URL, or `index` can't name an index.
    pub fn new(url: &str, index: &str, format: Format) -> Result<Self, String> {
        let url = Url::parse(url.trim()).map_err(|e| format!("not a URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.cannot_be_a_base()
        {
            return Err("give the cluster's http or https URL".to_owned());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "give the user with user=NAME, and the password in the environment".to_owned(),
            );
        }
        check_index(index)?;
        Ok(Self {
            url,
            index: index.to_owned(),
            format,
            username: None,
            password: None,
            api_key: None,
            ready: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Its URL and index.
    #[must_use]
    pub fn shown(&self) -> String {
        let mut url = self.url.clone();
        url.set_fragment(None);
        format!("{url} index {} ({})", self.index, self.format.name())
    }

    /// Writes the event `body` (an [`EventMessage`]) as its format says.
    pub(crate) async fn send(&self, client: &reqwest::Client, body: &[u8]) -> Result<(), String> {
        let message: EventMessage =
            serde_json::from_slice(body).map_err(|e| format!("not an event: {e}"))?;
        self.ensure_index(client).await?;
        let document = serde_json::json!({ "Records": message.records });
        let (method, path, ok_if_missing) = match self.format {
            Format::Namespace if REMOVALS.contains(&message.event_name.as_str()) => (
                Method::DELETE,
                vec!["_doc".to_owned(), document_id(&message.key)],
                true,
            ),
            Format::Namespace => (
                Method::PUT,
                vec!["_doc".to_owned(), document_id(&message.key)],
                false,
            ),
            Format::Access => (Method::POST, vec!["_doc".to_owned()], false),
        };
        let mut request = self.request(client, method.clone(), &path);
        if method != Method::DELETE {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(document.to_string());
        }
        let status = request.send().await.map_err(described)?.status();
        if status.is_success() || (ok_if_missing && status == StatusCode::NOT_FOUND) {
            Ok(())
        } else {
            Err(format!("it answered {status}"))
        }
    }

    /// Checks that the cluster answers and the index exists, creating it if it doesn't.
    pub(crate) async fn test(&self, client: &reqwest::Client) -> Result<(), String> {
        self.ready.store(false, Ordering::Relaxed);
        self.ensure_index(client).await
    }

    async fn ensure_index(&self, client: &reqwest::Client) -> Result<(), String> {
        if self.ready.load(Ordering::Relaxed) {
            return Ok(());
        }
        let exists = |status: StatusCode| match status {
            s if s.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(format!("it answered {s} for the index")),
        };
        let head = self
            .request(client, Method::HEAD, &[])
            .send()
            .await
            .map_err(described)?;
        if !exists(head.status())? {
            let created = self
                .request(client, Method::PUT, &[])
                .send()
                .await
                .map_err(described)?;
            // Another server may have just made it.
            if !created.status().is_success() {
                let again = self
                    .request(client, Method::HEAD, &[])
                    .send()
                    .await
                    .map_err(described)?;
                if !exists(again.status())? {
                    return Err(format!(
                        "it answered {} creating the index",
                        created.status()
                    ));
                }
            }
        }
        self.ready.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// A request for the index, or `path` in it.
    fn request(
        &self,
        client: &reqwest::Client,
        method: Method,
        path: &[String],
    ) -> reqwest::RequestBuilder {
        let mut url = self.url.clone();
        url.set_fragment(None);
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.pop_if_empty().push(&self.index).extend(path);
        }
        let request = client.request(method, url);
        if let Some(key) = &self.api_key {
            let mut value = header::HeaderValue::from_str(&format!("ApiKey {}", key.as_str()))
                .unwrap_or_else(|_| header::HeaderValue::from_static(""));
            value.set_sensitive(true);
            request.header(header::AUTHORIZATION, value)
        } else if let Some(user) = &self.username {
            request.basic_auth(user, self.password.as_ref().map(|p| p.as_str()))
        } else {
            request
        }
    }
}

impl fmt::Debug for Elasticsearch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Elasticsearch")
            .field("url", &self.shown())
            .finish_non_exhaustive()
    }
}

/// An object's document id: `BUCKET/KEY` hashed, since a key can be longer than an id
/// may be (512 bytes).
pub(crate) fn document_id(key: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

/// Checks Elasticsearch's rules for an index's name.
fn check_index(index: &str) -> Result<(), String> {
    let bad = index.is_empty()
        || index.len() > 255
        || index == "."
        || index == ".."
        || index.starts_with(['-', '_', '+'])
        || index
            .chars()
            .any(|c| c.is_uppercase() || r#"\/*?"<>| ,#:"#.contains(c));
    if bad {
        Err(format!(
            "`{index}` can't name an index: use lowercase letters, digits, `-`, `_` and `.`"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_and_urls_are_checked() {
        assert!(Elasticsearch::new("https://es.example:9200", "events", Format::Namespace).is_ok());
        for bad in ["", "Events", "_x", "a/b", "a b", "a,b", ".."] {
            assert!(check_index(bad).is_err(), "{bad}");
        }
        for bad in [
            "es.example:9200",
            "ftp://es.example",
            "https://es.example?x=1",
            "https://elastic:secret@es.example",
        ] {
            assert!(
                Elasticsearch::new(bad, "events", Format::Access).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn documents_are_named_by_their_objects() {
        let id = document_id("photos/a.jpg");
        assert_eq!(id.len(), 43);
        assert_eq!(id, document_id("photos/a.jpg"));
        assert_ne!(id, document_id("photos/b.jpg"));
        assert!(!id.contains(['/', '+', '=']));
    }

    #[test]
    fn requests_go_under_the_index() {
        let es = Elasticsearch::new("http://h:9200/proxy/", "events", Format::Namespace).unwrap();
        let client = reqwest::Client::new();
        let request = es
            .request(&client, Method::PUT, &["_doc".into(), "a/b".into()])
            .build()
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "http://h:9200/proxy/events/_doc/a%2Fb"
        );
        assert!(!format!("{es:?}").contains("password"));
    }
}
