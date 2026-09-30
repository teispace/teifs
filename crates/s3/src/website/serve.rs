//! The website endpoint: a bucket's objects as a static site, answered as S3's
//! `BUCKET.s3-website-REGION.amazonaws.com` answers them.
//!
//! A request whose host is `BUCKET.DOMAIN`, for a website domain, is answered here. It
//! reads objects through the S3 service as an anonymous request, so a site shows exactly
//! what its bucket's policy, ACLs and Block Public Access let anybody read, and each
//! read is an S3 read: encryption, ranges and conditions apply, in either layout.

use std::{fmt::Write, sync::Arc};

use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use s3s::{HttpResponse, service::S3Service};
use teifs_store::{Store, StoreError};
use teifs_types::website::{KeyReplacement, Protocol, RoutingRule, Site, WebsiteConfig};

use crate::{
    encode,
    observe::{Seen, between},
};

/// The headers of a website request its object's read gets.
const FORWARDED: [header::HeaderName; 5] = [
    header::RANGE,
    header::IF_MATCH,
    header::IF_NONE_MATCH,
    header::IF_MODIFIED_SINCE,
    header::IF_UNMODIFIED_SINCE,
];
/// The header naming another place an object's page is at.
const REDIRECT_LOCATION: &str = "x-amz-website-redirect-location";

/// A website request's site: the bucket its host names, or `None` for a website domain
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Website(pub(crate) Option<String>);

/// The domains buckets' websites are served on.
#[derive(Debug, Default)]
pub(crate) struct Domains(Vec<String>);

impl Domains {
    pub(crate) fn new(domains: &[String]) -> Self {
        let mut domains: Vec<String> = domains
            .iter()
            .map(|domain| domain.trim_matches('.').to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .collect();
        // The longest first: `a.web.example.com` is bucket `a` on `web.example.com`.
        domains.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        domains.dedup();
        Self(domains)
    }

    /// The website `host` (a `Host` header) is for, if it's one's.
    pub(crate) fn site(&self, host: &str) -> Option<Website> {
        if self.0.is_empty() {
            return None;
        }
        let host = without_port(host).to_ascii_lowercase();
        self.0.iter().find_map(|domain| {
            if host == *domain {
                return Some(Website(None));
            }
            let bucket = host.strip_suffix(domain.as_str())?.strip_suffix('.')?;
            (!bucket.is_empty()).then(|| Website(Some(bucket.to_owned())))
        })
    }
}

fn without_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// What website requests are answered with.
pub(crate) struct Endpoint<'a> {
    pub(crate) s3: &'a S3Service,
    pub(crate) store: &'a Store,
    /// Who asks.
    pub(crate) client: crate::Client,
}

/// A website request, as far as answering it needs.
struct Asked<'a> {
    bucket: &'a str,
    head: bool,
    /// Its own protocol and host, where redirects that name neither go.
    protocol: &'static str,
    host: &'a str,
    headers: &'a HeaderMap,
}

impl Endpoint<'_> {
    /// Answers a request to `website`.
    pub(crate) async fn serve<B>(
        &self,
        req: &Request<B>,
        website: Website,
        seen: &Arc<Seen>,
    ) -> HttpResponse {
        seen.on_website();
        let head = req.method() == Method::HEAD;
        seen.name(match *req.method() {
            Method::GET => "GetObject",
            Method::HEAD => "HeadObject",
            _ => "WebsiteRequest",
        });
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| req.uri().host())
            .unwrap_or_default();
        if !head && req.method() != Method::GET {
            let failure = Failure::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource.",
            )
            .with("Method", req.method().as_str())
            .with("ResourceType", "OBJECT");
            return page(&failure, None, head, &seen.id);
        }
        let Website(Some(bucket)) = website else {
            return page(&Failure::no_such_bucket(host), None, head, &seen.id);
        };
        let config = match self.store.bucket_website(&bucket).await {
            Ok(Some(config)) => config,
            Ok(None) => {
                let failure = Failure::new(
                    StatusCode::NOT_FOUND,
                    "NoSuchWebsiteConfiguration",
                    "The specified bucket does not have a website configuration",
                )
                .with("BucketName", &bucket);
                return page(&failure, None, head, &seen.id);
            }
            Err(StoreError::NoSuchBucket) => {
                return page(&Failure::no_such_bucket(&bucket), None, head, &seen.id);
            }
            Err(err) => {
                tracing::error!(error = %err, "couldn't read a bucket's website configuration");
                return page(&Failure::internal(), None, head, &seen.id);
            }
        };
        let path = req.uri().path();
        let key = percent_encoding::percent_decode_str(path.strip_prefix('/').unwrap_or(path))
            .decode_utf8_lossy()
            .into_owned();
        let asked = Asked {
            bucket: &bucket,
            head,
            protocol: if self.client.secure { "https" } else { "http" },
            host,
            headers: req.headers(),
        };
        match &*config {
            WebsiteConfig::RedirectAll {
                host_name,
                protocol,
            } => {
                seen.on(&bucket, &key);
                let protocol = protocol.map_or(asked.protocol, Protocol::name);
                let rest = req.uri().path_and_query().map_or("/", |p| p.as_str());
                redirect(
                    StatusCode::MOVED_PERMANENTLY,
                    &format!("{protocol}://{host_name}{rest}"),
                )
            }
            WebsiteConfig::Site(site) => self.site(site, &asked, &key, seen).await,
        }
    }

    async fn site(
        &self,
        site: &Site,
        asked: &Asked<'_>,
        key: &str,
        seen: &Arc<Seen>,
    ) -> HttpResponse {
        if let Some(rule) = site
            .routing_rules
            .iter()
            .find(|rule| before_read(rule, key))
        {
            seen.on(asked.bucket, key);
            return asked.redirect(rule, key);
        }
        let folder = key.is_empty() || key.ends_with('/');
        let object = if folder {
            format!("{key}{}", site.index_suffix)
        } else {
            key.to_owned()
        };
        seen.on(asked.bucket, &object);
        let answer = self
            .read(asked, &object, asked.head, true, Arc::clone(seen))
            .await;
        let status = answer.status();
        if status.is_success() || status == StatusCode::NOT_MODIFIED {
            return match answer.headers().get(REDIRECT_LOCATION) {
                Some(to) => redirect_to(StatusCode::MOVED_PERMANENTLY, to.clone()),
                None => answer,
            };
        }
        let failure = Failure::of(&answer, &object);
        // A folder asked for without its slash, when it has an index document.
        if !folder && matches!(status, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN) {
            let index = format!("{key}/{}", site.index_suffix);
            let probe = self.read(asked, &index, true, false, fresh()).await;
            if probe.status().is_success() {
                return redirect(StatusCode::FOUND, &format!("/{}/", encode::url(key)));
            }
        }
        if let Some(rule) = site
            .routing_rules
            .iter()
            .find(|rule| after_error(rule, key, status))
        {
            return asked.redirect(rule, key);
        }
        let document = match &site.error_key {
            Some(document) if status.is_client_error() => {
                let mut answer = self.read(asked, document, asked.head, false, fresh()).await;
                if answer.status().is_success() {
                    *answer.status_mut() = status;
                    failure.name_in(answer.headers_mut());
                    return answer;
                }
                Some(Failure::of(&answer, document))
            }
            _ => None,
        };
        page(&failure, document.as_ref(), asked.head, &seen.id)
    }

    /// Reads `key` of the asked bucket through the S3 service, as an anonymous request
    /// that `seen` watches; with the asked range and conditions when `forward`.
    async fn read(
        &self,
        asked: &Asked<'_>,
        key: &str,
        head: bool,
        forward: bool,
        seen: Arc<Seen>,
    ) -> HttpResponse {
        let path = format!("/{}/{}", encode::url(asked.bucket), encode::url(key));
        let Ok(uri) = path.parse::<Uri>() else {
            return page(&Failure::internal(), None, head, &seen.id);
        };
        let mut req = Request::new(s3s::Body::empty());
        *req.method_mut() = if head { Method::HEAD } else { Method::GET };
        *req.uri_mut() = uri;
        if forward {
            for name in FORWARDED {
                if let Some(value) = asked.headers.get(&name) {
                    req.headers_mut().insert(name, value.clone());
                }
            }
        }
        req.extensions_mut().insert(self.client);
        req.extensions_mut().insert(Arc::clone(&seen));
        match self.s3.call(req).await {
            Ok(answer) => answer,
            Err(err) => {
                tracing::error!(error = ?err, "couldn't read a website's object");
                page(&Failure::internal(), None, head, &seen.id)
            }
        }
    }
}

impl Asked<'_> {
    /// Where a routing rule sends a request for `key`.
    fn redirect(&self, rule: &RoutingRule, key: &str) -> HttpResponse {
        let to = &rule.redirect;
        let prefix = rule
            .condition
            .as_ref()
            .and_then(|c| c.key_prefix.as_deref())
            .unwrap_or_default();
        let key = match &to.replace_key {
            Some(KeyReplacement::Key(key)) => key.clone(),
            Some(KeyReplacement::Prefix(with)) => {
                format!("{with}{}", key.strip_prefix(prefix).unwrap_or(key))
            }
            None => key.to_owned(),
        };
        let protocol = to.protocol.map_or(self.protocol, Protocol::name);
        let host = to.host_name.as_deref().unwrap_or(self.host);
        let status = to
            .http_redirect_code
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::MOVED_PERMANENTLY);
        redirect(
            status,
            &format!("{protocol}://{host}/{}", encode::url(&key)),
        )
    }
}

/// Whether a rule redirects a request for `key` before it's read: one without a
/// condition, or whose only condition is the key's prefix.
fn before_read(rule: &RoutingRule, key: &str) -> bool {
    rule.condition.as_ref().is_none_or(|condition| {
        condition.error_code.is_none() && prefixes(condition.key_prefix.as_deref(), key)
    })
}

/// Whether a rule redirects a request for `key` whose read failed with `status`.
fn after_error(rule: &RoutingRule, key: &str, status: StatusCode) -> bool {
    rule.condition.as_ref().is_some_and(|condition| {
        condition.error_code == Some(status.as_u16())
            && prefixes(condition.key_prefix.as_deref(), key)
    })
}

fn prefixes(prefix: Option<&str>, key: &str) -> bool {
    prefix.is_none_or(|prefix| key.starts_with(prefix))
}

/// A watch for a read that isn't the request's own, so it's recorded nowhere.
fn fresh() -> Arc<Seen> {
    Arc::new(Seen::new())
}

fn redirect(status: StatusCode, location: &str) -> HttpResponse {
    match HeaderValue::from_str(location) {
        Ok(location) => redirect_to(status, location),
        Err(_) => page(&Failure::internal(), None, false, ""),
    }
}

fn redirect_to(status: StatusCode, location: HeaderValue) -> HttpResponse {
    let mut response = HttpResponse::new(s3s::Body::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    response
}

/// An error a website answers with.
#[derive(Debug)]
struct Failure {
    status: StatusCode,
    code: String,
    message: String,
    /// What it's about, as S3's page lists it (`Key`, `BucketName`).
    details: Vec<(&'static str, String)>,
}

impl Failure {
    fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            code: code.to_owned(),
            message: message.to_owned(),
            details: Vec::new(),
        }
    }

    fn with(mut self, name: &'static str, value: &str) -> Self {
        self.details.push((name, value.to_owned()));
        self
    }

    fn no_such_bucket(bucket: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
        )
        .with("BucketName", bucket)
    }

    fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "We encountered an internal error. Please try again.",
        )
    }

    /// The error a read of `key` failed with: from its XML body, or, for a `HEAD`
    /// that has none, from its status.
    fn of(answer: &HttpResponse, key: &str) -> Self {
        let status = answer.status();
        let bytes = answer.body().bytes();
        let text = bytes
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or_default();
        let (code, message) = if let Some(code) = between(text, "<Code>", "</Code>") {
            let message = between(text, "<Message>", "</Message>").unwrap_or_default();
            (code.to_owned(), unescape(message))
        } else {
            let (code, message) = match status {
                StatusCode::NOT_FOUND => ("NoSuchKey", "The specified key does not exist."),
                StatusCode::FORBIDDEN => ("AccessDenied", "Access Denied"),
                StatusCode::PRECONDITION_FAILED => (
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                ),
                _ => (
                    "InternalError",
                    "We encountered an internal error. Please try again.",
                ),
            };
            (code.to_owned(), message.to_owned())
        };
        let failure = Self {
            status,
            code,
            message,
            details: Vec::new(),
        };
        if failure.code == "NoSuchKey" {
            failure.with("Key", key)
        } else {
            failure
        }
    }

    /// Names the error in an answer's headers, as S3's website endpoint does.
    fn name_in(&self, headers: &mut HeaderMap) {
        if let Ok(code) = HeaderValue::from_str(&self.code) {
            headers.insert("x-amz-error-code", code);
        }
        if let Ok(message) = HeaderValue::from_str(&self.message) {
            headers.insert("x-amz-error-message", message);
        }
    }

    fn list(&self, page: &mut String) {
        let mut item = |name: &str, value: &str| {
            let _ = writeln!(page, "<li>{name}: {}</li>", escape(value));
        };
        item("Code", &self.code);
        item("Message", &self.message);
        for (name, value) in &self.details {
            item(name, value);
        }
    }
}

/// S3's HTML error page for `failure`, and for the custom error document's own failure.
fn page(failure: &Failure, document: Option<&Failure>, head: bool, id: &str) -> HttpResponse {
    let status = failure.status;
    let title = format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default()
    );
    let mut body =
        format!("<html>\n<head><title>{title}</title></head>\n<body>\n<h1>{title}</h1>\n<ul>\n");
    failure.list(&mut body);
    let _ = write!(body, "<li>RequestId: {}</li>\n</ul>\n", escape(id));
    if let Some(document) = document {
        body.push_str(
            "<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n<ul>\n",
        );
        document.list(&mut body);
        body.push_str("</ul>\n");
    }
    body.push_str("<hr/>\n</body>\n</html>\n");
    let length = body.len();
    let mut response = HttpResponse::new(if head {
        s3s::Body::empty()
    } else {
        s3s::Body::from(body)
    });
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    failure.name_in(headers);
    response
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// XML text as it reads.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use teifs_types::website::{Condition, Redirect};

    use super::*;

    #[test]
    fn hosts_name_buckets_on_the_longest_domain() {
        let domains = Domains::new(&[
            "Example.com".to_owned(),
            ".web.example.com.".to_owned(),
            "example.com".to_owned(),
        ]);
        let site = |host: &str| domains.site(host).map(|website| website.0);
        assert_eq!(site("blog.web.example.com"), Some(Some("blog".to_owned())));
        assert_eq!(
            site("my.blog.Example.COM:8080"),
            Some(Some("my.blog".to_owned()))
        );
        assert_eq!(site("web.example.com"), Some(None));
        assert_eq!(site("example.com:80"), Some(None));
        assert_eq!(site("notexample.com"), None);
        assert_eq!(site(".example.com"), None);
        assert_eq!(site("localhost:9000"), None);
        assert_eq!(Domains::new(&[]).site("a.example.com"), None);
        assert_eq!(without_port("[::1]:80"), "[::1]");
        assert_eq!(without_port("[::1]"), "[::1]");
        assert_eq!(without_port("host:"), "host:");
    }

    fn rule(prefix: Option<&str>, error_code: Option<u16>) -> RoutingRule {
        RoutingRule {
            condition: (prefix.is_some() || error_code.is_some()).then(|| Condition {
                key_prefix: prefix.map(str::to_owned),
                error_code,
            }),
            redirect: Redirect::default(),
        }
    }

    #[test]
    fn rules_apply_before_a_read_or_after_its_error() {
        let not_found = StatusCode::NOT_FOUND;
        assert!(before_read(&rule(None, None), "a"));
        assert!(before_read(&rule(Some("docs/"), None), "docs/a"));
        assert!(!before_read(&rule(Some("docs/"), None), "doc"));
        assert!(!before_read(&rule(None, Some(404)), "a"));
        assert!(after_error(&rule(None, Some(404)), "a", not_found));
        assert!(!after_error(&rule(None, Some(403)), "a", not_found));
        assert!(after_error(&rule(Some("a"), Some(404)), "ab", not_found));
        assert!(!after_error(&rule(Some("b"), Some(404)), "ab", not_found));
        assert!(!after_error(&rule(None, None), "a", not_found));
    }

    fn location(rule: &RoutingRule, key: &str) -> (u16, String) {
        let headers = HeaderMap::new();
        let asked = Asked {
            bucket: "site",
            head: false,
            protocol: "http",
            host: "site.web.test:8080",
            headers: &headers,
        };
        let answer = asked.redirect(rule, key);
        let location = answer.headers()[header::LOCATION]
            .to_str()
            .unwrap_or_default();
        (answer.status().as_u16(), location.to_owned())
    }

    #[test]
    fn redirects_change_what_they_name() {
        let mut docs = rule(Some("docs/"), None);
        docs.redirect.replace_key = Some(KeyReplacement::Prefix("documents/".to_owned()));
        assert_eq!(
            location(&docs, "docs/a b.html"),
            (
                301,
                "http://site.web.test:8080/documents/a%20b.html".to_owned()
            )
        );
        let mut elsewhere = rule(None, Some(404));
        elsewhere.redirect = Redirect {
            host_name: Some("example.com".to_owned()),
            protocol: Some(Protocol::Https),
            http_redirect_code: Some(302),
            replace_key: Some(KeyReplacement::Key("missing.html".to_owned())),
        };
        assert_eq!(
            location(&elsewhere, "gone"),
            (302, "https://example.com/missing.html".to_owned())
        );
        let mut prefixed = rule(None, None);
        prefixed.redirect.replace_key = Some(KeyReplacement::Prefix("v2/".to_owned()));
        assert_eq!(
            location(&prefixed, "a"),
            (301, "http://site.web.test:8080/v2/a".to_owned())
        );
    }

    #[test]
    fn error_pages_are_s3s() {
        let failure =
            Failure::new(StatusCode::NOT_FOUND, "NoSuchKey", "The <key>").with("Key", "a&b");
        let document = Failure::new(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied");
        let answer = page(&failure, Some(&document), false, "ID");
        assert_eq!(answer.status(), StatusCode::NOT_FOUND);
        assert_eq!(answer.headers()["x-amz-error-code"], "NoSuchKey");
        assert_eq!(answer.headers()["content-type"], "text/html; charset=utf-8");
        let body = answer.body().bytes().unwrap_or_default();
        assert_eq!(
            std::str::from_utf8(&body).unwrap_or_default(),
            "<html>\n<head><title>404 Not Found</title></head>\n<body>\n<h1>404 Not Found</h1>\n\
             <ul>\n<li>Code: NoSuchKey</li>\n<li>Message: The &lt;key&gt;</li>\n\
             <li>Key: a&amp;b</li>\n<li>RequestId: ID</li>\n</ul>\n\
             <h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n\
             <ul>\n<li>Code: AccessDenied</li>\n<li>Message: Access Denied</li>\n</ul>\n\
             <hr/>\n</body>\n</html>\n"
        );
        let head = page(&failure, None, true, "ID");
        assert_eq!(head.body().bytes().unwrap_or_default().len(), 0);
        assert_ne!(head.headers()[header::CONTENT_LENGTH], "0");
    }

    #[test]
    fn failures_are_read_from_xml_or_the_status() {
        let answer = |status: StatusCode, body: &str| {
            let mut answer = HttpResponse::new(s3s::Body::from(body.to_owned()));
            *answer.status_mut() = status;
            answer
        };
        let xml = answer(
            StatusCode::NOT_FOUND,
            "<Error><Code>NoSuchKey</Code><Message>a &amp; b</Message></Error>",
        );
        let failure = Failure::of(&xml, "k");
        assert_eq!(
            (failure.code.as_str(), failure.message.as_str()),
            ("NoSuchKey", "a & b")
        );
        assert_eq!(failure.details, [("Key", "k".to_owned())]);
        let head = Failure::of(&answer(StatusCode::FORBIDDEN, ""), "k");
        assert_eq!(
            (head.code.as_str(), head.details.len()),
            ("AccessDenied", 0)
        );
        let head = Failure::of(&answer(StatusCode::NOT_FOUND, ""), "k");
        assert_eq!(head.code, "NoSuchKey");
    }
}
