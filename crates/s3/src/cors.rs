//! Cross-origin resource sharing, as S3 does it: a bucket's CORS rules answer browsers'
//! preflight `OPTIONS` requests, and add `Access-Control-*` headers to requests that
//! carry an `Origin`. The first rule whose origin, method and headers match applies.
//!
//! s3s has no `OPTIONS` route, so this is a thin HTTP service around the S3 service.

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use s3s::{
    HttpError, HttpResponse, S3Result, dto,
    host::{MultiDomain, S3Host},
    s3_error,
    service::S3Service,
};
use teifs_store::{CorsRule, Store, StoreError};
use tracing::Instrument;

use crate::{
    access_log::Arrival,
    audit::Asked,
    health,
    limits::{StallTimeout, refusal},
    metrics,
    observe::{self, Received, Seen, Watch},
    website::Website,
};

/// How many rules a bucket's CORS configuration may have.
const MAX_RULES: usize = 100;
/// The methods a rule may allow.
const METHODS: [&str; 5] = ["GET", "PUT", "POST", "DELETE", "HEAD"];
/// What a response varies by when a bucket has CORS rules.
const VARY: &str = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method";

/// Checks a CORS configuration from a request body as S3 does.
pub(crate) fn from_dto(config: dto::CORSConfiguration) -> S3Result<Vec<CorsRule>> {
    if config.cors_rules.is_empty() {
        return Err(s3_error!(MalformedXML, "a CORS configuration needs a rule"));
    }
    if config.cors_rules.len() > MAX_RULES {
        return Err(s3_error!(
            InvalidRequest,
            "a CORS configuration can't have more than {MAX_RULES} rules"
        ));
    }
    config
        .cors_rules
        .into_iter()
        .map(|rule| {
            if rule.allowed_origins.is_empty() || rule.allowed_methods.is_empty() {
                return Err(s3_error!(
                    MalformedXML,
                    "a CORS rule needs an AllowedOrigin and an AllowedMethod"
                ));
            }
            if let Some(method) = rule
                .allowed_methods
                .iter()
                .find(|m| !METHODS.contains(&m.as_str()))
            {
                return Err(s3_error!(
                    InvalidRequest,
                    "Found unsupported HTTP method in CORS config. Unsupported method is {method}"
                ));
            }
            let allowed_headers = rule.allowed_headers.unwrap_or_default();
            for pattern in rule.allowed_origins.iter().chain(&allowed_headers) {
                if pattern.matches('*').count() > 1 {
                    return Err(s3_error!(
                        InvalidRequest,
                        "\"{pattern}\" can not have more than one wildcard."
                    ));
                }
            }
            if rule.id.as_ref().is_some_and(|id| id.len() > 255) {
                return Err(s3_error!(
                    InvalidRequest,
                    "a CORS rule's ID can't be longer than 255 characters"
                ));
            }
            Ok(CorsRule {
                id: rule.id,
                allowed_origins: rule.allowed_origins,
                allowed_methods: rule.allowed_methods,
                allowed_headers,
                expose_headers: rule.expose_headers.unwrap_or_default(),
                max_age_seconds: rule.max_age_seconds,
            })
        })
        .collect()
}

/// A bucket's CORS rules for a response.
pub(crate) fn to_dto(rules: Vec<CorsRule>) -> Vec<dto::CORSRule> {
    rules
        .into_iter()
        .map(|rule| dto::CORSRule {
            id: rule.id,
            allowed_origins: rule.allowed_origins,
            allowed_methods: rule.allowed_methods,
            allowed_headers: (!rule.allowed_headers.is_empty()).then_some(rule.allowed_headers),
            expose_headers: (!rule.expose_headers.is_empty()).then_some(rule.expose_headers),
            max_age_seconds: rule.max_age_seconds,
        })
        .collect()
}

/// Whether `value` matches `pattern`, which may hold one `*` standing for any text.
fn matches(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((prefix, suffix)) => {
            value.len() >= prefix.len() + suffix.len()
                && value.starts_with(prefix)
                && value.ends_with(suffix)
        }
    }
}

/// The rule that applies to a request from `origin` for `method` asking for `headers`
/// (lowercase), and whether it allows any origin.
fn find<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: &str,
    headers: &[String],
) -> Option<(&'a CorsRule, bool)> {
    rules.iter().find_map(|rule| {
        let pattern = rule.allowed_origins.iter().find(|p| matches(p, origin))?;
        let method_ok = rule.allowed_methods.iter().any(|m| m == method);
        let headers_ok = headers.iter().all(|h| {
            rule.allowed_headers
                .iter()
                .any(|p| matches(&p.to_ascii_lowercase(), h))
        });
        (method_ok && headers_ok).then_some((rule, pattern == "*"))
    })
}

/// Adds the headers a matching rule grants.
fn grant(headers: &mut HeaderMap, rule: &CorsRule, any_origin: bool, origin: &str) {
    let mut set = |name: &'static str, value: String| {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    };
    set(
        "access-control-allow-origin",
        if any_origin {
            "*".to_owned()
        } else {
            origin.to_owned()
        },
    );
    set(
        "access-control-allow-methods",
        rule.allowed_methods.join(", "),
    );
    if !rule.expose_headers.is_empty() {
        set(
            "access-control-expose-headers",
            rule.expose_headers.join(", "),
        );
    }
    if !any_origin {
        set("access-control-allow-credentials", "true".to_owned());
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// An S3 error answer that doesn't come from the S3 service. The message is escaped: it
/// may quote what the request sent.
pub(crate) fn error(status: StatusCode, code: &str, message: &str) -> HttpResponse {
    let message = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    let mut response = HttpResponse::new(s3s::Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    response
}

/// The S3 service with CORS in front of it.
#[derive(Clone)]
pub struct Service {
    s3: S3Service,
    store: Store,
    host: Option<Arc<MultiDomain>>,
    body_timeout: Option<Duration>,
    /// Whether plain HTTP counts as secure for SSE-C keys.
    plain_http_is_secure: bool,
    proxies: Arc<crate::TrustedProxies>,
    /// The connection's peer.
    client: crate::Client,
    certificates: crate::ClientCertificates,
    watch: Arc<Watch>,
    /// The background jobs, until the server takes them to run.
    workers: Arc<std::sync::Mutex<Option<crate::Workers>>>,
    /// What the store tells the lifecycle's removals, kept while the service is.
    expirations: Option<Arc<dyn teifs_store::Expirations>>,
    /// The domains buckets' websites are served on.
    websites: Arc<crate::website::Domains>,
    /// The server's freezes, and whether it was asked to stop.
    control: Arc<crate::Control>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").finish_non_exhaustive()
    }
}

impl Service {
    pub(crate) fn new(
        s3: S3Service,
        store: Store,
        host: Option<MultiDomain>,
        body_timeout: Option<Duration>,
        plain_http_is_secure: bool,
        proxies: crate::TrustedProxies,
        watch: Watch,
    ) -> Self {
        Self {
            watch: Arc::new(watch),
            workers: Arc::default(),
            expirations: None,
            websites: Arc::default(),
            control: Arc::default(),
            s3,
            store,
            host: host.map(Arc::new),
            body_timeout,
            plain_http_is_secure,
            proxies: Arc::new(proxies),
            client: crate::Client::default(),
            certificates: crate::ClientCertificates::default(),
        }
    }

    /// The service with its background jobs, for the server to take and run, and what
    /// logs the lifecycle's removals.
    #[must_use]
    pub(crate) fn with_workers(
        mut self,
        workers: crate::Workers,
        expirations: Arc<dyn teifs_store::Expirations>,
    ) -> Self {
        self.expirations = Some(expirations);
        *self
            .workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(workers);
        self
    }

    /// The service sharing `control` with its calls.
    #[must_use]
    pub(crate) fn with_control(mut self, control: Arc<crate::Control>) -> Self {
        self.control = control;
        self
    }

    /// What the admin API asks of the server: to stop or restart, to hold S3's requests.
    #[must_use]
    pub fn control(&self) -> Arc<crate::Control> {
        Arc::clone(&self.control)
    }

    /// The service with buckets' websites served on `domains` (`BUCKET.DOMAIN`).
    #[must_use]
    pub(crate) fn with_website_domains(mut self, domains: &[String]) -> Self {
        self.websites = Arc::new(crate::website::Domains::new(domains));
        self
    }

    /// The background jobs, which deliver buckets' access logs and make their inventory
    /// reports while they run: the first call has them, later ones none.
    #[must_use]
    pub fn workers(&self) -> Option<crate::Workers> {
        self.workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// The service for one connection whose client sent `certificates` over TLS.
    #[must_use]
    pub fn with_client_certificates(mut self, certificates: crate::ClientCertificates) -> Self {
        self.certificates = certificates;
        self
    }

    /// The service for one connection: requests on it come from `client`.
    #[must_use]
    pub fn for_client(&self, client: crate::Client) -> Self {
        Self {
            client,
            ..self.clone()
        }
    }

    /// Passes a request to the S3 service, its body timed out if it stalls.
    async fn s3(
        &self,
        req: Request<hyper::body::Incoming>,
        seen: &Arc<Seen>,
    ) -> Result<HttpResponse, HttpError> {
        if let Some(refused) = crate::sig_v2::refusal(req.headers()) {
            return Ok(refused);
        }
        let timeout = self.body_timeout;
        let client = self.proxies.client(self.client, req.headers());
        let mut req = req;
        req.extensions_mut().insert(client);
        req.extensions_mut().insert(self.certificates.clone());
        req.extensions_mut().insert(Arc::clone(seen));
        let req = req.map(|body| {
            let body = Received::new(body, Arc::clone(seen));
            match timeout {
                Some(timeout) => s3s::Body::http_body(StallTimeout::new(body, timeout)),
                None => s3s::Body::http_body(body),
            }
        });
        let req = match crate::iam_api::with_payload_hash(req).await {
            Ok(req) => req,
            Err(refused) => return Ok(*refused),
        };
        let mut req = req;
        let virtual_hosted = self.virtual_bucket(&req).is_some();
        crate::sig_v2::canonical_bucket_path(&mut req, virtual_hosted);
        let bucket = self.bucket_of(&req);
        match crate::post_form::with_form(req, bucket.as_deref()).await {
            // SSE-C keys never travel in the clear, whatever the request does with them
            // (a form's fields are headers by now).
            Ok(req)
                if !(client.secure || self.plain_http_is_secure)
                    && crate::sse::names_customer_key(req.headers()) =>
            {
                Ok(error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    crate::sse::CUSTOMER_KEY_NEEDS_TLS,
                ))
            }
            Ok(req) if crate::control::has_encoded_path(&req) => {
                crate::control::call_encoded(&self.s3, req).await
            }
            Ok(req) => self.s3.call(req).await,
            Err(refused) => Ok(*refused),
        }
    }

    /// The bucket named by a request's virtual host, if it's virtual-hosted.
    fn virtual_bucket<B>(&self, req: &Request<B>) -> Option<String> {
        let host = self.host.as_ref()?;
        let name = header(req.headers(), "host").or_else(|| req.uri().host())?;
        host.parse_host_header(name)
            .ok()
            .and_then(|vh| vh.bucket().map(str::to_owned))
    }

    /// The website a request is for, if it's for one.
    fn website<B>(&self, req: &Request<B>) -> Option<Website> {
        let name = header(req.headers(), "host").or_else(|| req.uri().host())?;
        self.websites.site(name)
    }

    /// Answers a request: on a website when `website` says so, else through S3.
    async fn answer(
        &self,
        req: Request<hyper::body::Incoming>,
        seen: &Arc<Seen>,
        website: Option<Website>,
    ) -> Result<HttpResponse, HttpError> {
        let Some(website) = website else {
            return self.s3(req, seen).await;
        };
        let endpoint = crate::website::Endpoint {
            s3: &self.s3,
            store: &self.store,
            client: self.proxies.client(self.client, req.headers()),
        };
        Ok(endpoint.serve(&req, website, seen).await)
    }

    /// The bucket a request is for: from a virtual host, else the path's first segment.
    fn bucket_of<B>(&self, req: &Request<B>) -> Option<String> {
        if let Some(bucket) = self.virtual_bucket(req) {
            return Some(bucket);
        }
        req.uri()
            .path()
            .trim_start_matches('/')
            .split('/')
            .next()
            .filter(|b| !b.is_empty())
            .map(str::to_owned)
    }

    /// Answers a preflight request.
    async fn preflight<B>(&self, req: &Request<B>, bucket: Option<String>) -> HttpResponse {
        let headers = req.headers();
        let (Some(origin), Some(method)) = (
            header(headers, "origin"),
            header(headers, "access-control-request-method"),
        ) else {
            return error(
                StatusCode::BAD_REQUEST,
                "BadRequest",
                "Insufficient information. Origin request header needed.",
            );
        };
        let Some(bucket) = bucket else {
            return error(
                StatusCode::BAD_REQUEST,
                "BadRequest",
                "A preflight request needs a bucket.",
            );
        };
        let rules = match self.store.bucket_cors(&bucket).await {
            Ok(Some(rules)) => rules,
            Ok(None) => {
                return error(
                    StatusCode::FORBIDDEN,
                    "AccessForbidden",
                    "CORSResponse: CORS is not enabled for this bucket.",
                );
            }
            Err(StoreError::NoSuchBucket) => {
                return error(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                );
            }
            Err(err) => {
                tracing::error!(error = %err, "couldn't read a bucket's CORS rules");
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "We encountered an internal error. Please try again.",
                );
            }
        };
        let requested: Vec<String> = header(headers, "access-control-request-headers")
            .unwrap_or_default()
            .split(',')
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        let Some((rule, any_origin)) = find(&rules, origin, method, &requested) else {
            return error(
                StatusCode::FORBIDDEN,
                "AccessForbidden",
                "CORSResponse: This CORS request is not allowed. This is usually because the evaluation of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.",
            );
        };
        let mut response = HttpResponse::new(s3s::Body::empty());
        let out = response.headers_mut();
        grant(out, rule, any_origin, origin);
        if !requested.is_empty()
            && let Ok(value) = HeaderValue::from_str(&requested.join(", "))
        {
            out.insert("access-control-allow-headers", value);
        }
        if let Some(age) = rule.max_age_seconds {
            out.insert("access-control-max-age", HeaderValue::from(age));
        }
        out.insert(header::VARY, HeaderValue::from_static(VARY));
        response
    }

    /// Cancel it when the server stops: it ends the answers that would last until then
    /// (live traces), so the connections can close.
    #[must_use]
    pub fn stopping(&self) -> tokio_util::sync::CancellationToken {
        self.watch.tracers.stopping()
    }

    async fn handle(self, req: Request<hyper::body::Incoming>) -> Result<HttpResponse, HttpError> {
        let path = req.uri().path();
        let website = self.website(&req);
        if website.is_none() && self.virtual_bucket(&req).is_none() {
            if let Some(probe) = health::probe(req.method(), path, req.headers(), req.uri().query())
            {
                let query = req.uri().query();
                return Ok(health::answer(probe, req.method(), query, &self.store).await);
            }
            if metrics::is_scrape(req.method(), path) {
                let client = self.proxies.client(self.client, req.headers());
                let seen = Seen::new();
                let response = metrics::scrape(
                    &self.watch.metrics,
                    &self.watch.scrapers,
                    req.uri().query(),
                    req.headers(),
                    client,
                    &seen.id,
                )
                .await;
                return Ok(response);
            }
        }
        let seen = Arc::new(Seen::new().with_method(req.method().clone()));
        let asked = self.watch.audits().then(|| {
            let client = self.proxies.client(self.client, req.headers());
            Asked::of(&req, client.ip)
        });
        let arrival = self.watch.access_log.on().then(|| {
            let client = self.proxies.client(self.client, req.headers());
            let bucket = match &website {
                Some(website) => website.0.clone(),
                None => self.bucket_of(&req),
            };
            Arrival::of(&req, client, bucket)
        });
        let request =
            observe::Request::new(Arc::clone(&self.watch), Arc::clone(&seen), asked, arrival);
        // Everything logged while answering names the request, as its answer does.
        let span = tracing::info_span!("request", id = %seen.id);
        // A client waiting for `100 Continue` hasn't sent the body the answer spares it.
        let continues = header(req.headers(), "expect")
            .is_some_and(|expect| expect.eq_ignore_ascii_case("100-continue"));
        let response = self.respond(req, &seen, website).instrument(span).await?;
        if !continues {
            observe::drain(&seen).await;
        }
        Ok(observe::finish(response, request))
    }

    /// Answers anything but the health check and metrics: a website's request when
    /// `website` says so.
    async fn respond(
        &self,
        req: Request<hyper::body::Incoming>,
        seen: &Arc<Seen>,
        website: Option<Website>,
    ) -> Result<HttpResponse, HttpError> {
        if let Some(refused) = refusal(req.headers()) {
            return Ok(refused);
        }
        let bucket = match &website {
            Some(website) => website.0.clone(),
            None => self.bucket_of(&req),
        };
        if req.method() == Method::OPTIONS {
            seen.name("PreflightRequest");
            return Ok(self.preflight(&req, bucket).await);
        }
        let Some(origin) = header(req.headers(), "origin").map(str::to_owned) else {
            return self.answer(req, seen, website).await;
        };
        // S3-compatible servers match an actual request on Access-Control-Request-Method
        // when it's sent, else on the request's own method.
        let method = header(req.headers(), "access-control-request-method")
            .map_or_else(|| req.method().as_str().to_owned(), str::to_owned);
        let rules = match bucket {
            Some(bucket) => self.store.bucket_cors(&bucket).await.ok().flatten(),
            None => None,
        };
        let mut response = self.answer(req, seen, website).await?;
        if let Some(rules) = rules {
            let headers = response.headers_mut();
            headers.insert(header::VARY, HeaderValue::from_static(VARY));
            if let Some((rule, any_origin)) = find(&rules, &origin, &method, &[]) {
                grant(headers, rule, any_origin, &origin);
            }
        }
        Ok(response)
    }
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for Service {
    type Response = HttpResponse;
    type Error = HttpError;
    type Future = BoxFuture<'static, Result<HttpResponse, HttpError>>;

    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        Box::pin(self.clone().handle(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origins: &[&str], methods: &[&str], headers: &[&str]) -> CorsRule {
        CorsRule {
            allowed_origins: origins.iter().map(|s| (*s).to_owned()).collect(),
            allowed_methods: methods.iter().map(|s| (*s).to_owned()).collect(),
            allowed_headers: headers.iter().map(|s| (*s).to_owned()).collect(),
            ..CorsRule::default()
        }
    }

    #[test]
    fn origins_match_with_one_wildcard() {
        assert!(matches("*suffix", "foo.suffix"));
        assert!(!matches("*suffix", "foo.suffix.get"));
        assert!(matches("start*end", "startend"));
        assert!(matches("start*end", "start12end"));
        assert!(!matches("start*end", "0start12end"));
        assert!(!matches("start*end", "startend0"));
        // The wildcard can't let the prefix and suffix overlap.
        assert!(!matches("ab*ba", "aba"));
        assert!(matches("*", "anything"));
        assert!(matches("http://a.com", "http://a.com"));
        assert!(!matches("http://a.com", "https://a.com"));
    }

    #[test]
    fn the_first_matching_rule_applies() {
        let rules = [
            rule(&["*.put"], &["PUT"], &[]),
            rule(
                &["https://app.example"],
                &["GET", "PUT"],
                &["x-amz-*", "content-type"],
            ),
            rule(&["*"], &["GET"], &[]),
        ];
        let (found, any) = find(&rules, "a.put", "PUT", &[]).unwrap();
        assert_eq!((found.allowed_origins[0].as_str(), any), ("*.put", false));
        let headers = ["x-amz-date".to_owned(), "content-type".to_owned()];
        let (found, _) = find(&rules, "https://app.example", "PUT", &headers).unwrap();
        assert_eq!(found.allowed_origins[0], "https://app.example");
        // A header no rule allows: only the wildcard-origin rule could apply, and it
        // allows no headers.
        assert!(
            find(
                &rules,
                "https://app.example",
                "PUT",
                &["x-other".to_owned()]
            )
            .is_none()
        );
        let (_, any) = find(&rules, "https://elsewhere", "GET", &[]).unwrap();
        assert!(any);
        assert!(find(&rules, "https://elsewhere", "DELETE", &[]).is_none());
    }

    #[test]
    fn configurations_are_checked() {
        let config = |rules: Vec<dto::CORSRule>| dto::CORSConfiguration { cors_rules: rules };
        let dto_rule = |origin: &str, method: &str| dto::CORSRule {
            allowed_origins: vec![origin.to_owned()],
            allowed_methods: vec![method.to_owned()],
            ..dto::CORSRule::default()
        };
        assert!(from_dto(config(vec![dto_rule("*.example", "GET")])).is_ok());
        assert!(from_dto(config(vec![])).is_err());
        assert!(from_dto(config(vec![dto_rule("*.a*", "GET")])).is_err());
        assert!(from_dto(config(vec![dto_rule("*", "PATCH")])).is_err());
        assert!(from_dto(config((0..101).map(|_| dto_rule("*", "GET")).collect())).is_err());
        let rules = from_dto(config(vec![dto_rule("*", "GET")])).unwrap();
        assert_eq!(to_dto(rules)[0].allowed_methods, ["GET"]);
    }
}
