//! The TeiFS web console: a page in the browser for buckets, objects, IAM and the
//! server's state, served on a listener of its own.
//!
//! The console adds no authority of its own. Its backend serves the page's files, signs
//! people in and out, and passes every other request on to the S3 service, signed with
//! Signature V4 by the signed-in person's own key, over an in-memory HTTP connection: the
//! S3 service authenticates, authorizes, audits and answers it exactly as it would a
//! request from the AWS CLI with that key. The key stays in the server's memory, never in
//! the browser after the sign-in form; the browser holds only an `HttpOnly` session
//! cookie.
//!
//! Routes:
//! - `GET /` and the page's files ([`assets`]).
//! - `GET|POST|DELETE /api/session`: who is signed in, sign in, sign out.
//! - `/api/s3/PATH`: an S3 or admin API request for `PATH`, signed for `s3`.
//! - `POST /api/iam`, `POST /api/sts`: an IAM or STS (Query protocol) request.
//! - `GET /api/download/BUCKET/KEY`: an object, as an attachment, for a plain link.

mod assets;
mod guard;
mod proxy;
mod sessions;

use std::{net::IpAddr, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use hyper::body::Incoming;
use s3s::{HttpError, HttpResponse};
use serde::{Deserialize, Serialize};
use teifs_s3::{Client, TrustedProxies};
use zeroize::Zeroizing;

pub use assets::{FILES, File, is_embedded};
pub use guard::{API_CSP, APP_CSP, CONSOLE_HEADER};
use sessions::{Attempts, Key, Session, Sessions};

/// The session cookie over HTTPS (`__Host-`: only from this origin, over HTTPS, for every
/// path).
pub const SECURE_COOKIE: &str = "__Host-teifs-console";
/// The session cookie over plain HTTP, which only loopback and a trusted proxy's network
/// carry it on.
pub const PLAIN_COOKIE: &str = "teifs-console";

/// The largest sign-in form.
const MAX_SIGN_IN_BYTES: usize = 16 * 1024;

/// The web console, ready to serve connections.
#[derive(Clone)]
pub struct Console {
    shared: Arc<Shared>,
    /// The connection's peer.
    client: Client,
}

struct Shared {
    s3: teifs_s3::Service,
    proxies: TrustedProxies,
    sessions: Sessions,
    attempts: Attempts,
    /// The `Host` requests to the S3 service carry: an address, which no domain's
    /// virtual-hosted-style bucket can be.
    host: String,
}

impl std::fmt::Debug for Console {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Console")
            .field("host", &self.shared.host)
            .finish_non_exhaustive()
    }
}

impl Console {
    /// A console for `s3`, the S3 service the server serves; `proxies` are the reverse
    /// proxies trusted to name their clients, and `host` the S3 endpoint's address
    /// (`127.0.0.1:9000`), which requests to it are signed for.
    #[must_use]
    pub fn new(s3: teifs_s3::Service, proxies: TrustedProxies, host: String) -> Self {
        Self {
            shared: Arc::new(Shared {
                s3,
                proxies,
                sessions: Sessions::default(),
                attempts: Attempts::default(),
                host,
            }),
            client: Client::default(),
        }
    }

    /// The console for one connection: requests on it come from `client`.
    #[must_use]
    pub fn for_client(&self, client: Client) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            client,
        }
    }

    async fn handle(self, req: Request<Incoming>) -> Result<HttpResponse, HttpError> {
        let client = self.shared.proxies.client(self.client, req.headers());
        let path = req.uri().path().to_owned();
        let response = match path.strip_prefix("/api/") {
            Some(route) => self.api(req, client, route).await,
            None => assets::serve(req.method(), &path),
        };
        Ok(guard::harden(
            response,
            path.starts_with("/api/"),
            client.secure,
        ))
    }

    async fn api(&self, req: Request<Incoming>, client: Client, route: &str) -> HttpResponse {
        if let Some(object) = route.strip_prefix("download/") {
            return self.download(req, client, object).await;
        }
        if let Some(refused) = guard::same_origin(req.headers()) {
            return refused;
        }
        if route == "session" {
            return match *req.method() {
                Method::GET => self.whoami(req.headers(), client.secure),
                Method::POST => self.sign_in(req, client).await,
                Method::DELETE => self.sign_out(req.headers(), client.secure),
                _ => method_not_allowed(),
            };
        }
        let Some(session) = self.session(req.headers(), client.secure) else {
            return signed_out();
        };
        match route {
            "iam" | "sts" if req.method() == Method::POST => {
                proxy::forward(&self.shared, &session, client, req, route, "/").await
            }
            "iam" | "sts" => method_not_allowed(),
            _ => match route.strip_prefix("s3") {
                Some(path) if path.is_empty() || path.starts_with('/') => {
                    let path = if path.is_empty() { "/" } else { path };
                    proxy::forward(&self.shared, &session, client, req, "s3", path).await
                }
                _ => error(StatusCode::NOT_FOUND, "NotFound", "There's no such route."),
            },
        }
    }

    /// The signed-in session the request's cookie names, if it's still open.
    fn session(&self, headers: &HeaderMap, secure: bool) -> Option<Arc<Session>> {
        let token = guard::cookie(headers, cookie_name(secure))?;
        self.shared.sessions.find(token)
    }

    fn whoami(&self, headers: &HeaderMap, secure: bool) -> HttpResponse {
        match self.session(headers, secure) {
            Some(session) => json(StatusCode::OK, &Whoami::of(&session)),
            None => signed_out(),
        }
    }

    async fn sign_in(&self, req: Request<Incoming>, client: Client) -> HttpResponse {
        let ip = client.ip.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        if let Err(wait) = self.shared.attempts.allowed(ip) {
            let mut response = error(
                StatusCode::TOO_MANY_REQUESTS,
                "TooManySignIns",
                "Too many failed sign-ins from this address: wait a few minutes, then try again.",
            );
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(wait.as_secs().max(1)),
            );
            return response;
        }
        let Some(form) = read_form(req.into_body()).await else {
            return error(
                StatusCode::BAD_REQUEST,
                "BadSignIn",
                "Send the access key and secret key as JSON.",
            );
        };
        let key = form.key();
        match proxy::caller_identity(&self.shared, client, &key).await {
            Ok((arn, account)) => {
                self.shared.attempts.succeeded(ip);
                tracing::info!(%arn, "signed in to the console");
                let session = Session::new(key, arn, account);
                let shown = Whoami::of(&session);
                let token = self.shared.sessions.start(session);
                let mut response = json(StatusCode::OK, &shown);
                set_cookie(&mut response, client.secure, &token, sessions::LONGEST);
                response
            }
            Err(proxy::SignInError::Refused) => {
                self.shared.attempts.failed(ip);
                error(
                    StatusCode::UNAUTHORIZED,
                    "SignInRefused",
                    "That access key and secret key don't sign in: check them, and that the key is active.",
                )
            }
            Err(proxy::SignInError::Unavailable(why)) => {
                tracing::warn!(error = %why, "the console couldn't check a sign-in");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    "The server couldn't check the key just now: try again.",
                )
            }
        }
    }

    fn sign_out(&self, headers: &HeaderMap, secure: bool) -> HttpResponse {
        if let Some(token) = guard::cookie(headers, cookie_name(secure)) {
            self.shared.sessions.end(token);
        }
        let mut response = HttpResponse::new(s3s::Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        set_cookie(&mut response, secure, "", std::time::Duration::ZERO);
        response
    }

    /// An object as an attachment, for a plain link (big files go to disk, not memory).
    async fn download(&self, req: Request<Incoming>, client: Client, object: &str) -> HttpResponse {
        if !matches!(*req.method(), Method::GET | Method::HEAD) {
            return method_not_allowed();
        }
        if let Some(refused) = guard::same_site(req.headers()) {
            return refused;
        }
        let Some(session) = self.session(req.headers(), client.secure) else {
            return signed_out();
        };
        let Some((_, key)) = object
            .split_once('/')
            .filter(|(b, k)| !b.is_empty() && !k.is_empty())
        else {
            return error(
                StatusCode::NOT_FOUND,
                "NotFound",
                "Name a bucket and a key.",
            );
        };
        let name = proxy::file_name(key);
        let path = format!("/{object}");
        let mut response = proxy::download(&self.shared, &session, client, req, &path).await;
        if response.status().is_success() {
            proxy::attachment(response.headers_mut(), &name);
        }
        response
    }
}

impl hyper::service::Service<Request<Incoming>> for Console {
    type Response = HttpResponse;
    type Error = HttpError;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, HttpError>> + Send>,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        Box::pin(self.clone().handle(req))
    }
}

/// The session cookie's name over HTTPS (`secure`) or plain HTTP.
#[must_use]
pub const fn cookie_name(secure: bool) -> &'static str {
    if secure { SECURE_COOKIE } else { PLAIN_COOKIE }
}

fn set_cookie(response: &mut HttpResponse, secure: bool, token: &str, age: std::time::Duration) {
    let attributes = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{attributes}",
        cookie_name(secure),
        age.as_secs()
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

/// The sign-in form.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignIn {
    access_key: String,
    secret_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

impl SignIn {
    fn key(mut self) -> Key {
        Key {
            id: self.access_key.trim().to_owned(),
            secret: Zeroizing::new(std::mem::take(&mut self.secret_key)),
            token: self
                .session_token
                .take()
                .filter(|token| !token.trim().is_empty())
                .map(Zeroizing::new),
        }
    }
}

impl Drop for SignIn {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.secret_key.zeroize();
        if let Some(token) = &mut self.session_token {
            token.zeroize();
        }
    }
}

async fn read_form(body: Incoming) -> Option<SignIn> {
    use http_body_util::BodyExt as _;
    let bytes = http_body_util::Limited::new(body, MAX_SIGN_IN_BYTES)
        .collect()
        .await
        .ok()?
        .to_bytes();
    // The form holds the secret: wipe its bytes once parsed.
    let bytes = Zeroizing::new(bytes.to_vec());
    let form: SignIn = serde_json::from_slice(&bytes).ok()?;
    (!form.access_key.trim().is_empty() && !form.secret_key.is_empty()).then_some(form)
}

/// Who is signed in, as the page shows it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Whoami {
    access_key: String,
    arn: String,
    account: String,
    /// Seconds until the session ends at the latest.
    expires_in: u64,
}

impl Whoami {
    fn of(session: &Session) -> Self {
        Self {
            access_key: session.key.id.clone(),
            arn: session.arn.clone(),
            account: session.account.clone(),
            expires_in: session.left().as_secs(),
        }
    }
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> HttpResponse {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut response = HttpResponse::new(s3s::Body::from(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// The console's own errors: `{"code": …, "message": …}`.
fn error(status: StatusCode, code: &str, message: &str) -> HttpResponse {
    #[derive(Serialize)]
    struct Error<'a> {
        code: &'a str,
        message: &'a str,
    }
    json(status, &Error { code, message })
}

fn signed_out() -> HttpResponse {
    error(
        StatusCode::UNAUTHORIZED,
        "SignedOut",
        "Sign in to the console first: the session ended or never started.",
    )
}

fn method_not_allowed() -> HttpResponse {
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "MethodNotAllowed",
        "That method isn't allowed here.",
    )
}
