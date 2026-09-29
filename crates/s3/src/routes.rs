//! Every request that isn't an S3 operation: the IAM and STS Query APIs, S3 Control and
//! TeiFS's admin API.
//! s3s hands them to one custom route, [`Routes`], before it parses a path as a bucket
//! and key, and after it has checked the signature.
//!
//! What's served is a table, [`ENDPOINTS`]: each endpoint names its method, path and
//! what it needs of its caller ([`Needs`]), which has no default, so an endpoint can't be
//! added without saying how it's authorized. Every call is decided by the table before
//! its handler runs: unsigned requests and keys IAM doesn't know are refused, and an
//! endpoint's action is decided with the caller's policies (the root user may always).
//! A test walks the table with an anonymous caller and a user without permissions.

use std::{sync::Arc, time::SystemTime};

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use s3s::{Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, route::S3Route};
use teifs_iam::{Iam, Identity};
use teifs_store::Store;
use teifs_types::admin::{
    ADMIN_CONFIG, ADMIN_IAM, ADMIN_IAM_SECRETS, ADMIN_INFO, ADMIN_PREFIX, ADMIN_ROOT_KEY,
    ServerConfig,
};

use crate::{
    access::{Client, base_context},
    admin,
    bucket_access::Rules,
    control, iam_api,
};

/// Which API a request is for, told apart before anything else is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// IAM and STS: a signed form posted to `/`.
    Query,
    /// S3 Control: `/v20180820/…` with the `x-amz-account-id` header, which no S3
    /// request sends (so a bucket named `v20180820` stays a bucket).
    Control,
    /// TeiFS's admin API: JSON under `/.teifs/admin/v1/`, which can't be a bucket (but
    /// can be a key, so virtual-hosted-style requests are never for it).
    Admin,
}

/// What an endpoint needs of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Needs {
    /// This action on this resource, decided with the caller's policies.
    Action(&'static str, &'static str),
    /// The Query APIs name an action in each call's body, and IAM decides it.
    PerCall,
    /// Only the account's root user, whatever policies say.
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    Get,
    Put,
    Post,
    Delete,
}

impl Verb {
    fn of(method: &Method) -> Option<Self> {
        Some(match *method {
            Method::GET => Self::Get,
            Method::PUT => Self::Put,
            Method::POST => Self::Post,
            Method::DELETE => Self::Delete,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handler {
    Query,
    GetAccountBlock,
    PutAccountBlock,
    DeleteAccountBlock,
    Info,
    Config,
    ExportIam,
    ExportIamSecrets,
    ImportIam,
    RotateRootKey,
}

/// One endpoint.
#[derive(Debug)]
pub(crate) struct Endpoint {
    pub(crate) api: Api,
    pub(crate) verb: Verb,
    pub(crate) path: &'static str,
    pub(crate) needs: Needs,
    handler: Handler,
}

/// The account resource S3 Control's account-wide actions are decided on.
const ACCOUNT: &str = teifs_policy::S3_ACCOUNT_RESOURCE;

/// The resource of the admin API's actions, which are about the server, not a resource.
const ANY: &str = "*";

/// Everything served besides S3's operations.
pub(crate) static ENDPOINTS: &[Endpoint] = &[
    Endpoint {
        api: Api::Query,
        verb: Verb::Post,
        path: "/",
        needs: Needs::PerCall,
        handler: Handler::Query,
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Get,
        path: control::PUBLIC_ACCESS_BLOCK,
        needs: Needs::Action("s3:GetAccountPublicAccessBlock", ACCOUNT),
        handler: Handler::GetAccountBlock,
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Put,
        path: control::PUBLIC_ACCESS_BLOCK,
        needs: Needs::Action("s3:PutAccountPublicAccessBlock", ACCOUNT),
        handler: Handler::PutAccountBlock,
    },
    // AWS decides deleting with the permission to put.
    Endpoint {
        api: Api::Control,
        verb: Verb::Delete,
        path: control::PUBLIC_ACCESS_BLOCK,
        needs: Needs::Action("s3:PutAccountPublicAccessBlock", ACCOUNT),
        handler: Handler::DeleteAccountBlock,
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_INFO,
        needs: Needs::Action("teifs:GetServerInfo", ANY),
        handler: Handler::Info,
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_CONFIG,
        needs: Needs::Action("teifs:GetServerConfig", ANY),
        handler: Handler::Config,
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_IAM,
        needs: Needs::Action("teifs:ExportIAM", ANY),
        handler: Handler::ExportIam,
    },
    // Secrets, and an import that sets them and may take another account's id: the
    // root user's alone.
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_IAM_SECRETS,
        needs: Needs::Root,
        handler: Handler::ExportIamSecrets,
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Put,
        path: ADMIN_IAM,
        needs: Needs::Root,
        handler: Handler::ImportIam,
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Post,
        path: ADMIN_ROOT_KEY,
        needs: Needs::Root,
        handler: Handler::RotateRootKey,
    },
];

/// One endpoint, as [`endpoints`] describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointInfo {
    /// Its HTTP method.
    pub method: &'static str,
    /// Its path.
    pub path: &'static str,
    /// The action it needs; none when each call names its own (IAM and STS) or only the
    /// root user may call it.
    pub action: Option<&'static str>,
    /// Whether only the root user may call it.
    pub root_only: bool,
    /// Its API.
    pub api: Api,
}

/// Everything TeiFS serves besides S3's operations.
pub fn endpoints() -> impl Iterator<Item = EndpointInfo> {
    ENDPOINTS.iter().map(|e| EndpointInfo {
        method: match e.verb {
            Verb::Get => "GET",
            Verb::Put => "PUT",
            Verb::Post => "POST",
            Verb::Delete => "DELETE",
        },
        path: e.path,
        action: match e.needs {
            Needs::Action(action, _) => Some(action),
            Needs::PerCall | Needs::Root => None,
        },
        root_only: e.needs == Needs::Root,
        api: e.api,
    })
}

/// Which API a request is for, if it isn't an S3 operation; `domains` are those of
/// virtual-hosted-style requests.
fn api_of(method: &Method, uri: &Uri, headers: &HeaderMap, domains: &[String]) -> Option<Api> {
    let path = uri.path();
    if iam_api::is_form_post(method, uri, headers) {
        Some(Api::Query)
    } else if headers.contains_key(control::ACCOUNT_HEADER) && path.starts_with(control::PREFIX) {
        Some(Api::Control)
    } else if path.starts_with(ADMIN_PREFIX) && !admin::is_virtual_hosted(headers, domains) {
        Some(Api::Admin)
    } else {
        None
    }
}

/// The endpoint a request is for, among its API's.
fn endpoint(api: Api, method: &Method, path: &str) -> Option<&'static Endpoint> {
    let verb = Verb::of(method)?;
    ENDPOINTS
        .iter()
        .find(|e| e.api == api && e.verb == verb && e.path == path)
}

/// The route s3s hands everything but S3's operations to.
pub(crate) struct Routes {
    pub(crate) iam: Arc<Iam>,
    pub(crate) store: Store,
    pub(crate) rules: Arc<Rules>,
    /// The domains of virtual-hosted-style requests.
    pub(crate) domains: Vec<String>,
    /// When the service was built: the server's start, as the admin API reports it.
    pub(crate) started: SystemTime,
    /// How the server was started, for the admin API.
    pub(crate) config: Option<Arc<ServerConfig>>,
    /// Where the root key is kept, if the admin API may replace it.
    pub(crate) root_keys: Option<Arc<dyn admin::RootKeyStore>>,
}

#[async_trait::async_trait]
impl S3Route for Routes {
    fn is_match(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        _: &mut http::Extensions,
    ) -> bool {
        api_of(method, uri, headers, &self.domains).is_some()
    }

    /// Everything is decided in [`Self::call`], where each API answers in its format.
    async fn check_access(&self, _: &mut S3Request<Body>) -> S3Result<()> {
        Ok(())
    }

    async fn call(&self, req: S3Request<Body>) -> S3Result<S3Response<Body>> {
        let api = api_of(&req.method, &req.uri, &req.headers, &self.domains)
            .expect("matched by is_match");
        // Each API answers errors in its own format.
        Ok(match api {
            Api::Query => iam_api::serve(&self.iam, req).await,
            Api::Control => self
                .serve(api, req)
                .await
                .unwrap_or_else(|err| control::error_response(&err)),
            Api::Admin => self
                .serve(api, req)
                .await
                .unwrap_or_else(|err| admin::error_response(&err)),
        })
    }
}

impl Routes {
    /// Authenticates, finds the endpoint, decides whether the caller may call it, and
    /// calls it.
    async fn serve(&self, api: Api, req: S3Request<Body>) -> S3Result<S3Response<Body>> {
        let identity = self.authenticate(&req)?;
        // Temporary credentials that may not use IAM (`GetSessionToken`'s, federated
        // users') may not manage the drive either.
        if api == Api::Admin && identity.session().is_some_and(|s| !s.may_manage()) {
            return Err(denied());
        }
        let endpoint = endpoint(api, &req.method, req.uri.path()).ok_or_else(|| match api {
            Api::Admin => admin::not_found(),
            Api::Control | Api::Query => S3Error::with_message(
                S3ErrorCode::NotImplemented,
                "TeiFS serves the account's Block Public Access from S3 Control, and nothing \
                 else yet.",
            ),
        })?;
        let allowed = match endpoint.needs {
            Needs::Action(action, resource) => {
                let client = req.extensions.get::<Client>().copied().unwrap_or_default();
                let context = base_context(&identity, &req.headers, client, &self.iam.account());
                identity
                    .decide(&context, action, resource, None)
                    .is_allowed()
            }
            Needs::Root => identity.is_root(),
            Needs::PerCall => false,
        };
        if !allowed {
            return Err(denied());
        }
        if api == Api::Control {
            control::check_account(&req.headers, &self.iam.account())?;
        }
        match endpoint.handler {
            Handler::GetAccountBlock => control::get_public_access_block(&self.store).await,
            Handler::PutAccountBlock => {
                control::put_public_access_block(&self.store, &self.rules, req).await
            }
            Handler::DeleteAccountBlock => {
                control::delete_public_access_block(&self.store, &self.rules).await
            }
            Handler::Info => Ok(admin::info(&self.store, &self.iam, self.started)),
            Handler::Config => admin::config(self.config.as_deref()),
            Handler::ExportIam => Ok(admin::export(&self.iam, false)),
            Handler::ExportIamSecrets => Ok(admin::export(&self.iam, true)),
            Handler::ImportIam => admin::import(&self.iam, req).await,
            Handler::RotateRootKey => {
                admin::rotate_root_key(&self.iam, self.root_keys.as_ref()).await
            }
            Handler::Query => unreachable!("the Query APIs are served by iam_api"),
        }
    }

    /// Who signed a request: refused when unsigned, or signed with a key IAM doesn't
    /// know (one deleted since the signature was checked, say) or a session that's over.
    fn authenticate(&self, req: &S3Request<Body>) -> S3Result<Arc<Identity>> {
        let credentials = req.credentials.as_ref().ok_or_else(denied)?;
        let token = crate::access::security_token(&req.headers, &req.uri);
        crate::access::identify(&self.iam, &credentials.access_key, token.as_deref())
    }
}

fn denied() -> S3Error {
    s3s::s3_error!(AccessDenied, "Access Denied")
}

/// Why a request's body can't be used.
pub(crate) type Refusal = (StatusCode, &'static str, &'static str);

/// A body that ended before its length.
pub(crate) const INCOMPLETE: Refusal = (
    StatusCode::BAD_REQUEST,
    "IncompleteBody",
    "You did not provide the number of bytes specified by the Content-Length HTTP header.",
);

/// A body that isn't what the signature's `x-amz-content-sha256` says.
pub(crate) const NOT_SIGNED: Refusal = (
    StatusCode::FORBIDDEN,
    "SignatureDoesNotMatch",
    "The request's body isn't the one its signature covers.",
);

/// Why a body couldn't be read: too large, stalled, or else `otherwise`.
pub(crate) fn unreadable(
    err: &(dyn std::error::Error + Send + Sync + 'static),
    otherwise: Refusal,
) -> Refusal {
    let err: &(dyn std::error::Error + 'static) = err;
    let too_large = std::iter::successors(Some(err), |e| e.source()).any(|e| {
        e.is::<s3s::BodySizeLimitExceeded>() || e.is::<http_body_util::LengthLimitError>()
    });
    if too_large {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "EntityTooLarge",
            "The request body is larger than this API accepts.",
        )
    } else if crate::limits::is_stalled(err) {
        (
            StatusCode::BAD_REQUEST,
            "RequestTimeout",
            "Your socket connection to the server was not read from or written to within the \
             timeout period.",
        )
    } else {
        otherwise
    }
}

/// A route's whole body, at most `limit` bytes, and only if it's the body the signature
/// covers: s3s checks a hash it was given while the body is read, and this checks it
/// again, so `UNSIGNED-PAYLOAD` or a hash s3s didn't check is refused too.
pub(crate) async fn signed_body(req: &mut S3Request<Body>, limit: usize) -> Result<Bytes, Refusal> {
    let body = req
        .input
        .store_all_limited(limit)
        .await
        .map_err(|err| unreadable(err.as_ref(), NOT_SIGNED))?;
    let signed = req
        .headers
        .get(iam_api::CONTENT_SHA256)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|hash| hash.eq_ignore_ascii_case(&iam_api::sha256_hex(&body)));
    if signed { Ok(body) } else { Err(NOT_SIGNED) }
}

/// A refusal as an S3 error, for the APIs that answer in S3's format.
pub(crate) fn s3_refusal((status, code, message): Refusal) -> S3Error {
    let mut err = S3Error::with_message(S3ErrorCode::Custom(code.into()), message);
    err.set_status_code(status);
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    http::HeaderName::from_static(k),
                    http::HeaderValue::from_str(v).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn requests_are_told_apart_before_they_are_read() {
        let form = headers(&[("content-type", "application/x-www-form-urlencoded")]);
        let account = headers(&[("x-amz-account-id", "123456789012")]);
        let uri = |s: &str| s.parse::<Uri>().unwrap();
        let block = uri(control::PUBLIC_ACCESS_BLOCK);
        let domains = ["localhost".to_owned()];
        let api = |method: &Method, uri: &Uri, headers: &HeaderMap| {
            api_of(method, uri, headers, &domains)
        };
        assert_eq!(api(&Method::POST, &uri("/"), &form), Some(Api::Query));
        assert_eq!(api(&Method::GET, &block, &account), Some(Api::Control));
        assert_eq!(
            api(&Method::GET, &uri("/v20180820/other"), &account),
            Some(Api::Control)
        );
        // Without the header, it's a bucket named v20180820 and its keys.
        assert_eq!(api(&Method::GET, &block, &HeaderMap::new()), None);
        assert_eq!(api(&Method::GET, &uri("/bucket/key"), &account), None);
        assert_eq!(api(&Method::GET, &uri("/"), &form), None);
        // The admin API, unless the host names a bucket: then it's that bucket's key.
        let info = uri(ADMIN_INFO);
        let path_style = headers(&[("host", "localhost:9000")]);
        let bucket = headers(&[("host", "photos.localhost:9000")]);
        assert_eq!(api(&Method::GET, &info, &path_style), Some(Api::Admin));
        assert_eq!(
            api(
                &Method::DELETE,
                &uri("/.teifs/admin/v1/x"),
                &HeaderMap::new()
            ),
            Some(Api::Admin)
        );
        assert_eq!(api(&Method::GET, &info, &bucket), None);
        let key = uri("/photos/.teifs/admin/v1/info");
        assert_eq!(api(&Method::GET, &key, &path_style), None);
        assert_eq!(
            api(&Method::GET, &uri("/.teifs/admin/v2/info"), &path_style),
            None
        );
    }

    #[test]
    fn every_endpoint_is_found_and_says_what_it_needs() {
        for (e, info) in ENDPOINTS.iter().zip(endpoints()) {
            let method = Method::from_bytes(info.method.as_bytes()).unwrap();
            assert_eq!(Verb::of(&method), Some(e.verb));
            let found = endpoint(e.api, &method, e.path).unwrap();
            assert!(std::ptr::eq(found, e), "{e:?} is shadowed");
            match e.needs {
                Needs::PerCall => assert_eq!(e.api, Api::Query),
                Needs::Root => assert_ne!(e.api, Api::Query),
                Needs::Action(action, resource) => {
                    assert!(action.contains(':') && !resource.is_empty(), "{e:?}");
                    let service = if e.api == Api::Admin { "teifs:" } else { "s3:" };
                    assert!(action.starts_with(service), "{e:?}");
                }
            }
        }
        assert!(endpoint(Api::Control, &Method::PATCH, control::PUBLIC_ACCESS_BLOCK).is_none());
        assert!(endpoint(Api::Control, &Method::GET, "/v20180820/other").is_none());
    }
}
