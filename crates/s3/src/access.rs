//! Who may do what. With IAM, a request is signed with a key IAM knows ([`Auth`]), and
//! before the operation runs, [`Access`] decides every permission the operation needs
//! (`teifs_policy::authorizations`) against the signer's policies. The decision reads
//! only what TeiFS knows about the request: its operation, the bucket and key s3s parsed,
//! the headers and query the condition keys name, and the connection ([`Client`]).
//!
//! What's checked is what's acted on: copy and rename sources are parsed by the same
//! functions the operations use. Permissions that only add to a response (the tag count
//! of a `GetObject`) are decided here too and kept in the [`Caller`] the operations read.

use std::{net::IpAddr, sync::Arc};

use s3s::{
    S3Request, S3Result,
    access::{S3Access, S3AccessContext},
    auth::{S3Auth, SecretKey},
    dto::CopySource,
    path::S3Path,
    s3_error,
};
use teifs_iam::{Iam, Identity};
use teifs_policy::{
    Authorization, Context, Date, Facts, Number, S3_ACCOUNT_RESOURCE, S3Key, TagKind, Target,
    bucket_arn, object_arn,
};

use crate::{drive::REGION, tagging};

/// The connection a request came in on, which the server records in the request's
/// extensions (`aws:SourceIp`, `aws:SecureTransport`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Client {
    /// The peer's address.
    pub ip: Option<IpAddr>,
    /// Whether the connection is TLS.
    pub secure: bool,
}

/// Looks up signing secrets in IAM.
pub(crate) struct Auth(pub(crate) Arc<Iam>);

#[async_trait::async_trait]
impl S3Auth for Auth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        self.0
            .credential(access_key)
            .map(|c| SecretKey::from(c.secret.as_str().to_owned()))
            .ok_or_else(|| s3_error!(InvalidAccessKeyId))
    }
}

/// Decides requests against IAM's policies.
pub(crate) struct Access {
    iam: Arc<Iam>,
    account: Arc<str>,
}

impl Access {
    pub(crate) fn new(iam: Arc<Iam>) -> Self {
        let account = iam.account().into();
        Self { iam, account }
    }
}

/// Who a request is from, for the operations: in the request's extensions whenever IAM
/// decides requests.
#[derive(Clone)]
pub(crate) struct Caller {
    identity: Arc<Identity>,
    context: Arc<Context>,
    /// The permissions the request may go without that it doesn't have.
    withheld: Vec<&'static str>,
}

impl Caller {
    /// The id uploads are owned by: `aws:userid` (the account id for root, a user's
    /// unique id).
    pub(crate) fn id(&self) -> &str {
        self.identity.principal().user_id()
    }

    /// Whether this is the account's root user.
    pub(crate) fn is_root(&self) -> bool {
        self.identity.is_root()
    }

    /// Whether the caller may do `action` on `resource` (for operations that name
    /// several objects, such as `DeleteObjects`).
    pub(crate) fn allows(&self, action: &str, resource: &str) -> bool {
        self.identity.allows(&self.context, action, resource)
    }

    /// Whether the request has an optional permission (`s3:GetObjectTagging` for the tag
    /// count of a `GetObject`).
    pub(crate) fn may(&self, action: &str) -> bool {
        !self.withheld.contains(&action)
    }
}

/// The caller of a request IAM decided, if IAM decides requests.
pub(crate) fn caller<T>(req: &S3Request<T>) -> Option<&Caller> {
    req.extensions.get::<Caller>()
}

/// Whether the caller may use an optional permission: always without IAM.
pub(crate) fn may<T>(req: &S3Request<T>, action: &str) -> bool {
    caller(req).is_none_or(|c| c.may(action))
}

/// AWS answers a read of a missing key with 403 to whoever may not list the bucket, so
/// keys can't be probed for.
pub(crate) fn hide_missing(
    caller: Option<&Caller>,
    bucket: &str,
    err: s3s::S3Error,
) -> s3s::S3Error {
    let hidden = *err.code() == s3s::S3ErrorCode::NoSuchKey
        && caller.is_some_and(|c| !c.allows("s3:ListBucket", &bucket_arn(bucket)));
    if hidden { denied() } else { err }
}

fn denied() -> s3s::S3Error {
    s3_error!(AccessDenied, "Access Denied")
}

#[async_trait::async_trait]
impl S3Access for Access {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        // Unsigned requests are for bucket policies, which come later; until then only
        // signed requests get anywhere.
        let access_key = cx.credentials().ok_or_else(denied)?.access_key.clone();
        // A key deleted since its signature was checked is refused like any other.
        let identity = self
            .iam
            .credential(&access_key)
            .ok_or_else(denied)?
            .identity;
        let client = cx
            .extensions_mut()
            .get::<Client>()
            .copied()
            .unwrap_or_default();
        let mut withheld = Vec::new();
        // The root user is never restricted, so needs no context to decide with.
        let context = if identity.is_root() {
            Context::new(identity.principal().clone(), Date::now())
        } else {
            let operation = cx.s3_op().name();
            let source = source(operation, cx)?;
            let context = context(&identity, cx, client, &self.account)?;
            let facts = facts(cx, source.as_ref());
            // An operation with no action is one only the root user may make.
            let needs = teifs_policy::authorizations(operation, &facts).ok_or_else(denied)?;
            for need in needs.iter() {
                match resource(need, cx.s3_path(), operation, source.as_ref()) {
                    Resource::Arn(arn) => {
                        if !identity.allows(&context, need.action, &arn) {
                            if need.required {
                                return Err(denied());
                            }
                            withheld.push(need.action);
                        }
                    }
                    // Decided per object by the operation.
                    Resource::PerObject => {}
                    Resource::Unknown if need.required => return Err(denied()),
                    Resource::Unknown => withheld.push(need.action),
                }
            }
            context
        };
        cx.extensions_mut().insert(Caller {
            identity,
            context: Arc::new(context),
            withheld,
        });
        Ok(())
    }
}

/// The object a copy or rename reads from: (bucket, key, whether a version is named).
type Source = (String, String, bool);

fn source(operation: &str, cx: &S3AccessContext<'_>) -> S3Result<Option<Source>> {
    let header = |name: &str| cx.headers().get(name).and_then(|v| v.to_str().ok());
    match operation {
        "CopyObject" | "UploadPartCopy" => {
            let Some(value) = header("x-amz-copy-source") else {
                return Ok(None);
            };
            match CopySource::parse(value) {
                Ok(CopySource::Bucket {
                    bucket,
                    key,
                    version_id,
                }) => Ok(Some((bucket.into(), key.into(), version_id.is_some()))),
                // Access points and outposts aren't TeiFS's; the operation refuses them.
                _ => Ok(None),
            }
        }
        "RenameObject" => {
            let (Some(value), S3Path::Object { bucket, .. }) =
                (header("x-amz-rename-source"), cx.s3_path())
            else {
                return Ok(None);
            };
            let key = crate::drive::rename_source(value, bucket)?;
            Ok(Some((bucket.to_string(), key, false)))
        }
        _ => Ok(None),
    }
}

/// What a permission is decided for.
enum Resource {
    Arn(String),
    /// The operation names its objects in its body (`DeleteObjects`) and decides each.
    PerObject,
    /// Nothing TeiFS can name: refused when required.
    Unknown,
}

fn resource(
    need: &Authorization,
    path: &S3Path,
    operation: &str,
    source: Option<&Source>,
) -> Resource {
    match (need.target, path) {
        (Target::Account, _) => Resource::Arn(S3_ACCOUNT_RESOURCE.to_owned()),
        (Target::Bucket, S3Path::Bucket { bucket } | S3Path::Object { bucket, .. }) => {
            Resource::Arn(bucket_arn(bucket))
        }
        (Target::Object, S3Path::Object { bucket, key }) => Resource::Arn(object_arn(bucket, key)),
        (Target::Object, S3Path::Bucket { .. }) if operation == "DeleteObjects" => {
            Resource::PerObject
        }
        // A permission on the objects of a bucket-level request (who may see owners in a
        // listing) is decided for the bucket's objects as a whole.
        (Target::Object, S3Path::Bucket { bucket }) if !need.required => {
            Resource::Arn(object_arn(bucket, ""))
        }
        (Target::Source, _) => source.map_or(Resource::Unknown, |(bucket, key, _)| {
            Resource::Arn(object_arn(bucket, key))
        }),
        _ => Resource::Unknown,
    }
}

fn facts(cx: &S3AccessContext<'_>, source: Option<&Source>) -> Facts {
    let has = |name: &str| cx.headers().contains_key(name);
    let is_true = |name: &str| {
        cx.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    };
    Facts {
        version_id: query(cx, "versionId").is_some(),
        source_version_id: source.is_some_and(|(_, _, version)| *version),
        tagging: has("x-amz-tagging"),
        acl: has("x-amz-acl")
            || cx
                .headers()
                .keys()
                .any(|h| h.as_str().starts_with("x-amz-grant-")),
        retention: has("x-amz-object-lock-mode") || has("x-amz-object-lock-retain-until-date"),
        legal_hold: has("x-amz-object-lock-legal-hold"),
        bypass_governance: is_true("x-amz-bypass-governance-retention"),
        object_lock: is_true("x-amz-bucket-object-lock-enabled"),
        ownership: has("x-amz-object-ownership"),
    }
}

/// The decoded value of a query parameter.
fn query(cx: &S3AccessContext<'_>, name: &str) -> Option<String> {
    let text = cx.uri().query()?;
    text.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| {
            crate::drive::urlencoding_decode(&value.replace('+', " "))
                .unwrap_or_else(|_| value.to_owned())
        })
    })
}

/// Headers that are S3 condition keys as they are.
const HEADER_KEYS: &[(&str, S3Key)] = &[
    ("x-amz-acl", S3Key::Acl),
    ("x-amz-grant-full-control", S3Key::GrantFullControl),
    ("x-amz-grant-read", S3Key::GrantRead),
    ("x-amz-grant-read-acp", S3Key::GrantReadAcp),
    ("x-amz-grant-write", S3Key::GrantWrite),
    ("x-amz-grant-write-acp", S3Key::GrantWriteAcp),
    ("x-amz-copy-source", S3Key::CopySource),
    ("x-amz-metadata-directive", S3Key::MetadataDirective),
    ("x-amz-server-side-encryption", S3Key::ServerSideEncryption),
    (
        "x-amz-server-side-encryption-aws-kms-key-id",
        S3Key::ServerSideEncryptionKmsKeyId,
    ),
    (
        "x-amz-server-side-encryption-customer-algorithm",
        S3Key::ServerSideEncryptionCustomerAlgorithm,
    ),
    ("x-amz-storage-class", S3Key::StorageClass),
    (
        "x-amz-website-redirect-location",
        S3Key::WebsiteRedirectLocation,
    ),
    ("x-amz-content-sha256", S3Key::ContentSha256),
    ("x-amz-object-lock-mode", S3Key::ObjectLockMode),
    ("x-amz-object-lock-legal-hold", S3Key::ObjectLockLegalHold),
    ("x-amz-object-ownership", S3Key::ObjectOwnership),
    ("if-match", S3Key::IfMatch),
    ("if-none-match", S3Key::IfNoneMatch),
];

/// Query parameters that are S3 condition keys as they are.
const QUERY_KEYS: &[(&str, S3Key)] = &[
    ("prefix", S3Key::Prefix),
    ("delimiter", S3Key::Delimiter),
    ("versionId", S3Key::VersionId),
];

/// What every signed request's context has, whatever the API: who and when, the
/// connection, and the client's `User-Agent` and `Referer`.
pub(crate) fn base_context(
    identity: &Identity,
    headers: &http::HeaderMap,
    client: Client,
    account: &str,
) -> Context {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let mut context = Context::new(identity.principal().clone(), Date::now())
        .with_secure_transport(client.secure)
        .with_region(REGION)
        .with_resource_account(account);
    if let Some(ip) = client.ip {
        context = context.with_source_ip(ip);
    }
    if let Some(agent) = header("user-agent") {
        context = context.with_user_agent(agent);
    }
    if let Some(referer) = header("referer") {
        context = context.with_referer(referer);
    }
    for (key, value) in identity.tags() {
        context = context.with_tag(TagKind::Principal, key, value);
    }
    context
}

/// Everything a condition may test about an S3 request.
fn context(
    identity: &Identity,
    cx: &S3AccessContext<'_>,
    client: Client,
    account: &str,
) -> S3Result<Context> {
    let headers = cx.headers();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let mut context = base_context(identity, headers, client, account);
    for (name, key) in HEADER_KEYS {
        if let Some(value) = header(name) {
            context = context.with(*key, value.to_owned());
        }
    }
    for (name, key) in QUERY_KEYS {
        if let Some(value) = query(cx, name) {
            context = context.with(*key, value);
        }
    }
    if let Some(max) = query(cx, "max-keys").as_deref().and_then(Number::parse) {
        context = context.with(S3Key::MaxKeys, max);
    }
    if let Some(date) = header("x-amz-object-lock-retain-until-date").and_then(Date::parse) {
        context = context.with(S3Key::ObjectLockRetainUntilDate, date);
    }
    let presigned = query(cx, "X-Amz-Signature").is_some() || query(cx, "Signature").is_some();
    let sig_v4 = query(cx, "X-Amz-Algorithm").is_some()
        || header("authorization").is_some_and(|a| a.starts_with("AWS4-"));
    context = context
        .with(
            S3Key::AuthType,
            if presigned {
                "REST-QUERY-STRING"
            } else {
                "REST-HEADER"
            }
            .to_owned(),
        )
        .with(
            S3Key::SignatureVersion,
            if sig_v4 { "AWS4-HMAC-SHA256" } else { "AWS" }.to_owned(),
        );
    if let Some(value) = header("x-amz-tagging") {
        for (key, value) in tagging::from_header(value)? {
            context = context.with_tag(TagKind::RequestObject, &key, &value);
        }
    }
    Ok(context)
}
