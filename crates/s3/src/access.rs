//! Who may do what. With IAM, a request is signed with a key IAM knows ([`Auth`]) or not
//! signed at all (anonymous), and before the operation runs, [`Access`] decides every
//! permission the operation needs (`teifs_policy::authorizations`) against the caller's
//! policies and the bucket's policy, under the bucket's Block Public Access settings
//! ([`BucketRules`]). What no policy allows or denies, a bucket's or an object's ACL may
//! still allow, where the bucket's Object Ownership enables ACLs. The decision reads only what TeiFS knows about the request: its
//! operation, the bucket and key s3s parsed, the headers and query the condition keys
//! name, and the connection ([`Client`]).
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
use teifs_iam::{AuthError, Iam, Identity};
use teifs_policy::{
    Authorization, Context, Date, Decision, Facts, Number, PrincipalKind, S3_ACCOUNT_RESOURCE,
    S3Key, TagKind, Target, bucket_arn, object_arn,
};
use teifs_store::{Store, StoreError};

use crate::{
    acl::{self, AclOf},
    bucket_access::{BucketRules, Rules},
    caps::Caps,
    drive::REGION,
    errors::from_store,
    post_form::{self, Form},
    tagging,
};

/// Where a request came from, which the server records in the request's extensions
/// (`aws:SourceIp`, `aws:SecureTransport`): its connection's, or what a trusted proxy
/// says of its client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Client {
    /// The client's address.
    pub ip: Option<IpAddr>,
    /// Whether it came over TLS.
    pub secure: bool,
    /// The TLS version it connected with, `1.2` or `1.3` (`s3:TlsVersion`): none over
    /// plain HTTP, or when a proxy names a client whose connection it can't vouch for.
    pub tls: Option<&'static str>,
}

/// Looks up signing secrets in IAM.
pub(crate) struct Auth(pub(crate) Arc<Iam>);

#[async_trait::async_trait]
impl S3Auth for Auth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        self.0
            .secret(access_key)
            .map(|secret| SecretKey::from(secret.as_str().to_owned()))
            .ok_or_else(|| s3_error!(InvalidAccessKeyId))
    }
}

/// The header, query parameter and form field that carry temporary credentials' session
/// token.
const TOKEN: &str = "x-amz-security-token";
const TOKEN_QUERY: &str = "X-Amz-Security-Token";

/// The session token sent with a request: the `x-amz-security-token` header, or a
/// presigned URL's `X-Amz-Security-Token` (or, as Signature V2 presigns it,
/// `x-amz-security-token`).
pub(crate) fn security_token(headers: &http::HeaderMap, uri: &http::Uri) -> Option<String> {
    headers
        .get(TOKEN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| query_param(uri.query(), TOKEN_QUERY))
        .or_else(|| query_param(uri.query(), TOKEN))
}

/// Who signed a request with `access_key` and `token`, as S3 refuses it if not anyone.
pub(crate) fn identify(
    iam: &Iam,
    access_key: &str,
    token: Option<&str>,
) -> S3Result<Arc<Identity>> {
    iam.identify(access_key, token).map_err(|err| match err {
        AuthError::InvalidToken => s3_error!(
            InvalidToken,
            "The provided token is malformed or otherwise invalid."
        ),
        AuthError::ExpiredToken => s3_error!(ExpiredToken, "The provided token has expired."),
        // A key deleted since its signature was checked, or a session whose user or role
        // is gone, is refused like any other.
        AuthError::UnknownKey | AuthError::Revoked => denied(),
    })
}

/// Decides requests against IAM's policies and the buckets' own.
pub(crate) struct Access {
    iam: Arc<Iam>,
    rules: Arc<Rules>,
    /// Where objects' ACLs are read from.
    store: Store,
    account: Arc<str>,
    anonymous: Arc<Identity>,
}

impl Access {
    pub(crate) fn new(iam: Arc<Iam>, rules: Arc<Rules>, store: Store) -> Self {
        let account = iam.account().into();
        Self {
            iam,
            rules,
            store,
            account,
            anonymous: Arc::new(Identity::anonymous()),
        }
    }

    /// Whether `identity` may do `action` on `arn`: [`allows`], then the ACL of the
    /// object `(bucket, key)` the request is on, if any. `creating`: the request makes the
    /// object (see [`acl_for`]).
    async fn permits(
        &self,
        identity: &Identity,
        context: &Context,
        (action, arn): (&str, &str),
        rules: Option<&BucketRules>,
        object: Option<(&str, &str)>,
        creating: bool,
    ) -> S3Result<bool> {
        let decision = decide(identity, context, action, arn, rules);
        let (Decision::ImplicitDeny, Some(rules)) = (decision, rules) else {
            return Ok(decision.is_allowed());
        };
        if bucket_acl_allows(identity, context, (action, arn), rules, creating) {
            return Ok(true);
        }
        // The object's ACL, read only when the bucket's ACLs apply.
        let (Some((AclOf::Object, permission)), Some((bucket, key))) =
            (acl_for(action, rules, creating), object)
        else {
            return Ok(false);
        };
        let acl = match self.store.head(bucket, key).await {
            Ok(info) => info.attrs.acl,
            Err(StoreError::NoSuchKey | StoreError::NoSuchBucket) => None,
            Err(err) => return Err(from_store(err)),
        };
        Ok(
            acl.is_some_and(|acl| acl.grants(permission, is_signed(identity)))
                && identity.within_boundary(context, action, arn),
        )
    }

    /// For an action AWS decides with an object's own tags, `context` with the tags of the
    /// object `(bucket, key)` as `s3:ExistingObjectTag`s (none when there's no such
    /// object); `None` for other actions. Any other error refuses the request rather than
    /// letting it be decided without them.
    async fn with_existing_tags(
        &self,
        context: &Context,
        action: &str,
        (bucket, key): (&str, &str),
    ) -> S3Result<Option<Context>> {
        if !EXISTING_OBJECT_TAGS.contains(&action) {
            return Ok(None);
        }
        let mut context = context.clone();
        match self.store.head(bucket, key).await {
            Ok(info) => {
                for (name, value) in &info.attrs.tags {
                    context = context.with_tag(TagKind::ExistingObject, name, value);
                }
                Ok(Some(context))
            }
            Err(StoreError::NoSuchKey | StoreError::NoSuchBucket) => Ok(Some(context)),
            Err(err) => Err(from_store(err)),
        }
    }
}

/// The actions AWS decides with the object's own tags (`s3:ExistingObjectTag/…`), as its
/// service authorization reference lists them.
const EXISTING_OBJECT_TAGS: [&str; 23] = [
    "s3:DeleteObjectAnnotation",
    "s3:DeleteObjectTagging",
    "s3:DeleteObjectVersionAnnotation",
    "s3:DeleteObjectVersionTagging",
    "s3:GetObject",
    "s3:GetObjectAcl",
    "s3:GetObjectAnnotation",
    "s3:GetObjectAttributes",
    "s3:GetObjectTagging",
    "s3:GetObjectVersion",
    "s3:GetObjectVersionAcl",
    "s3:GetObjectVersionAnnotation",
    "s3:GetObjectVersionAttributes",
    "s3:GetObjectVersionTagging",
    "s3:ListObjectAnnotations",
    "s3:ListObjectVersionAnnotations",
    "s3:PutObjectAcl",
    "s3:PutObjectAnnotation",
    "s3:PutObjectTagging",
    "s3:PutObjectVersionAcl",
    "s3:PutObjectVersionAnnotation",
    "s3:PutObjectVersionTagging",
    "s3:UpdateObjectEncryption",
];

/// The operations that make the object they name.
const CREATING: [&str; 4] = [
    "PutObject",
    "PostObject",
    "CopyObject",
    "CreateMultipartUpload",
];

/// What only the bucket owner's account may do, and what its root user may always do,
/// whatever the bucket policy says, so a policy can't lock the owner out.
const OWNER_ONLY: [&str; 3] = [
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
];

/// What the policies say about `identity` doing `action` on `resource`, which is in the
/// bucket `rules` describe (`None`: not in a bucket, or one that doesn't exist).
fn decide(
    identity: &Identity,
    context: &Context,
    action: &str,
    resource: &str,
    rules: Option<&BucketRules>,
) -> Decision {
    let Some(rules) = rules else {
        return identity.decide(context, action, resource, None);
    };
    let anonymous = !is_signed(identity);
    if OWNER_ONLY.contains(&action) {
        if identity.is_root() {
            return Decision::Allow;
        }
        if anonymous {
            return Decision::ImplicitDeny;
        }
    }
    match identity.decide(context, action, resource, rules.policy.as_deref()) {
        // Only a policy allows an anonymous request, and `RestrictPublicBuckets` takes
        // that away from a public one; an ACL may still allow it.
        Decision::Allow if anonymous && rules.restricted() => Decision::ImplicitDeny,
        decision => decision,
    }
}

fn is_signed(identity: &Identity) -> bool {
    identity.principal().kind() != PrincipalKind::Anonymous
}

/// The ACL that could allow `action` in a bucket whose ACLs apply. A request that makes
/// an object (`creating`) sets the new object's ACL and tags as part of making it: the
/// bucket's `WRITE`, which allows the object, allows them too, as on AWS.
fn acl_for(
    action: &str,
    rules: &BucketRules,
    creating: bool,
) -> Option<(AclOf, teifs_store::Permission)> {
    let action = match action {
        "s3:PutObjectAcl" | "s3:PutObjectTagging" if creating => "s3:PutObject",
        action => action,
    };
    acl::permission_for(action).filter(|_| rules.acls_apply())
}

/// Whether the bucket's ACL allows an action the policies left undecided.
fn bucket_acl_allows(
    identity: &Identity,
    context: &Context,
    (action, arn): (&str, &str),
    rules: &BucketRules,
    creating: bool,
) -> bool {
    matches!(acl_for(action, rules, creating), Some((AclOf::Bucket, permission))
        if rules.acl.as_ref().is_some_and(|acl| acl.grants(permission, is_signed(identity))))
        && identity.within_boundary(context, action, arn)
}

/// [`decide`], then the bucket's ACL: for what needs no object read.
pub(crate) fn allows(
    identity: &Identity,
    context: &Context,
    action: &str,
    resource: &str,
    rules: Option<&BucketRules>,
) -> bool {
    match decide(identity, context, action, resource, rules) {
        Decision::Allow => true,
        Decision::ExplicitDeny => false,
        Decision::ImplicitDeny => rules.is_some_and(|rules| {
            bucket_acl_allows(identity, context, (action, resource), rules, false)
        }),
    }
}

/// Who a request is from, for the operations: in the request's extensions whenever IAM
/// decides requests.
#[derive(Clone)]
pub(crate) struct Caller {
    identity: Arc<Identity>,
    context: Arc<Context>,
    /// The rules of the bucket the request is on.
    rules: Option<Arc<BucketRules>>,
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
        allows(
            &self.identity,
            &self.context,
            action,
            resource,
            self.rules.as_deref(),
        )
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
        let client = cx
            .extensions_mut()
            .get::<Client>()
            .copied()
            .unwrap_or_default();
        let signed = cx.credentials().is_some();
        with_caps(cx, signed)?;
        let (form, posted) = posted(cx)?;
        let identity = match cx.credentials() {
            None => Arc::clone(&self.anonymous),
            Some(credentials) => {
                let token = form
                    .as_ref()
                    .and_then(|form| form.field(TOKEN))
                    .map(str::to_owned)
                    .or_else(|| security_token(cx.headers(), cx.uri()));
                identify(&self.iam, &credentials.access_key, token.as_deref())?
            }
        };
        let operation = cx.s3_op().name();
        let path = posted.as_ref().unwrap_or_else(|| cx.s3_path());
        let source = source(operation, cx)?;
        let bucket_name = match path {
            S3Path::Bucket { bucket } | S3Path::Object { bucket, .. } => Some(bucket.to_string()),
            S3Path::Root => None,
        };
        // Whoever asks, a bucket owned by another account than the one named is refused.
        if bucket_name.is_some() && operation != "CreateBucket" {
            check_owner(field(cx, form.as_ref(), EXPECTED_OWNER), &self.account)?;
        }
        if source.is_some() {
            check_owner(
                field(cx, form.as_ref(), EXPECTED_SOURCE_OWNER),
                &self.account,
            )?;
        }
        let rules = match &bucket_name {
            Some(bucket) => Some(self.rules.of(bucket).await?),
            None => None,
        };
        let source_rules = match &source {
            Some((bucket, ..)) if bucket_name.as_ref() == Some(bucket) => rules.clone(),
            Some((bucket, ..)) => Some(self.rules.of(bucket).await?),
            None => None,
        };
        // The root user is restricted only by a bucket policy, so without one needs no
        // context to decide with.
        let unrestricted = identity.is_root()
            && [&rules, &source_rules]
                .iter()
                .all(|r| r.as_ref().is_none_or(|r| r.policy.is_none()));
        if unrestricted {
            let context = Context::new(identity.principal().clone(), Date::now());
            cx.extensions_mut().insert(Caller {
                identity,
                context: Arc::new(context),
                rules,
                withheld: Vec::new(),
            });
            return Ok(());
        }
        let context = context(&identity, cx, form.as_ref(), client, &self.account, signed)?;
        let facts = facts(cx, form.as_ref(), source.as_ref());
        if operation == "CreateBucket" {
            // Its tags and region are in its body, which conditions may test: decided
            // once that's read.
            cx.extensions_mut().insert(Deferred {
                identity,
                context,
                facts,
                rules,
            });
            return Ok(());
        }
        let asked = Asked {
            operation,
            path,
            source: source.as_ref(),
            rules: rules.as_deref(),
            source_rules: source_rules.as_deref(),
        };
        let withheld = self
            .decide_needs(&identity, &context, &facts, &asked)
            .await?;
        cx.extensions_mut().insert(Caller {
            identity,
            context: Arc::new(context),
            rules,
            withheld,
        });
        Ok(())
    }

    async fn create_bucket(
        &self,
        req: &mut S3Request<s3s::dto::CreateBucketInput>,
    ) -> S3Result<()> {
        let Some(Deferred {
            identity,
            mut context,
            mut facts,
            rules,
        }) = req.extensions.remove::<Deferred>()
        else {
            return Ok(());
        };
        let configuration = req.input.create_bucket_configuration.as_ref();
        let tags = tagging::of_new_bucket(configuration)?;
        for (key, value) in tags.iter().flatten() {
            context = context.with_tag(TagKind::Request, key, value);
        }
        if let Some(location) = configuration.and_then(|c| c.location_constraint.as_ref()) {
            context = context.with(S3Key::LocationConstraint, location.as_str().to_owned());
        }
        facts.bucket_tags = tags.is_some();
        let path = S3Path::bucket(&req.input.bucket);
        let asked = Asked {
            operation: "CreateBucket",
            path: &path,
            source: None,
            rules: rules.as_deref(),
            source_rules: None,
        };
        let withheld = self
            .decide_needs(&identity, &context, &facts, &asked)
            .await?;
        req.extensions.insert(Caller {
            identity,
            context: Arc::new(context),
            rules,
            withheld,
        });
        Ok(())
    }
}

/// Refuses a request whose decision waits on its body and was never made (the
/// operation's own check didn't run): nothing goes ahead undecided.
pub(crate) fn ensure_decided<T>(req: &S3Request<T>) -> S3Result<()> {
    if req.extensions.get::<Deferred>().is_some() {
        return Err(denied());
    }
    Ok(())
}

/// A request decided once its body is read (`CreateBucket`), with what `check` found.
#[derive(Clone)]
struct Deferred {
    identity: Arc<Identity>,
    context: Context,
    facts: Facts,
    rules: Option<Arc<BucketRules>>,
}

/// What a request asks for, to decide it.
struct Asked<'a> {
    operation: &'a str,
    path: &'a S3Path,
    source: Option<&'a Source>,
    rules: Option<&'a BucketRules>,
    source_rules: Option<&'a BucketRules>,
}

impl Access {
    /// Decides every permission the request needs: an error for a required one it
    /// doesn't have, else the optional ones it goes without.
    async fn decide_needs(
        &self,
        identity: &Identity,
        context: &Context,
        facts: &Facts,
        asked: &Asked<'_>,
    ) -> S3Result<Vec<&'static str>> {
        let Asked {
            operation,
            path,
            source,
            rules,
            source_rules,
        } = *asked;
        // An operation with no action is one only the root user may make.
        let needs = teifs_policy::authorizations(operation, facts);
        if needs.is_none() && !identity.is_root() {
            return Err(denied());
        }
        let tests_tags = tests_existing_tags(identity, [rules, source_rules]);
        // A bucket whose tags decide access puts them in the context of what's in it.
        let in_bucket = with_resource_tags(context, rules);
        let in_source = with_resource_tags(context, source_rules);
        let mut withheld = Vec::new();
        for need in needs.iter().flat_map(|needs| needs.iter()) {
            let (bucket, context) = match need.target {
                Target::Source => (source_rules, in_source.as_ref().unwrap_or(context)),
                Target::Account | Target::Other => (None, context),
                Target::Bucket | Target::Object => (rules, in_bucket.as_ref().unwrap_or(context)),
            };
            match resource(need, path, operation, source) {
                Resource::Arn(arn) => {
                    let object = object_of(need.target, path, source);
                    let creating = need.target == Target::Object && CREATING.contains(&operation);
                    let tagged = match object {
                        Some(object) if tests_tags && !creating => {
                            self.with_existing_tags(context, need.action, object)
                                .await?
                        }
                        _ => None,
                    };
                    let allowed = self
                        .permits(
                            identity,
                            tagged.as_ref().unwrap_or(context),
                            (need.action, &arn),
                            bucket,
                            object,
                            creating,
                        )
                        .await?;
                    if !allowed {
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
        Ok(withheld)
    }
}

/// `context` with a bucket's tags as `aws:ResourceTag` and `s3:BucketTag`, when they
/// decide access (ABAC is on and it has some); `None` otherwise.
pub(crate) fn with_resource_tags(
    context: &Context,
    rules: Option<&BucketRules>,
) -> Option<Context> {
    let tags = rules?
        .resource_tags
        .as_ref()
        .filter(|tags| !tags.is_empty())?;
    let mut context = context.clone();
    for (key, value) in tags {
        context =
            context
                .with_tag(TagKind::Resource, key, value)
                .with_tag(TagKind::Bucket, key, value);
    }
    Some(context)
}

/// Checks the upload size caps a request carries ([`Caps`]) and hands them to the
/// operation in the request's extensions.
fn with_caps(cx: &mut S3AccessContext<'_>, signed: bool) -> S3Result<()> {
    let caps = Caps::of(cx.uri().query(), cx.s3_op().name(), signed && is_sig_v4(cx))?;
    if caps != Caps::default() {
        cx.extensions_mut().insert(caps);
    }
    Ok(())
}

/// A browser upload's form and the object it names (its path names only the bucket);
/// `None` for other requests. A browser upload without its form is refused.
fn posted(cx: &mut S3AccessContext<'_>) -> S3Result<(Option<Form>, Option<S3Path>)> {
    if cx.s3_op().name() != "PostObject" {
        return Ok((None, None));
    }
    let form = cx
        .extensions_mut()
        .get::<Form>()
        .cloned()
        .ok_or_else(post_form::too_large)?;
    let path = match (cx.s3_path(), form.key()) {
        (S3Path::Bucket { bucket }, Some(key)) => Some(S3Path::object(bucket, key)),
        _ => None,
    };
    Ok((Some(form), path))
}

/// Whether a policy that decides the request tests an object's own tags, which are then
/// read for the actions AWS decides with them (and only then).
fn tests_existing_tags<'a>(
    identity: &Identity,
    rules: impl IntoIterator<Item = Option<&'a BucketRules>>,
) -> bool {
    identity.tests_tags(TagKind::ExistingObject)
        || rules.into_iter().flatten().any(|rules| {
            rules
                .policy
                .as_deref()
                .is_some_and(|policy| policy.tests_tags(TagKind::ExistingObject))
        })
}

/// The object `(bucket, key)` a need's action is on, if it's one.
fn object_of<'a>(
    target: Target,
    path: &'a S3Path,
    source: Option<&'a Source>,
) -> Option<(&'a str, &'a str)> {
    match (target, path) {
        (Target::Source, _) => source.map(|(bucket, key, _)| (bucket.as_str(), key.as_str())),
        (Target::Object, S3Path::Object { bucket, key }) => Some((bucket.as_ref(), key.as_ref())),
        _ => None,
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

fn facts(cx: &S3AccessContext<'_>, form: Option<&Form>, source: Option<&Source>) -> Facts {
    let has = |name: &str| field(cx, form, name).is_some();
    let is_true =
        |name: &str| field(cx, form, name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let grants = match form {
        Some(form) => GRANTS.iter().any(|name| form.field(name).is_some()),
        None => cx
            .headers()
            .keys()
            .any(|h| h.as_str().starts_with("x-amz-grant-")),
    };
    Facts {
        version_id: query(cx, "versionId").is_some(),
        source_version_id: source.is_some_and(|(_, _, version)| *version),
        tagging: match form {
            Some(form) => form.field("tagging").is_some() || has("x-amz-tagging"),
            None => has("x-amz-tagging"),
        },
        acl: form.map_or_else(|| has("x-amz-acl"), |form| form.acl().is_some()) || grants,
        retention: has("x-amz-object-lock-mode") || has("x-amz-object-lock-retain-until-date"),
        legal_hold: has("x-amz-object-lock-legal-hold"),
        bypass_governance: is_true("x-amz-bypass-governance-retention"),
        object_lock: is_true("x-amz-bucket-object-lock-enabled"),
        ownership: has("x-amz-object-ownership"),
        // In the body: set once it's read (`S3Access::create_bucket`).
        bucket_tags: false,
    }
}

/// The grants a form may carry, as s3s reads them into an upload.
const GRANTS: [&str; 4] = [
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
];

/// The account a request expects its bucket's owner to be.
const EXPECTED_OWNER: &str = "x-amz-expected-bucket-owner";
/// The account a copy expects its source bucket's owner to be.
const EXPECTED_SOURCE_OWNER: &str = "x-amz-source-expected-bucket-owner";

/// Checks an expected bucket owner, if the request names one, as S3 does: it must be an
/// account id (12 digits), and the bucket's (every bucket on a drive is its account's).
fn check_owner(expected: Option<&str>, account: &str) -> S3Result<()> {
    match expected {
        None => Ok(()),
        Some(id) if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_digit()) => {
            let mut err = s3s::S3Error::with_message(
                s3s::S3ErrorCode::Custom("InvalidBucketOwnerAWSAccountID".into()),
                "The value of the expected bucket owner parameter must be an AWS Account ID.",
            );
            err.set_status_code(http::StatusCode::BAD_REQUEST);
            Err(err)
        }
        Some(id) if id == account => Ok(()),
        Some(_) => Err(denied()),
    }
}

/// A request header, or for a browser upload, the form field of that name (its headers
/// say nothing about the object).
fn field<'a>(cx: &'a S3AccessContext<'_>, form: Option<&'a Form>, name: &str) -> Option<&'a str> {
    match form {
        Some(form) => form.field(name),
        None => cx.headers().get(name).and_then(|v| v.to_str().ok()),
    }
}

/// The decoded value of a query parameter.
fn query(cx: &S3AccessContext<'_>, name: &str) -> Option<String> {
    query_param(cx.uri().query(), name)
}

/// The decoded value of the parameter `name` of `query`.
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
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

/// What every signed request's context has, whatever the API: who and when (with the
/// principal's tags and a session's facts), the connection, and the client's
/// `User-Agent` and `Referer`.
pub(crate) fn base_context(
    identity: &Identity,
    headers: &http::HeaderMap,
    client: Client,
    account: &str,
) -> Context {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let mut context = identity
        .context(Date::now())
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
    context
}

/// Everything a condition may test about an S3 request.
fn context(
    identity: &Identity,
    cx: &S3AccessContext<'_>,
    form: Option<&Form>,
    client: Client,
    account: &str,
    signed: bool,
) -> S3Result<Context> {
    let headers = cx.headers();
    let header = |name: &str| field(cx, form, name);
    let mut context = base_context(identity, headers, client, account);
    if let Some(version) = client.tls.and_then(Number::parse) {
        context = context.with(S3Key::TlsVersion, version);
    }
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
    let tags = if let Some(form) = form {
        if let Some(acl) = form.acl() {
            context = context.with(S3Key::Acl, acl.to_owned());
        }
        if signed {
            context = context.with(S3Key::AuthType, "POST".to_owned()).with(
                S3Key::SignatureVersion,
                signature_version(form.signed_v4()).to_owned(),
            );
            if let Some(age) = form.field("x-amz-date").and_then(signature_age) {
                context = context.with(S3Key::SignatureAge, age);
            }
        }
        form.tags()?
    } else {
        if signed {
            context = with_signature(context, cx);
        }
        header("x-amz-tagging")
            .map(tagging::from_header)
            .transpose()?
    };
    for (key, value) in tags.into_iter().flatten() {
        context = context.with_tag(TagKind::RequestObject, &key, &value);
    }
    Ok(context)
}

/// How a signed request was signed (`s3:authType`, `s3:signatureversion`, and for a
/// presigned link `s3:signatureAge`); an anonymous request has none of them.
fn with_signature(mut context: Context, cx: &S3AccessContext<'_>) -> Context {
    let presigned = query(cx, "X-Amz-Signature").is_some() || query(cx, "Signature").is_some();
    let sig_v4 = is_sig_v4(cx);
    // Only presigned requests have an age, as on AWS: a header signature is checked
    // against the clock instead.
    if presigned && let Some(age) = query(cx, "X-Amz-Date").as_deref().and_then(signature_age) {
        context = context.with(S3Key::SignatureAge, age);
    }
    context
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
            signature_version(sig_v4).to_owned(),
        )
}

/// Whether a signed request is signed with Signature V4, in its header or its query.
fn is_sig_v4(cx: &S3AccessContext<'_>) -> bool {
    query(cx, "X-Amz-Algorithm").is_some()
        || cx
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.starts_with("AWS4-"))
}

/// `s3:signatureAge`: the milliseconds since `signed` (Signature V4's
/// `YYYYMMDDTHHMMSSZ`), none when it isn't that. A date ahead of the clock, which the
/// signature check allows within its skew, is no age at all.
fn signature_age(signed: &str) -> Option<Number> {
    let signed = amz_date(signed)?;
    let age = Date::now().millis_since(signed).max(0);
    Some(Number::from_int(age))
}

/// A Signature V4 date, `20260929T123000Z`.
fn amz_date(text: &str) -> Option<Date> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' || !digits(0..8) || !digits(9..15)
    {
        return None;
    }
    Date::parse(&format!(
        "{}-{}-{}T{}:{}:{}Z",
        &text[0..4],
        &text[4..6],
        &text[6..8],
        &text[9..11],
        &text[11..13],
        &text[13..15]
    ))
}

/// `s3:signatureversion` for Signature V4 or V2.
const fn signature_version(v4: bool) -> &'static str {
    if v4 { "AWS4-HMAC-SHA256" } else { "AWS" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_drives_account_owns_its_buckets() {
        let account = "123456789012";
        assert!(check_owner(None, account).is_ok());
        assert!(check_owner(Some(account), account).is_ok());
        let other = check_owner(Some("210987654321"), account).unwrap_err();
        assert_eq!(*other.code(), s3s::S3ErrorCode::AccessDenied);
        for invalid in [
            "",
            "12345678901",
            "1234567890123",
            "12345678901a",
            " 123456789012",
        ] {
            let err = check_owner(Some(invalid), account).unwrap_err();
            assert_eq!(
                err.status_code(),
                Some(http::StatusCode::BAD_REQUEST),
                "{invalid:?}"
            );
            assert_eq!(err.code().as_str(), "InvalidBucketOwnerAWSAccountID");
        }
    }

    #[test]
    fn signature_v4_dates_give_an_age() {
        assert_eq!(
            amz_date("20260929T123005Z"),
            Date::parse("2026-09-29T12:30:05Z")
        );
        for bad in [
            "",
            "2026-09-29T12:30:05Z",
            "20260929T123005",
            "20260929 123005Z",
            "20260929T12300aZ",
            "20261329T123005Z",
            "20260929T123005Zx",
        ] {
            assert_eq!(amz_date(bad), None, "{bad:?}");
        }
        let age = |secs: i64| {
            let then = Date::now().unix_seconds() - i128::from(secs);
            let text = Date::from_unix_seconds(i64::try_from(then).unwrap()).to_string();
            let compact: String = text.chars().filter(|c| *c != '-' && *c != ':').collect();
            signature_age(&compact).and_then(Number::whole)
        };
        let ten_minutes = age(600).unwrap();
        assert!((600_000..605_000).contains(&ten_minutes), "{ten_minutes}");
        // Ahead of the clock is no age, not a negative one.
        assert_eq!(age(-300), Some(0));
        assert_eq!(signature_age("yesterday"), None);
    }

    #[test]
    fn session_tokens_come_from_the_header_or_a_presigned_query() {
        let uri = |text: &str| text.parse::<http::Uri>().unwrap();
        let mut headers = http::HeaderMap::new();
        assert_eq!(security_token(&headers, &uri("/b/k?x-id=GetObject")), None);
        assert_eq!(
            security_token(&headers, &uri("/b/k?X-Amz-Security-Token=a%2Bb%2Fc%3D&x=1")).as_deref(),
            Some("a+b/c=")
        );
        assert_eq!(
            security_token(&headers, &uri("/b/k?x-amz-security-token=v2")).as_deref(),
            Some("v2")
        );
        headers.insert(TOKEN, http::HeaderValue::from_static("from+header="));
        assert_eq!(
            security_token(&headers, &uri("/b/k?X-Amz-Security-Token=query")).as_deref(),
            Some("from+header=")
        );
    }
}
