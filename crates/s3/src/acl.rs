//! ACLs over S3: canned ACLs, `x-amz-grant-*` headers and `AccessControlPolicy` bodies
//! read into an [`Acl`], answers written from one, the rules Object Ownership and Block
//! Public Access set for ACL writes, and which action each ACL permission allows.

use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use teifs_store::{
    Acl, AclGrant, Grantee, NewBucket, OWNER_ID, ObjectOwnership, Permission, PublicAccessBlock,
};

/// The ACL-related parts of a request that writes an object or a bucket.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AclHeaders<'a> {
    /// `x-amz-acl`.
    pub(crate) canned: Option<&'a str>,
    pub(crate) full_control: Option<&'a str>,
    pub(crate) read: Option<&'a str>,
    pub(crate) read_acp: Option<&'a str>,
    /// Buckets only.
    pub(crate) write: Option<&'a str>,
    pub(crate) write_acp: Option<&'a str>,
}

/// Fills [`AclHeaders`] from any input that has the ACL headers (`write` only exists on
/// bucket requests).
macro_rules! acl_headers {
    ($input:expr) => {
        $crate::acl::AclHeaders {
            canned: $input.acl.as_ref().map(|a| a.as_str()),
            full_control: $input.grant_full_control.as_deref(),
            read: $input.grant_read.as_deref(),
            read_acp: $input.grant_read_acp.as_deref(),
            write: None,
            write_acp: $input.grant_write_acp.as_deref(),
        }
    };
    ($input:expr, bucket) => {
        $crate::acl::AclHeaders {
            write: $input.grant_write.as_deref(),
            ..acl_headers!($input)
        }
    };
}
pub(crate) use acl_headers;

/// The ACL a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Requested {
    /// None: the default, private.
    Nothing,
    /// A canned ACL, by name, and what it grants.
    Canned(&'static str, Acl),
    /// Explicit grants (headers or a body).
    Grants(Acl),
}

impl Requested {
    /// The ACL to store: none for the default.
    pub(crate) fn into_acl(self) -> Option<Acl> {
        match self {
            Self::Nothing => None,
            Self::Canned(_, acl) | Self::Grants(acl) => Some(acl),
        }
    }

    fn acl(&self) -> Option<&Acl> {
        match self {
            Self::Nothing => None,
            Self::Canned(_, acl) | Self::Grants(acl) => Some(acl),
        }
    }

    /// Whether a bucket with ACLs disabled accepts it on an object write: no ACL, or the
    /// bucket owner's full control (the canned ACL, or the same as explicit grants).
    fn is_bucket_owner_full_control(&self) -> bool {
        match self {
            Self::Nothing => true,
            Self::Canned(name, _) => *name == BUCKET_OWNER_FULL_CONTROL,
            Self::Grants(acl) => *acl == Acl::private(),
        }
    }
}

const BUCKET_OWNER_FULL_CONTROL: &str = "bucket-owner-full-control";

/// The canned ACLs, what each grants besides the owner's full control, and whether it's
/// for objects, buckets or both. In a one-account drive the object's owner is the
/// bucket's, so the `bucket-owner-*` ones are private.
const CANNED: &[(&str, Extra, Applies)] = &[
    ("private", &[], Applies::Both),
    (
        "public-read",
        &[(Grantee::AllUsers, Permission::Read)],
        Applies::Both,
    ),
    (
        "public-read-write",
        &[
            (Grantee::AllUsers, Permission::Read),
            (Grantee::AllUsers, Permission::Write),
        ],
        Applies::Both,
    ),
    (
        "authenticated-read",
        &[(Grantee::AuthenticatedUsers, Permission::Read)],
        Applies::Both,
    ),
    ("aws-exec-read", &[], Applies::Objects),
    ("bucket-owner-read", &[], Applies::Objects),
    (BUCKET_OWNER_FULL_CONTROL, &[], Applies::Objects),
    (
        "log-delivery-write",
        &[
            (Grantee::LogDelivery, Permission::Write),
            (Grantee::LogDelivery, Permission::ReadAcp),
        ],
        Applies::Buckets,
    ),
];

/// What a canned ACL grants besides the owner's full control.
type Extra = &'static [(Grantee, Permission)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applies {
    Objects,
    Buckets,
    Both,
}

/// What a request's headers ask for, on a bucket (`bucket`) or an object.
pub(crate) fn requested(headers: &AclHeaders<'_>, bucket: bool) -> S3Result<Requested> {
    let grants = [
        (headers.full_control, Permission::FullControl),
        (headers.read, Permission::Read),
        (headers.read_acp, Permission::ReadAcp),
        (headers.write, Permission::Write),
        (headers.write_acp, Permission::WriteAcp),
    ];
    let has_grants = grants.iter().any(|(value, _)| value.is_some());
    match (headers.canned, has_grants) {
        (Some(_), true) => Err(s3_error!(
            InvalidRequest,
            "Specifying both Canned ACLs and Header Grants is not allowed"
        )),
        (Some(name), false) => canned(name, bucket),
        (None, true) => {
            let mut acl = Acl { grants: Vec::new() };
            for (value, permission) in grants {
                if let Some(value) = value {
                    for grantee in grantees(value)? {
                        acl.grants.push(AclGrant {
                            grantee,
                            permission,
                        });
                    }
                }
            }
            Ok(Requested::Grants(acl))
        }
        (None, false) => Ok(Requested::Nothing),
    }
}

fn canned(name: &str, bucket: bool) -> S3Result<Requested> {
    let (name, extra, _) = CANNED
        .iter()
        .find(|(known, _, applies)| {
            *known == name
                && match applies {
                    Applies::Both => true,
                    Applies::Objects => !bucket,
                    Applies::Buckets => bucket,
                }
        })
        .ok_or_else(|| s3_error!(InvalidArgument, "`{name}` isn't a canned ACL"))?;
    let mut acl = Acl::private();
    acl.grants
        .extend(extra.iter().map(|&(grantee, permission)| AclGrant {
            grantee,
            permission,
        }));
    Ok(Requested::Canned(name, acl))
}

/// The grantees of an `x-amz-grant-*` header: `id="…"`, `uri="…"` or `emailAddress="…"`,
/// separated by commas.
fn grantees(value: &str) -> S3Result<Vec<Grantee>> {
    value
        .split(',')
        .map(|item| {
            let (kind, text) = item
                .trim()
                .split_once('=')
                .ok_or_else(|| s3_error!(InvalidArgument, "`{item}` isn't a grantee"))?;
            let text = text.trim();
            let text = text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .unwrap_or(text);
            grantee(kind.trim(), text)
        })
        .collect()
}

/// A grantee named by its kind (`id`, `uri`, `emailAddress`) and value.
fn grantee(kind: &str, value: &str) -> S3Result<Grantee> {
    match kind {
        "id" if value == OWNER_ID => Ok(Grantee::Owner),
        "id" => Err(s3_error!(InvalidArgument, "Invalid id")),
        "uri" => {
            Grantee::from_uri(value).ok_or_else(|| s3_error!(InvalidArgument, "Invalid group uri"))
        }
        "emailAddress" => Err(unresolvable_email()),
        _ => Err(s3_error!(
            InvalidArgument,
            "`{kind}` isn't a kind of grantee (id, uri, emailAddress)"
        )),
    }
}

fn unresolvable_email() -> S3Error {
    s3_error!(
        UnresolvableGrantByEmailAddress,
        "The email address you provided does not match any account on record."
    )
}

/// What a `PutBucketAcl` or `PutObjectAcl` asks for: exactly one of a canned ACL, grant
/// headers or an `AccessControlPolicy` body.
pub(crate) fn put_request(
    headers: &AclHeaders<'_>,
    body: Option<dto::AccessControlPolicy>,
    bucket: bool,
) -> S3Result<Requested> {
    let from_headers = requested(headers, bucket)?;
    match (from_headers, body) {
        (Requested::Nothing, None) => Err(s3_error!(
            MissingSecurityHeader,
            "Your request was missing a required header"
        )),
        (Requested::Nothing, Some(body)) => from_body(body).map(Requested::Grants),
        (_, Some(_)) => Err(s3_error!(
            UnexpectedContent,
            "This request does not support content"
        )),
        (requested, None) => Ok(requested),
    }
}

fn from_body(body: dto::AccessControlPolicy) -> S3Result<Acl> {
    if let Some(owner) = body.owner.and_then(|o| o.id)
        && owner != OWNER_ID
    {
        return Err(s3_error!(InvalidArgument, "Invalid id"));
    }
    let grants = body
        .grants
        .unwrap_or_default()
        .into_iter()
        .map(|grant| {
            let (Some(who), Some(permission)) = (grant.grantee, grant.permission) else {
                return Err(malformed_acl());
            };
            let permission = Permission::parse(permission.as_str()).ok_or_else(malformed_acl)?;
            let (kind, value) = match who.type_.as_str() {
                dto::Type::CANONICAL_USER => ("id", who.id),
                dto::Type::GROUP => ("uri", who.uri),
                dto::Type::AMAZON_CUSTOMER_BY_EMAIL => return Err(unresolvable_email()),
                _ => return Err(malformed_acl()),
            };
            Ok(AclGrant {
                grantee: grantee(kind, &value.ok_or_else(malformed_acl)?)?,
                permission,
            })
        })
        .collect::<S3Result<Vec<_>>>()?;
    Ok(Acl { grants })
}

fn malformed_acl() -> S3Error {
    s3_error!(
        MalformedACLError,
        "The XML you provided was not well-formed or did not validate against our published schema"
    )
}

/// The owner, as answers name it.
pub(crate) fn owner() -> dto::Owner {
    dto::Owner {
        display_name: Some(OWNER_ID.to_owned()),
        id: Some(OWNER_ID.to_owned()),
    }
}

/// An ACL's grants, as `GetBucketAcl` and `GetObjectAcl` answer them.
pub(crate) fn to_grants(acl: &Acl) -> dto::Grants {
    acl.grants
        .iter()
        .map(|grant| {
            let grantee = match grant.grantee.uri() {
                None => dto::Grantee {
                    display_name: Some(OWNER_ID.to_owned()),
                    id: Some(OWNER_ID.to_owned()),
                    type_: dto::Type::from_static(dto::Type::CANONICAL_USER),
                    email_address: None,
                    uri: None,
                },
                Some(uri) => dto::Grantee {
                    type_: dto::Type::from_static(dto::Type::GROUP),
                    uri: Some(uri.to_owned()),
                    display_name: None,
                    email_address: None,
                    id: None,
                },
            };
            dto::Grant {
                grantee: Some(grantee),
                permission: Some(dto::Permission::from(grant.permission.name().to_owned())),
            }
        })
        .collect()
}

/// What reading an ACL answers: private while ACLs are disabled, as on AWS.
pub(crate) fn effective(ownership: ObjectOwnership, stored: Option<Acl>) -> Acl {
    stored
        .filter(|_| ownership.acls_enabled())
        .unwrap_or_else(Acl::private)
}

pub(crate) fn not_supported() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("AccessControlListNotSupported".into()),
        "The bucket does not allow ACLs",
    );
    err.set_status_code(http::StatusCode::BAD_REQUEST);
    err
}

pub(crate) fn public_blocked() -> S3Error {
    s3_error!(
        AccessDenied,
        "Access Denied: the bucket's Block Public Access settings (BlockPublicAcls) refuse a \
         public ACL"
    )
}

/// Checks the ACL an object write (`PutObject`, `CopyObject`, `CreateMultipartUpload`) asks
/// for against the bucket's settings, and gives the ACL to store.
pub(crate) fn for_object_write(
    requested: Requested,
    ownership: ObjectOwnership,
    block: PublicAccessBlock,
) -> S3Result<Option<Acl>> {
    if !ownership.acls_enabled() {
        return if requested.is_bucket_owner_full_control() {
            Ok(None)
        } else {
            Err(not_supported())
        };
    }
    check_public(&requested, block)?;
    Ok(requested.into_acl())
}

/// Checks a `PutBucketAcl` or `PutObjectAcl` against the bucket's settings.
pub(crate) fn for_acl_write(
    requested: Requested,
    ownership: ObjectOwnership,
    block: PublicAccessBlock,
) -> S3Result<Acl> {
    if !ownership.acls_enabled() {
        return Err(not_supported());
    }
    check_public(&requested, block)?;
    Ok(requested.into_acl().unwrap_or_else(Acl::private))
}

fn check_public(requested: &Requested, block: PublicAccessBlock) -> S3Result<()> {
    if block.block_public_acls && requested.acl().is_some_and(Acl::is_public) {
        return Err(public_blocked());
    }
    Ok(())
}

/// Checks the ACL a `CreateBucket` asks for against the new bucket's settings: an ACL
/// that grants others needs ACLs enabled, and a public one needs Block Public Access
/// off.
pub(crate) fn for_new_bucket(requested: Requested, new: &NewBucket) -> S3Result<Option<Acl>> {
    let acls_enabled = new.ownership.is_none_or(ObjectOwnership::acls_enabled);
    let acl = requested.into_acl();
    let owner_only = acl.as_ref().is_none_or(Acl::owner_only);
    if !acls_enabled && !owner_only {
        return Err(invalid_with_ownership());
    }
    if new.block_public_access && acl.as_ref().is_some_and(Acl::is_public) {
        let mut err = S3Error::with_message(
            S3ErrorCode::Custom("InvalidBucketAclWithBlockPublicAccessError".into()),
            "Bucket cannot have public ACLs set with BlockPublicAccess enabled",
        );
        err.set_status_code(http::StatusCode::BAD_REQUEST);
        return Err(err);
    }
    Ok(acl.filter(|_| acls_enabled))
}

/// `BucketOwnerEnforced` refused because the bucket's ACL grants someone else.
pub(crate) fn invalid_with_ownership() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("InvalidBucketAclWithObjectOwnership".into()),
        "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
    );
    err.set_status_code(http::StatusCode::BAD_REQUEST);
    err
}

/// `GetBucketOwnershipControls` on a bucket that has no setting.
pub(crate) fn no_ownership_controls() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("OwnershipControlsNotFoundError".into()),
        "The bucket ownership controls were not found",
    );
    err.set_status_code(http::StatusCode::NOT_FOUND);
    err
}

/// Which ACL an action is decided by, as AWS maps ACL permissions to actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclOf {
    Bucket,
    Object,
}

/// The ACL permission that allows `action`, and on what; none for actions ACLs don't
/// grant.
pub(crate) fn permission_for(action: &str) -> Option<(AclOf, Permission)> {
    Some(match action {
        "s3:ListBucket" | "s3:ListBucketVersions" | "s3:ListBucketMultipartUploads" => {
            (AclOf::Bucket, Permission::Read)
        }
        "s3:PutObject" | "s3:DeleteObject" => (AclOf::Bucket, Permission::Write),
        "s3:GetBucketAcl" => (AclOf::Bucket, Permission::ReadAcp),
        "s3:PutBucketAcl" => (AclOf::Bucket, Permission::WriteAcp),
        "s3:GetObject" | "s3:GetObjectVersion" => (AclOf::Object, Permission::Read),
        "s3:GetObjectAcl" | "s3:GetObjectVersionAcl" => (AclOf::Object, Permission::ReadAcp),
        "s3:PutObjectAcl" | "s3:PutObjectVersionAcl" => (AclOf::Object, Permission::WriteAcp),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> AclHeaders<'static> {
        AclHeaders::default()
    }

    fn code<T: std::fmt::Debug>(result: S3Result<T>) -> String {
        result.unwrap_err().code().as_str().to_owned()
    }

    fn grants(acl: &Acl) -> Vec<(Grantee, Permission)> {
        acl.grants
            .iter()
            .map(|g| (g.grantee, g.permission))
            .collect()
    }

    #[test]
    fn canned_acls_expand_for_their_kind() {
        let canned = |name, bucket| {
            requested(
                &AclHeaders {
                    canned: Some(name),
                    ..headers()
                },
                bucket,
            )
        };
        let Requested::Canned("public-read", acl) = canned("public-read", false).unwrap() else {
            panic!("canned");
        };
        assert_eq!(
            grants(&acl),
            [
                (Grantee::Owner, Permission::FullControl),
                (Grantee::AllUsers, Permission::Read)
            ]
        );
        for private in ["private", "bucket-owner-full-control", "bucket-owner-read"] {
            assert_eq!(
                canned(private, false).unwrap().into_acl(),
                Some(Acl::private())
            );
        }
        assert!(canned("log-delivery-write", true).is_ok());
        assert_eq!(code(canned("log-delivery-write", false)), "InvalidArgument");
        assert_eq!(
            code(canned("bucket-owner-full-control", true)),
            "InvalidArgument"
        );
        assert_eq!(code(canned("Public-Read", false)), "InvalidArgument");
        assert_eq!(requested(&headers(), false).unwrap(), Requested::Nothing);
    }

    #[test]
    fn grant_headers_name_the_owner_or_a_group() {
        let acl = requested(
            &AclHeaders {
                full_control: Some(r#"id="teifs""#),
                read: Some(
                    r#"uri="http://acs.amazonaws.com/groups/global/AllUsers", uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers"#,
                ),
                ..headers()
            },
            false,
        )
        .unwrap()
        .into_acl()
        .unwrap();
        assert_eq!(
            grants(&acl),
            [
                (Grantee::Owner, Permission::FullControl),
                (Grantee::AllUsers, Permission::Read),
                (Grantee::AuthenticatedUsers, Permission::Read),
            ]
        );
        let one = |value: &'static str| {
            requested(
                &AclHeaders {
                    read: Some(value),
                    ..headers()
                },
                false,
            )
        };
        assert_eq!(code(one(r#"id="someone-else""#)), "InvalidArgument");
        assert_eq!(
            code(one(r#"uri="http://example.com/x""#)),
            "InvalidArgument"
        );
        assert_eq!(code(one("teifs")), "InvalidArgument");
        assert_eq!(code(one(r#"name="x""#)), "InvalidArgument");
        assert_eq!(
            code(one(r#"emailAddress="a@example.com""#)),
            "UnresolvableGrantByEmailAddress"
        );
        let both = AclHeaders {
            canned: Some("private"),
            read: Some(r#"id="teifs""#),
            ..headers()
        };
        assert_eq!(code(requested(&both, false)), "InvalidRequest");
    }

    #[test]
    fn acl_puts_take_exactly_one_form() {
        let body = |grants: Vec<dto::Grant>, owner: &str| dto::AccessControlPolicy {
            owner: Some(dto::Owner {
                id: Some(owner.to_owned()),
                display_name: None,
            }),
            grants: Some(grants),
        };
        let from = to_grants(&Acl::private());
        let acl = put_request(&headers(), Some(body(from.clone(), OWNER_ID)), false).unwrap();
        assert_eq!(acl.into_acl(), Some(Acl::private()));
        assert_eq!(
            code(put_request(
                &headers(),
                Some(body(from.clone(), "x")),
                false
            )),
            "InvalidArgument"
        );
        let canned = AclHeaders {
            canned: Some("private"),
            ..headers()
        };
        assert_eq!(
            code(put_request(&canned, Some(body(from, OWNER_ID)), false)),
            "UnexpectedContent"
        );
        assert_eq!(
            code(put_request(&headers(), None, false)),
            "MissingSecurityHeader"
        );
        let broken = dto::Grant {
            grantee: None,
            permission: Some(dto::Permission::from_static(dto::Permission::READ)),
        };
        assert_eq!(
            code(put_request(
                &headers(),
                Some(body(vec![broken], OWNER_ID)),
                false
            )),
            "MalformedACLError"
        );
        // What GetObjectAcl answers is what PutObjectAcl takes back.
        let public = canned_acl("public-read-write");
        let back = put_request(&headers(), Some(body(to_grants(&public), OWNER_ID)), true)
            .unwrap()
            .into_acl();
        assert_eq!(back, Some(public));
    }

    fn canned_acl(name: &str) -> Acl {
        canned(name, true).unwrap().into_acl().unwrap()
    }

    #[test]
    fn ownership_and_block_public_access_decide_acl_writes() {
        let enforced = ObjectOwnership::BucketOwnerEnforced;
        let writer = ObjectOwnership::ObjectWriter;
        let open = PublicAccessBlock::default();
        let canned = |name| {
            requested(
                &AclHeaders {
                    canned: Some(name),
                    ..headers()
                },
                false,
            )
            .unwrap()
        };
        // ACLs disabled: only no ACL or the bucket owner's full control.
        assert_eq!(
            for_object_write(Requested::Nothing, enforced, open).unwrap(),
            None
        );
        assert_eq!(
            for_object_write(canned("bucket-owner-full-control"), enforced, open).unwrap(),
            None
        );
        let explicit = Requested::Grants(Acl::private());
        assert_eq!(for_object_write(explicit, enforced, open).unwrap(), None);
        for refused in ["private", "public-read"] {
            assert_eq!(
                code(for_object_write(canned(refused), enforced, open)),
                "AccessControlListNotSupported"
            );
        }
        assert_eq!(
            code(for_acl_write(canned("private"), enforced, open)),
            "AccessControlListNotSupported"
        );
        // ACLs enabled: stored, unless public while BlockPublicAcls is on.
        assert_eq!(
            for_object_write(canned("public-read"), writer, open).unwrap(),
            Some(canned_acl("public-read"))
        );
        assert_eq!(
            code(for_object_write(
                canned("public-read"),
                writer,
                PublicAccessBlock::ALL
            )),
            "AccessDenied"
        );
        assert_eq!(
            for_acl_write(canned("private"), writer, PublicAccessBlock::ALL).unwrap(),
            Acl::private()
        );
        // A new bucket: an ACL needs ACLs enabled, and can't be public while Block
        // Public Access is on.
        let new = |ownership, block_public_access| NewBucket {
            ownership,
            block_public_access,
            ..NewBucket::default()
        };
        let aws = NewBucket::default();
        assert_eq!(for_new_bucket(canned("private"), &aws).unwrap(), None);
        assert_eq!(
            code(for_new_bucket(canned("public-read"), &aws)),
            "InvalidBucketAclWithObjectOwnership"
        );
        let writer_blocked = new(Some(writer), true);
        assert_eq!(
            code(for_new_bucket(canned("public-read"), &writer_blocked)),
            "InvalidBucketAclWithBlockPublicAccessError"
        );
        assert_eq!(
            for_new_bucket(canned("private"), &writer_blocked).unwrap(),
            Some(Acl::private())
        );
        let legacy = new(None, false);
        assert_eq!(
            for_new_bucket(canned("public-read"), &legacy).unwrap(),
            Some(canned_acl("public-read"))
        );
        // Reading: private while disabled.
        let public = canned_acl("public-read");
        assert_eq!(effective(enforced, Some(public.clone())), Acl::private());
        assert_eq!(effective(writer, Some(public.clone())), public);
        assert_eq!(effective(writer, None), Acl::private());
    }

    #[test]
    fn permissions_map_to_actions_as_aws_documents() {
        assert_eq!(
            permission_for("s3:ListBucket"),
            Some((AclOf::Bucket, Permission::Read))
        );
        assert_eq!(
            permission_for("s3:PutObject"),
            Some((AclOf::Bucket, Permission::Write))
        );
        assert_eq!(
            permission_for("s3:GetObject"),
            Some((AclOf::Object, Permission::Read))
        );
        assert_eq!(
            permission_for("s3:PutObjectAcl"),
            Some((AclOf::Object, Permission::WriteAcp))
        );
        for none in [
            "s3:DeleteObjectVersion",
            "s3:PutBucketPolicy",
            "s3:AbortMultipartUpload",
            "s3:GetObjectTagging",
        ] {
            assert_eq!(permission_for(none), None, "{none}");
        }
    }
}
