//! Every request that isn't an S3 operation: the IAM and STS Query APIs, S3 Control,
//! TeiFS's admin API, and `MinIO`'s listen API ([`crate::listen`]) and the calls of its
//! admin API that TeiFS serves (bucket quotas).
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
use teifs_policy::{Context, Decision};
use teifs_store::Store;
use teifs_types::admin::{
    ADMIN_BUCKETS, ADMIN_CONFIG, ADMIN_IAM, ADMIN_IAM_SECRETS, ADMIN_INFO, ADMIN_LDAP_ATTACH,
    ADMIN_LDAP_DETACH, ADMIN_LDAP_POLICIES, ADMIN_PREFIX, ADMIN_ROOT_KEY, ADMIN_SNAPSHOTS,
    ADMIN_TRACE, MINIO_GET_BUCKET_QUOTA, MINIO_SET_BUCKET_QUOTA, ServerConfig,
};

use crate::{
    access::{Client, allows, base_context, with_resource_tags},
    admin,
    bucket_access::Rules,
    bucket_export, control,
    errors::StoreResultExt,
    events::Events,
    iam_api, listen, minio_config, minio_heal, minio_iam, minio_info, minio_kms, minio_ldap,
    minio_metrics, minio_pools, minio_profile, minio_service, minio_service_accounts,
    minio_speedtest,
    observe::{self, Seen},
    quota,
    trace::Tracers,
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
    /// `MinIO`'s admin API, for the calls TeiFS serves: `/minio/admin/v3/…` (or `v4`),
    /// and its KMS API, `/minio/kms/v1/…`, only at their exact paths, so a bucket named
    /// `minio` keeps its other keys.
    Minio,
}

/// What an endpoint needs of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Needs {
    /// This action on this resource, decided with the caller's policies.
    Action(&'static str, &'static str),
    /// Any of these actions on any resource, decided with the caller's policies (as
    /// `MinIO` decides an admin call that several actions allow).
    AnyAction(&'static [&'static str]),
    /// This action on the bucket the path names, decided with the caller's policies and
    /// the bucket's own, and its tags while they decide access.
    OnBucket(&'static str),
    /// This action on the bucket the query names (`?bucket=NAME`), decided with the
    /// caller's policies (as `MinIO` decides its admin actions).
    OnQueryBucket(&'static str),
    /// This action, decided with the caller's policies; or, on the caller's own access
    /// key (`?accessKey=` names the key that signed), anything but an explicit deny (as
    /// `MinIO` lets a user read itself and change its own secret).
    OrOwnKey(&'static str),
    /// Anything but an explicit deny of this action: a call on the caller's own key.
    NotDenied(&'static str),
    /// Anything but an explicit deny of this action; the handler then lets a caller
    /// without it act only on its own service accounts (as `MinIO` decides them).
    OrOwnAccount(&'static str),
    /// The action of the service call `?action=` names (`MinIO`'s restart, stop,
    /// freeze and unfreeze), decided with the caller's policies.
    ServiceAction,
    /// This KMS action, decided with the caller's policies on no key and then on the
    /// key `?key-id=` names (`arn:minio:kms:::KEY`; for a key's status, the default key
    /// by default), as `MinIO` decides them.
    OnKmsKey(&'static str),
    /// Any caller who signs: the call answers about the caller alone.
    Signed,
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
    Tags(control::TagCallKind),
    Info,
    Config,
    ExportIam,
    ExportIamSecrets,
    ImportIam,
    RotateRootKey,
    LdapPolicies,
    AttachLdapPolicies,
    DetachLdapPolicies,
    Snapshots,
    TakeSnapshot,
    ExportBuckets,
    ImportBuckets,
    Trace,
    SetBucketQuota,
    GetBucketQuota,
    AddUser,
    ChangeMyPassword,
    RemoveUser,
    ListUsers,
    UserInfo,
    SetUserStatus,
    UpdateGroupMembers,
    GetGroup,
    ListGroups,
    SetGroupStatus,
    AddCannedPolicy,
    InfoCannedPolicy,
    ListCannedPolicies,
    RemoveCannedPolicy,
    AttachPolicy,
    DetachPolicy,
    PolicyEntities,
    AccountInfo,
    AddServiceAccount,
    UpdateServiceAccount,
    InfoServiceAccount,
    ListServiceAccounts,
    DeleteServiceAccount,
    ListAccessKeysBulk,
    InfoAccessKey,
    TemporaryAccountInfo,
    MinioInfo(minio_info::Kind),
    MinioService,
    MinioMetrics(minio_metrics::Call),
    MinioHeal(minio_heal::Call),
    MinioKms(minio_kms::Call),
    MinioSpeedtest(minio_speedtest::Call),
    MinioLdap(minio_ldap::Call),
    MinioConfig(minio_config::Call),
}

impl Handler {
    /// The operation's name, in metrics and the audit log.
    const fn name(self) -> &'static str {
        match self {
            Self::Query => "IAM",
            Self::GetAccountBlock => "GetPublicAccessBlock",
            Self::PutAccountBlock => "PutPublicAccessBlock",
            Self::DeleteAccountBlock => "DeletePublicAccessBlock",
            Self::Tags(control::TagCallKind::List) => "ListTagsForResource",
            Self::Tags(control::TagCallKind::Tag) => "TagResource",
            Self::Tags(control::TagCallKind::Untag) => "UntagResource",
            Self::Info => "GetServerInfo",
            Self::Config => "GetServerConfig",
            Self::ExportIam => "ExportIAM",
            Self::ExportIamSecrets => "ExportIAMSecrets",
            Self::ImportIam => "ImportIAM",
            Self::RotateRootKey => "RotateRootKey",
            Self::LdapPolicies => "ListLDAPPolicies",
            Self::AttachLdapPolicies => "AttachLDAPPolicy",
            Self::DetachLdapPolicies => "DetachLDAPPolicy",
            Self::Snapshots => "ListSnapshots",
            Self::TakeSnapshot => "TakeSnapshot",
            Self::ExportBuckets => "ExportBucketMetadata",
            Self::ImportBuckets => "ImportBucketMetadata",
            Self::Trace => "ServerTrace",
            Self::SetBucketQuota => "SetBucketQuota",
            Self::GetBucketQuota => "GetBucketQuota",
            Self::AddUser => "AddUser",
            Self::ChangeMyPassword => "ChangeMyPassword",
            Self::RemoveUser => "RemoveUser",
            Self::ListUsers => "ListUsers",
            Self::UserInfo => "GetUserInfo",
            Self::SetUserStatus => "SetUserStatus",
            Self::UpdateGroupMembers => "UpdateGroupMembers",
            Self::GetGroup => "GetGroup",
            Self::ListGroups => "ListGroups",
            Self::SetGroupStatus => "SetGroupStatus",
            Self::AddCannedPolicy => "AddCannedPolicy",
            Self::InfoCannedPolicy => "InfoCannedPolicy",
            Self::ListCannedPolicies => "ListCannedPolicies",
            Self::RemoveCannedPolicy => "RemoveCannedPolicy",
            Self::AttachPolicy => "AttachPolicy",
            Self::DetachPolicy => "DetachPolicy",
            Self::PolicyEntities => "ListPolicyMappingEntities",
            Self::AccountInfo => "AccountInfo",
            Self::AddServiceAccount => "AddServiceAccount",
            Self::UpdateServiceAccount => "UpdateServiceAccount",
            Self::InfoServiceAccount => "InfoServiceAccount",
            Self::ListServiceAccounts => "ListServiceAccounts",
            Self::DeleteServiceAccount => "DeleteServiceAccount",
            Self::ListAccessKeysBulk => "ListAccessKeysBulk",
            Self::InfoAccessKey => "InfoAccessKey",
            Self::TemporaryAccountInfo => "TemporaryAccountInfo",
            Self::MinioInfo(kind) => kind.name(),
            Self::MinioService => "Service",
            Self::MinioMetrics(call) => call.name(),
            Self::MinioHeal(call) => call.name(),
            Self::MinioKms(call) => call.name(),
            Self::MinioSpeedtest(call) => call.name(),
            Self::MinioLdap(call) => call.name(),
            Self::MinioConfig(call) => call.name(),
        }
    }
}

/// One endpoint.
#[derive(Debug)]
pub(crate) struct Endpoint {
    pub(crate) api: Api,
    pub(crate) verb: Verb,
    pub(crate) path: &'static str,
    pub(crate) needs: Needs,
    handler: Handler,
    /// What it does, in a line: the reference (`docs/ADMIN_API.md`) shows it.
    about: &'static str,
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
        about: "The IAM and STS Query APIs: each call names its action in the signed form",
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Get,
        path: control::PUBLIC_ACCESS_BLOCK,
        needs: Needs::Action("s3:GetAccountPublicAccessBlock", ACCOUNT),
        handler: Handler::GetAccountBlock,
        about: "The account's Block Public Access settings",
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Put,
        path: control::PUBLIC_ACCESS_BLOCK,
        needs: Needs::Action("s3:PutAccountPublicAccessBlock", ACCOUNT),
        handler: Handler::PutAccountBlock,
        about: "Sets the account's Block Public Access, combined with every bucket's own",
    },
    // AWS decides deleting with the permission to put.
    Endpoint {
        api: Api::Control,
        verb: Verb::Delete,
        path: control::PUBLIC_ACCESS_BLOCK,
        needs: Needs::Action("s3:PutAccountPublicAccessBlock", ACCOUNT),
        handler: Handler::DeleteAccountBlock,
        about: "Removes the account's Block Public Access, leaving each bucket's own",
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Get,
        path: control::TAGS,
        needs: Needs::OnBucket("s3:ListTagsForResource"),
        handler: Handler::Tags(control::TagCallKind::List),
        about: "A bucket's tags (`ListTagsForResource`)",
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Post,
        path: control::TAGS,
        needs: Needs::OnBucket("s3:TagResource"),
        handler: Handler::Tags(control::TagCallKind::Tag),
        about: "Adds tags to a bucket, or changes their values (`TagResource`), with ABAC too",
    },
    Endpoint {
        api: Api::Control,
        verb: Verb::Delete,
        path: control::TAGS,
        needs: Needs::OnBucket("s3:UntagResource"),
        handler: Handler::Tags(control::TagCallKind::Untag),
        about: "Removes a bucket's tags by key (`UntagResource`), with ABAC too",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_INFO,
        needs: Needs::Action("teifs:GetServerInfo", ANY),
        handler: Handler::Info,
        about: "Version, drive, account, uptime, what the drive holds, its disks' room, background jobs and what scrubs found: `ServerInfo`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_CONFIG,
        needs: Needs::Action("teifs:GetServerConfig", ANY),
        handler: Handler::Config,
        about: "How the server was started, without secrets: `ServerConfig`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_SNAPSHOTS,
        needs: Needs::Action("teifs:ListSnapshots", ANY),
        handler: Handler::Snapshots,
        about: "The drive's metadata snapshots, oldest first: `Snapshot`s",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Post,
        path: ADMIN_SNAPSHOTS,
        needs: Needs::Action("teifs:TakeSnapshot", ANY),
        handler: Handler::TakeSnapshot,
        about: "Snapshots the drive's metadata now (both databases, kept with the daily ones): `Snapshot`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_BUCKETS,
        needs: Needs::Action("teifs:ExportBucketMetadata", ANY),
        handler: Handler::ExportBuckets,
        about: "Every bucket (`?bucket=NAME`: one) with its layout, versioning and settings: `BucketsExport`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Put,
        path: ADMIN_BUCKETS,
        needs: Needs::Action("teifs:ImportBucketMetadata", ANY),
        handler: Handler::ImportBuckets,
        about: "Imports a `BucketsExport`: creates missing buckets and applies the settings given, checked as S3's calls check them: `BucketsImportReport`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_TRACE,
        needs: Needs::Action("teifs:ServerTrace", ANY),
        handler: Handler::Trace,
        about: "A live trace: each request answered from now on, as its audit entry, one JSON line each (`application/x-ndjson`), until the caller leaves; the query filters it (`errors`, `api`, `bucket`, `prefix`, `status`, `slowerThanMs`)",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_IAM,
        needs: Needs::Action("teifs:ExportIAM", ANY),
        handler: Handler::ExportIam,
        about: "The account's IAM, access keys without their secrets: `IamExport`",
    },
    // Secrets, and an import that sets them and may take another account's id: the
    // root user's alone.
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_IAM_SECRETS,
        needs: Needs::Root,
        handler: Handler::ExportIamSecrets,
        about: "The account's IAM with access keys' secrets, to move it to another drive",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Put,
        path: ADMIN_IAM,
        needs: Needs::Root,
        handler: Handler::ImportIam,
        about: "Imports an `IamExport` into an empty IAM, all or nothing: `ImportReport`; `?account=adopt` also takes its account id",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Post,
        path: ADMIN_ROOT_KEY,
        needs: Needs::Root,
        handler: Handler::RotateRootKey,
        about: "Replaces a root key the drive generated and answers the new one: `RootKeyRotated`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Get,
        path: ADMIN_LDAP_POLICIES,
        needs: Needs::Action("teifs:ListLDAPPolicies", ANY),
        handler: Handler::LdapPolicies,
        about: "The managed policies mapped to LDAP users' and groups' DNs (`?dn=DN`: one): `LdapPolicyMapping`s",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Post,
        path: ADMIN_LDAP_ATTACH,
        needs: Needs::Action("teifs:AttachLDAPPolicy", ANY),
        handler: Handler::AttachLdapPolicies,
        about: "Maps managed policies to an LDAP user's or group's DN, which the directory must have (`LdapPolicyRequest`): `LdapPolicyChanged`",
    },
    Endpoint {
        api: Api::Admin,
        verb: Verb::Post,
        path: ADMIN_LDAP_DETACH,
        needs: Needs::Action("teifs:DetachLDAPPolicy", ANY),
        handler: Handler::DetachLdapPolicies,
        about: "Removes managed policies from an LDAP user's or group's DN (`LdapPolicyRequest`): `LdapPolicyChanged`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: MINIO_SET_BUCKET_QUOTA,
        needs: Needs::OnQueryBucket("admin:SetBucketQuota"),
        handler: Handler::SetBucketQuota,
        about: "Sets `?bucket=NAME`'s hard quota in bytes (`{\"size\":N,\"quotatype\":\"hard\"}`, or `quota` for `size`), or clears it with none: `mc quota set` and `clear`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: MINIO_GET_BUCKET_QUOTA,
        needs: Needs::OnQueryBucket("admin:GetBucketQuota"),
        handler: Handler::GetBucketQuota,
        about: "`?bucket=NAME`'s quota (`quota` and `size` in bytes, `0` for none): `mc quota info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/accountinfo",
        needs: Needs::Signed,
        handler: Handler::AccountInfo,
        about: "The caller's name and policy, and the buckets it may read (`s3:ListBucket`) or write (`s3:PutObject`) with what each holds and has turned on: `mc admin accountinfo`, the console's buckets",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/add-user",
        needs: Needs::OrOwnKey("admin:CreateUser"),
        handler: Handler::AddUser,
        about: "Makes user `?accessKey=` (an IAM user of that name, signing with a key of that id) or changes its secret and status; the body is an encrypted `AddOrUpdateUserReq`: `mc admin user add`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/change-my-password",
        needs: Needs::NotDenied("admin:ChangeMyPassword"),
        handler: Handler::ChangeMyPassword,
        about: "A new secret (an encrypted `AddOrUpdateUserReq`) for the access key that signs the request",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Delete,
        path: "/minio/admin/v3/remove-user",
        needs: Needs::Action("admin:DeleteUser", ANY),
        handler: Handler::RemoveUser,
        about: "Deletes user `?accessKey=` with its keys, policies and memberships: `mc admin user rm`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/list-users",
        needs: Needs::Action("admin:ListUsers", ANY),
        handler: Handler::ListUsers,
        about: "Every user's `UserInfo` by name, encrypted: `mc admin user ls`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/user-info",
        needs: Needs::OrOwnKey("admin:GetUser"),
        handler: Handler::UserInfo,
        about: "User `?accessKey=`'s `UserInfo` (status, policies, groups): `mc admin user info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/set-user-status",
        needs: Needs::Action("admin:EnableUser", ANY),
        handler: Handler::SetUserStatus,
        about: "Enables or disables user `?accessKey=` (`&status=enabled|disabled`); a disabled user's keys and sessions don't sign: `mc admin user enable` and `disable`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/update-group-members",
        needs: Needs::Action("admin:AddUserToGroup", ANY),
        handler: Handler::UpdateGroupMembers,
        about: "Adds members to a group (made if needed) or removes them, or the group when it's empty (`GroupAddRemove`): `mc admin group add` and `rm`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/group",
        needs: Needs::Action("admin:GetGroup", ANY),
        handler: Handler::GetGroup,
        about: "Group `?group=`'s `GroupDesc`: `mc admin group info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/groups",
        needs: Needs::Action("admin:ListGroups", ANY),
        handler: Handler::ListGroups,
        about: "Every group's name: `mc admin group ls`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/set-group-status",
        needs: Needs::Action("admin:EnableGroup", ANY),
        handler: Handler::SetGroupStatus,
        about: "Enables or disables group `?group=` (`&status=`); a disabled group's policies don't count: `mc admin group enable` and `disable`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/add-canned-policy",
        needs: Needs::Action("admin:CreatePolicy", ANY),
        handler: Handler::AddCannedPolicy,
        about: "Makes policy `?name=` from the body's document or gives it a new version; a built-in name with `&overrideBuiltin=true`, and `&resetBuiltin=true` removes the override: `mc admin policy create`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/info-canned-policy",
        needs: Needs::Action("admin:GetPolicy", ANY),
        handler: Handler::InfoCannedPolicy,
        about: "Policy `?name=`'s document, or with `&v=2` its `PolicyInfo`: `mc admin policy info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/list-canned-policies",
        needs: Needs::Action("admin:ListUserPolicies", ANY),
        handler: Handler::ListCannedPolicies,
        about: "Every policy's document by name, built-in ones included: `mc admin policy ls`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Delete,
        path: "/minio/admin/v3/remove-canned-policy",
        needs: Needs::Action("admin:DeletePolicy", ANY),
        handler: Handler::RemoveCannedPolicy,
        about: "Deletes policy `?name=`, which nothing may use: `mc admin policy rm`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/idp/builtin/policy/attach",
        needs: Needs::Action("admin:UpdatePolicyAssociation", ANY),
        handler: Handler::AttachPolicy,
        about: "Attaches policies to a user or group (an encrypted `PolicyAssociationReq`), answering what changed, encrypted: `mc admin policy attach`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/idp/builtin/policy/detach",
        needs: Needs::Action("admin:UpdatePolicyAssociation", ANY),
        handler: Handler::DetachPolicy,
        about: "Detaches policies from a user or group, as `attach`: `mc admin policy detach`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/idp/builtin/policy-entities",
        needs: Needs::Action("admin:ListUserPolicies", ANY),
        handler: Handler::PolicyEntities,
        about: "Who has which policies (`?user=`, `?group=`, `?policy=`, each repeated, or all), encrypted: `mc admin policy entities`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/add-service-account",
        needs: Needs::OrOwnAccount("admin:CreateServiceAccount"),
        handler: Handler::AddServiceAccount,
        about: "Makes a service account for the encrypted `AddServiceAccountReq`'s `targetUser` (the caller's own user by default) and answers its credentials, encrypted: `mc admin user svcacct add`, `mc admin accesskey create`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/update-service-account",
        needs: Needs::Action("admin:UpdateServiceAccount", ANY),
        handler: Handler::UpdateServiceAccount,
        about: "Changes service account `?accessKey=` as the encrypted `UpdateServiceAccountReq` says; what it leaves out stays: `mc admin user svcacct edit`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/info-service-account",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::InfoServiceAccount,
        about: "Service account `?accessKey=`: its parent, status, policy (its parent's when implied), name, description and expiry, encrypted: `mc admin user svcacct info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/list-service-accounts",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::ListServiceAccounts,
        about: "The service accounts of `?user=` (the caller's own user by default), encrypted: `mc admin user svcacct list`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Delete,
        path: "/minio/admin/v3/delete-service-account",
        needs: Needs::OrOwnAccount("admin:RemoveServiceAccount"),
        handler: Handler::DeleteServiceAccount,
        about: "Deletes service account `?accessKey=`: `mc admin user svcacct rm`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/list-access-keys-bulk",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::ListAccessKeysBulk,
        about: "The service accounts of `?users=` (repeated), every user's with `all=true` (which needs `admin:ListUsers`), or the caller's, by `listType` (`users-only`, `sts-only`, `svcacc-only`, `all`), encrypted: `mc admin accesskey ls`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/info-access-key",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::InfoAccessKey,
        about: "Access key `?accessKey=` (the caller's by default) when it's a service account, encrypted: `mc admin accesskey info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/idp/ldap/policy/attach",
        needs: Needs::Action("admin:UpdatePolicyAssociation", ANY),
        handler: Handler::MinioLdap(minio_ldap::Call::Attach),
        about: "Maps policies to an LDAP user (by name or DN) or group (by DN), from an encrypted `PolicyAssociationReq`, answering what changed, encrypted: `mc idp ldap policy attach`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/idp/ldap/policy/detach",
        needs: Needs::Action("admin:UpdatePolicyAssociation", ANY),
        handler: Handler::MinioLdap(minio_ldap::Call::Detach),
        about: "Unmaps policies from an LDAP user or group, as `attach`: `mc idp ldap policy detach`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/idp/ldap/policy-entities",
        needs: Needs::AnyAction(&[
            "admin:ListUserPolicies",
            "admin:ListUsers",
            "admin:ListGroups",
        ]),
        handler: Handler::MinioLdap(minio_ldap::Call::Entities),
        about: "Which LDAP users and groups have which policies (`?user=`, `?group=`, `?policy=`, each repeated, or all), encrypted: `mc idp ldap policy entities`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/idp/ldap/add-service-account",
        needs: Needs::OrOwnAccount("admin:CreateServiceAccount"),
        handler: Handler::MinioLdap(minio_ldap::Call::AddServiceAccount),
        about: "Makes a service account for the encrypted request's `targetUser`, an LDAP user's name (the caller's own LDAP user by default), and answers its credentials, encrypted: `mc idp ldap accesskey create`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/idp/ldap/list-access-keys",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::MinioLdap(minio_ldap::Call::ListAccessKeys),
        about: "LDAP user `?userDN=`'s service accounts (the caller's own by default), encrypted",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/idp/ldap/list-access-keys-bulk",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::MinioLdap(minio_ldap::Call::ListAccessKeysBulk),
        about: "LDAP users' service accounts by DN (`?userDNs=`, repeated; the caller's own by default; `&all=true` with `admin:ListUsers`), encrypted: `mc idp ldap accesskey ls`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/idp/openid/list-access-keys-bulk",
        needs: Needs::OrOwnAccount("admin:ListServiceAccounts"),
        handler: Handler::MinioLdap(minio_ldap::Call::OpenIdListAccessKeysBulk),
        about: "OpenID Connect users' access keys by configuration, of which none are kept, encrypted: `mc idp openid accesskey ls`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/temporary-account-info",
        needs: Needs::Action("admin:ListTemporaryAccounts", ANY),
        handler: Handler::TemporaryAccountInfo,
        about: "Temporary credentials `?accessKey=`: TeiFS keeps nothing about a session, so always `XMinioAdminNoSuchAccessKey`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/info",
        needs: Needs::Action("admin:ServerInfo", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Server),
        about: "The server as `madmin.InfoMessage`: one server with one pool of one set, its drives the disks the drive uses, what it holds, and whether its KMS and LDAP directory answer: `mc admin info`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/storageinfo",
        needs: Needs::Action("admin:StorageInfo", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Storage),
        about: "The drive's disks and their room as `madmin.StorageInfo`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/datausageinfo",
        needs: Needs::Action("admin:DataUsageInfo", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::DataUsage),
        about: "What each bucket holds as `madmin.DataUsageInfo`, with the disks' room when `?capacity=true`: `mc admin info`, the console's dashboard",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/service",
        needs: Needs::ServiceAction,
        handler: Handler::MinioService,
        about: "Restarts or stops the server once it has answered, or freezes S3's requests until as many unfreezes have come, as `?action=` (`restart`, `stop`, `freeze`, `unfreeze`) asks; with `?dry-run=true` it only answers. Restarting needs `admin:ServiceRestart`, stopping `admin:ServiceStop`, freezing and unfreezing `admin:ServiceFreeze`: `mc admin service`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/trace",
        needs: Needs::Action("admin:ServerTrace", ANY),
        handler: Handler::MinioMetrics(minio_metrics::Call::Trace),
        about: "A live trace as `madmin.TraceInfo` documents, until the caller leaves: S3's requests as `MinIO`'s S3 type, the other APIs' as its internal type, filtered by `types` (or `s3`, `internal`, `all`), `err` and `threshold`; headers and queries with their secrets redacted: `mc admin trace`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/log",
        needs: Needs::Action("admin:ConsoleLog", ANY),
        handler: Handler::MinioMetrics(minio_metrics::Call::Log),
        about: "The server's log as `madmin.LogInfo` documents: the last `limit` lines (of the 10,000 kept) of the kind `logType` asks (`ERROR`, `WARNING`, `INFO`; all by default), then each as it's logged, until the caller leaves: `mc admin logs`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/metrics",
        needs: Needs::Action("admin:ServerInfo", ANY),
        handler: Handler::MinioMetrics(minio_metrics::Call::Metrics),
        about: "Live metrics as `madmin.RealtimeMetrics` documents, the first at once and then one every `interval` (a second at least), `n` times or until the caller leaves: S3's requests being served and those answered since the server started, `MinIO`'s API metrics: `mc admin scanner status`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/top/locks",
        needs: Needs::Action("admin:TopLocksInfo", ANY),
        handler: Handler::MinioMetrics(minio_metrics::Call::TopLocks),
        about: "The oldest locks held, as `madmin.LockEntries`: always none, since a request holds no lock past its answer: `mc admin top locks`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/force-unlock",
        needs: Needs::Action("admin:ForceUnlock", ANY),
        handler: Handler::MinioMetrics(minio_metrics::Call::ForceUnlock),
        about: "Releases the locks `paths` names: none is ever held past a request, so there's nothing to release: `mc admin force-unlock`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/heal/",
        needs: Needs::Action("admin:Heal", ANY),
        handler: Handler::MinioHeal(minio_heal::Call::Heal),
        about: "Starts a heal of every bucket, as `madmin.HealOpts` asks, and answers its token; with `?clientToken=` the results since the last call; `?forceStart`, `?forceStop`. One drive has no other copy to heal from: a heal checks each bucket and object and reports it, changing nothing; a deep scan reads each version's bytes, as `teifs verify` does: `mc admin heal`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/heal/{path}",
        needs: Needs::Action("admin:Heal", ANY),
        handler: Handler::MinioHeal(minio_heal::Call::Heal),
        about: "A heal of one bucket, or of its objects under a prefix (`{bucket}/{prefix}`): as `heal/`: `mc admin heal ALIAS/BUCKET/PREFIX`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/pools/list",
        needs: Needs::AnyAction(&["admin:ServerInfo", "admin:Decommission"]),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::List)),
        about: "The server's pools as `madmin.PoolStatus`: the drive, its only pool, named by its path: `mc admin decommission status`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/pools/status",
        needs: Needs::AnyAction(&["admin:ServerInfo", "admin:Decommission"]),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::Status)),
        about: "The `pool` named (its path, or `0` with `by-id=true`) as `madmin.PoolStatus`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/pools/decommission",
        needs: Needs::Action("admin:Decommission", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::Decommission)),
        about: "501 NotImplemented: the drive is the only pool, with no other to move its objects to: `mc admin decommission start`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/pools/cancel",
        needs: Needs::Action("admin:Decommission", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::Cancel)),
        about: "501 NotImplemented, as no decommission can run: `mc admin decommission cancel`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/rebalance/start",
        needs: Needs::Action("admin:Rebalance", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::RebalanceStart)),
        about: "501 NotImplemented: one pool has nothing to balance with: `mc admin rebalance start`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/rebalance/status",
        needs: Needs::Action("admin:Rebalance", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::RebalanceStatus)),
        about: "404 XMinioAdminRebalanceNotStarted, as MinIO answers when none runs: `mc admin rebalance status`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/rebalance/stop",
        needs: Needs::Action("admin:Rebalance", ANY),
        handler: Handler::MinioInfo(minio_info::Kind::Pools(minio_pools::Call::RebalanceStop)),
        about: "501 NotImplemented, as no rebalance can run: `mc admin rebalance stop`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/profile",
        needs: Needs::Action("admin:Profiling", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Profile(
            minio_profile::Call::Profile,
        )),
        about: "Takes the `profilerType` profiles (`cpu`) for `duration` (a minute unless told, an hour at most) and answers them in a zip with `cluster.info`, as MinIO does: `mc admin profile`, `mc support profile`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/profiling/start",
        needs: Needs::Action("admin:Profiling", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Profile(
            minio_profile::Call::Start,
        )),
        about: "Starts the `profilerType` profiles, answering a `madmin.StartProfilingResult` for each: MinIO's older profiling calls",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/profiling/download",
        needs: Needs::Action("admin:Profiling", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Profile(
            minio_profile::Call::Download,
        )),
        about: "Stops the profiles started and answers them in a zip, as `POST profile` does",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/speedtest",
        needs: Needs::Action("admin:OBDInfo", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Object),
        about: "Measures the store: writes objects of `size` with `concurrent` writers for `duration`, reads them back as long, and streams `madmin.SpeedTestResult`; `autotune` adds writers while reads get faster. S3's requests wait meanwhile: `mc admin speedtest`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/speedtest/object",
        needs: Needs::Action("admin:OBDInfo", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Object),
        about: "Measures the store: writes objects of `size` with `concurrent` writers for `duration`, reads them back as long, and streams `madmin.SpeedTestResult`; `autotune` adds writers while reads get faster. S3's requests wait meanwhile: `mc admin speedtest`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/speedtest/drive",
        needs: Needs::Action("admin:OBDInfo", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Drive),
        about: "Writes a file of `filesize` to each disk in blocks of `blocksize`, syncs it and reads it back: `madmin.DriveSpeedTestResult`, `mc support perf drive`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/speedtest/net",
        needs: Needs::Action("admin:OBDInfo", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Network),
        about: "501 NotImplemented: a server is one node, with no network between nodes to measure",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/speedtest/site",
        needs: Needs::Action("admin:OBDInfo", ANY),
        handler: Handler::MinioSpeedtest(minio_speedtest::Call::Network),
        about: "501 NotImplemented: there are no other sites to measure the network to",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/background-heal/status",
        needs: Needs::Action("admin:Heal", ANY),
        handler: Handler::MinioHeal(minio_heal::Call::BackgroundStatus),
        about: "The background heal's status as `madmin.BgHealState`: the drive's scrub, with the versions it checked and the drive's disks: `mc admin heal` with no target",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/kms/status",
        needs: Needs::Action("admin:KMSKeyStatus", ANY),
        handler: Handler::MinioKms(minio_kms::Call::Status),
        about: "The KMS as `madmin.KMSStatus`: its kind, default key, and whether each of its endpoints answers (older clients; newer ones call `/minio/kms/v1/status`)",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/admin/v3/kms/key/create",
        needs: Needs::Action("admin:KMSCreateKey", ANY),
        handler: Handler::MinioKms(minio_kms::Call::CreateKey),
        about: "Creates the KMS key `?key-id=` (older clients; newer ones call `/minio/kms/v1/key/create`)",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/kms/key/status",
        needs: Needs::Action("admin:KMSKeyStatus", ANY),
        handler: Handler::MinioKms(minio_kms::Call::KeyStatus),
        about: "Whether KMS key `?key-id=` (the default key by default) seals a new data key and unseals it again, as `madmin.KMSKeyStatus` (older clients; newer ones call `/minio/kms/v1/key/status`)",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/kms/v1/status",
        needs: Needs::Action("kms:Status", ANY),
        handler: Handler::MinioKms(minio_kms::Call::Status),
        about: "The KMS as `madmin.KMSStatus`: its kind, default key, and whether each of its endpoints answers: `mc admin kms status`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/kms/v1/metrics",
        needs: Needs::Action("kms:Metrics", ANY),
        handler: Handler::MinioKms(minio_kms::Call::Metrics),
        about: "The KMS's calls since the server started (sealing, unsealing, creating and rotating keys): how many succeeded, were refused and failed, and a cumulative latency histogram",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/kms/v1/apis",
        needs: Needs::Action("kms:API", ANY),
        handler: Handler::MinioKms(minio_kms::Call::Apis),
        about: "The KMS API's calls, as `madmin.KMSAPI`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/kms/v1/version",
        needs: Needs::Action("kms:Version", ANY),
        handler: Handler::MinioKms(minio_kms::Call::Version),
        about: "The server's version, as `madmin.KMSVersion`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Post,
        path: "/minio/kms/v1/key/create",
        needs: Needs::OnKmsKey("kms:CreateKey"),
        handler: Handler::MinioKms(minio_kms::Call::CreateKey),
        about: "Creates KMS key `?key-id=`: `mc admin kms key create`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/kms/v1/key/list",
        needs: Needs::Action("kms:ListKeys", ANY),
        handler: Handler::MinioKms(minio_kms::Call::ListKeys),
        about: "The KMS keys whose names start with `?pattern=` (`*` or nothing for all) that the caller may list, as `madmin.KMSKeyInfo`: `mc admin kms key list`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/kms/v1/key/status",
        needs: Needs::OnKmsKey("kms:KeyStatus"),
        handler: Handler::MinioKms(minio_kms::Call::KeyStatus),
        about: "Whether KMS key `?key-id=` (the default key by default) seals a new data key and unseals it again, as `madmin.KMSKeyStatus`: `mc admin kms key status`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/get-config-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::Get),
        about: "A sub-system's settings (`?key=subsys`, `subsys:` for its default target, `subsys:target` for one), without secrets, as key-value lines encrypted with the caller's secret key: `mc admin config get`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/set-config-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::Set),
        about: "Sets the key-value lines of the encrypted body; they take effect when the server starts again: `mc admin config set`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Delete,
        path: "/minio/admin/v3/del-config-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::Delete),
        about: "Resets the targets or keys the encrypted body names to their defaults: `mc admin config reset`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/help-config-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::Help),
        about: "Help for sub-system `?subSys=` (all of them when empty) or its key `?key=`, keys named by their variables with `?env`, as `madmin.Help`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/list-config-history-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::History),
        about: "The newest `?count=` changes (0 for all), oldest first, as `madmin.ConfigHistoryEntry` encrypted with the caller's secret key: `mc admin config history`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Delete,
        path: "/minio/admin/v3/clear-config-history-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::ClearHistory),
        about: "Forgets change `?restoreId=` (`all` for every one)",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/restore-config-history-kv",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::RestoreHistory),
        about: "Sets change `?restoreId=`'s lines again, then forgets it: `mc admin config restore`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Get,
        path: "/minio/admin/v3/config",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::Export),
        about: "The whole configuration, secrets included, encrypted with the caller's secret key: `mc admin config export`",
    },
    Endpoint {
        api: Api::Minio,
        verb: Verb::Put,
        path: "/minio/admin/v3/config",
        needs: Needs::Action("admin:ConfigUpdate", ANY),
        handler: Handler::MinioConfig(minio_config::Call::Import),
        about: "Replaces the whole configuration with the encrypted body's: `mc admin config import`",
    },
];

/// Why a call decided on its query's bucket has one.
const ON: &str = "decided on the query's bucket";

/// `MinIO`'s admin API, as its clients reach it.
const MINIO_ADMIN: &str = "/minio/admin/v3/";
/// The same, as newer clients reach it.
const MINIO_ADMIN_V4: &str = "/minio/admin/v4/";

/// `MinIO`'s KMS API.
pub(crate) const MINIO_KMS: &str = "/minio/kms/v1/";

/// A path of `MinIO`'s admin API, spelled as its `v3` endpoint is, or of its KMS API.
fn minio_admin_path(path: &str) -> Option<std::borrow::Cow<'_, str>> {
    if path.starts_with(MINIO_ADMIN) || path.starts_with(MINIO_KMS) {
        Some(std::borrow::Cow::Borrowed(path))
    } else {
        let rest = path.strip_prefix(MINIO_ADMIN_V4)?;
        Some(std::borrow::Cow::Owned(format!("{MINIO_ADMIN}{rest}")))
    }
}

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
    /// Other actions that allow it too.
    pub or_actions: &'static [&'static str],
    /// Whether only the root user may call it.
    pub root_only: bool,
    /// Whether a caller may call it on its own access key without the action, unless a
    /// policy denies it.
    pub own_key: bool,
    /// Its API.
    pub api: Api,
    /// What it does, in a line.
    pub about: &'static str,
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
            Needs::AnyAction(actions) => actions.first().copied(),
            Needs::Action(action, _)
            | Needs::OnBucket(action)
            | Needs::OnQueryBucket(action)
            | Needs::OrOwnKey(action)
            | Needs::NotDenied(action)
            | Needs::OrOwnAccount(action)
            | Needs::OnKmsKey(action) => Some(action),
            Needs::PerCall | Needs::Root | Needs::Signed | Needs::ServiceAction => None,
        },
        or_actions: match e.needs {
            Needs::AnyAction(actions) => actions.get(1..).unwrap_or_default(),
            _ => &[],
        },
        root_only: e.needs == Needs::Root,
        own_key: matches!(
            e.needs,
            Needs::OrOwnKey(_) | Needs::NotDenied(_) | Needs::OrOwnAccount(_) | Needs::Signed
        ),
        api: e.api,
        about: e.about,
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
    } else if path.starts_with(ADMIN_PREFIX) && admin::virtual_bucket(headers, domains).is_none() {
        Some(Api::Admin)
    } else if minio_admin_path(path).is_some_and(|path| {
        ENDPOINTS
            .iter()
            .any(|e| e.api == Api::Minio && matches(e.path, &path))
    }) && admin::virtual_bucket(headers, domains).is_none()
    {
        Some(Api::Minio)
    } else {
        None
    }
}

/// The endpoint a request is for, among its API's.
fn endpoint(api: Api, method: &Method, path: &str) -> Option<&'static Endpoint> {
    let verb = Verb::of(method)?;
    let path = match api {
        Api::Minio => minio_admin_path(path)?,
        Api::Query | Api::Control | Api::Admin => std::borrow::Cow::Borrowed(path),
    };
    ENDPOINTS
        .iter()
        .find(|e| e.api == api && e.verb == verb && matches(e.path, &path))
}

/// Whether `path` is an endpoint's: the same, or, for a path ending in a `{label}`, one
/// with something in its place.
fn matches(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix('}').and_then(|p| p.rsplit_once('{')) {
        Some((prefix, _)) => path.len() > prefix.len() && path.starts_with(prefix),
        None => pattern == path,
    }
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
    /// Whoever watches live traces.
    pub(crate) tracers: Arc<Tracers>,
    /// The requests' live figures, for `MinIO`'s realtime metrics.
    pub(crate) live: crate::metrics::Live,
    /// `MinIO`'s heal sequences.
    pub(crate) heals: Arc<crate::minio_heal::Heals>,
    /// The profiles being taken (`mc admin profile`).
    pub(crate) profiles: Arc<crate::minio_profile::Profiles>,
    /// Where events go: the server's notification targets and its listeners.
    pub(crate) events: Events,
    /// Where requests' access log records go, turned on when an import makes a bucket log.
    pub(crate) access_log: Arc<crate::access_log::AccessLog>,
    /// Where answered requests go for buckets' request metrics.
    pub(crate) request_metrics: Arc<crate::request_metrics::RequestMetrics>,
    /// The server's freezes, and whether it was asked to stop.
    pub(crate) control: Arc<crate::minio_service::Control>,
    /// Where `mc admin config` keeps what it sets, if the drive keeps it.
    pub(crate) configs: Option<Arc<minio_config::Configs>>,
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
        listen::Request::of(method, uri, headers, &self.domains).is_some()
            || api_of(method, uri, headers, &self.domains).is_some()
    }

    /// Everything is decided in [`Self::call`], where each API answers in its format.
    async fn check_access(&self, _: &mut S3Request<Body>) -> S3Result<()> {
        Ok(())
    }

    async fn call(&self, req: S3Request<Body>) -> S3Result<S3Response<Body>> {
        if let Some(scope) = listen::Request::of(&req.method, &req.uri, &req.headers, &self.domains)
        {
            return self.listen(scope, req).await;
        }
        let api = api_of(&req.method, &req.uri, &req.headers, &self.domains)
            .expect("matched by is_match");
        let seen = req.extensions.get::<Arc<Seen>>().cloned();
        let request_id = observe::request_id(&req.extensions);
        if let Some(seen) = &seen {
            seen.api(match api {
                Api::Query if req.service.as_deref() == Some("iam") => "IAM",
                Api::Query => "STS",
                Api::Control => "Control",
                Api::Admin | Api::Minio => "Admin",
            });
            if let Some(credentials) = &req.credentials {
                seen.signed_by(&credentials.access_key);
            }
        }
        // Each API answers errors in its own format.
        let response = match api {
            Api::Query => {
                observe::name(
                    &req.extensions,
                    if req.service.as_deref() == Some("iam") {
                        "IAM"
                    } else {
                        "STS"
                    },
                );
                iam_api::serve(&self.iam, req).await
            }
            Api::Control => self
                .serve(api, req)
                .await
                .unwrap_or_else(|err| control::error_response(&err, &request_id)),
            Api::Admin => self
                .serve(api, req)
                .await
                .unwrap_or_else(|err| admin::error_response(&err, &request_id)),
            Api::Minio => {
                let resource = req.uri.path().to_owned();
                self.serve(api, req)
                    .await
                    .unwrap_or_else(|err| admin::minio_error_response(&err, &resource, &request_id))
            }
        };
        // Refused before its endpoint was found: named by its API.
        if let Some(seen) = seen {
            seen.name(match api {
                Api::Query => "STS",
                Api::Control => "Control",
                Api::Admin | Api::Minio => "Admin",
            });
        }
        Ok(response)
    }
}

impl Routes {
    /// Authenticates, finds the endpoint, decides whether the caller may call it, and
    /// calls it.
    async fn serve(&self, api: Api, mut req: S3Request<Body>) -> S3Result<S3Response<Body>> {
        let identity = self.authenticate(&req)?;
        // Temporary credentials that may not use IAM (`GetSessionToken`'s, federated
        // users') may not manage the drive either.
        if matches!(api, Api::Admin | Api::Minio)
            && identity.session().is_some_and(|s| !s.may_manage())
        {
            return Err(denied());
        }
        let endpoint = endpoint(api, &req.method, req.uri.path()).ok_or_else(|| match api {
            Api::Admin | Api::Minio => admin::not_found(),
            Api::Control | Api::Query => S3Error::with_message(
                S3ErrorCode::NotImplemented,
                "TeiFS serves the account's Block Public Access and buckets' tags from S3 \
                 Control, and nothing else yet.",
            ),
        })?;
        observe::name(&req.extensions, endpoint.handler.name());
        let client = req.extensions.get::<Client>().copied().unwrap_or_default();
        let context = || base_context(&identity, &req.headers, client, &self.iam.account());
        // A call on a bucket's tags is decided with what it asks for, read first.
        let mut on_bucket = None;
        let mut query_bucket = None;
        // Whether the caller has the action itself, beyond its own service accounts.
        let mut privileged = false;
        let allowed = match endpoint.needs {
            Needs::Action(action, resource) => identity
                .decide(&context(), action, resource, None)
                .is_allowed(),
            Needs::AnyAction(actions) => actions
                .iter()
                .any(|action| identity.decide(&context(), action, ANY, None).is_allowed()),
            Needs::OnBucket(action) => {
                let Handler::Tags(kind) = endpoint.handler else {
                    unreachable!("only calls on tags are on a bucket")
                };
                let bucket = control::tagged_bucket(&req)?;
                let context = context();
                let call = control::TagCall::read(kind, &mut req).await?;
                let rules = self.rules.of(&bucket).await?;
                let context = with_resource_tags(&context, Some(&rules)).unwrap_or(context);
                let allowed = allows(
                    &identity,
                    &call.in_context(context),
                    action,
                    &teifs_policy::bucket_arn(&bucket),
                    Some(&rules),
                );
                on_bucket = Some((bucket, call));
                allowed
            }
            Needs::OnQueryBucket(action) => {
                let bucket = admin::query_bucket(req.uri.query())?;
                let allowed = identity
                    .decide(&context(), action, &teifs_policy::bucket_arn(&bucket), None)
                    .is_allowed();
                query_bucket = Some(bucket);
                allowed
            }
            Needs::OrOwnKey(action) => {
                let decision = identity.decide(&context(), action, ANY, None);
                decision.is_allowed() || (decision != Decision::ExplicitDeny && on_own_key(&req))
            }
            Needs::NotDenied(action) => {
                identity.decide(&context(), action, ANY, None) != Decision::ExplicitDeny
            }
            Needs::OrOwnAccount(action) => {
                let decision = identity.decide(&context(), action, ANY, None);
                privileged = decision.is_allowed();
                decision != Decision::ExplicitDeny
            }
            Needs::OnKmsKey(action) => {
                self.on_kms_key(&identity, &context(), (action, endpoint.handler), &req)?
            }
            Needs::ServiceAction => {
                let action = minio_service::Action::asked(req.uri.query())?;
                identity
                    .decide(&context(), action.needs(), ANY, None)
                    .is_allowed()
            }
            Needs::Root => identity.is_root(),
            Needs::Signed => true,
            Needs::PerCall => false,
        };
        if !allowed {
            return Err(denied());
        }
        if api == Api::Control {
            control::check_account(&req.headers, &self.iam.account())?;
        }
        let context = base_context(&identity, &req.headers, client, &self.iam.account());
        self.call(
            endpoint.handler,
            req,
            (&identity, &context, privileged),
            on_bucket,
            query_bucket,
        )
        .await
    }

    /// Whether the caller may call a KMS action on no key and on the key `?key-id=`
    /// names (for a key's status, the default key by default).
    fn on_kms_key(
        &self,
        identity: &Identity,
        context: &Context,
        (action, handler): (&str, Handler),
        req: &S3Request<Body>,
    ) -> S3Result<bool> {
        // Decided on no key before the key is read, so a caller without the action
        // learns nothing about the request (as on MinIO).
        if !identity.decide(context, action, ANY, None).is_allowed() {
            return Ok(false);
        }
        let default = (handler == Handler::MinioKms(minio_kms::Call::KeyStatus))
            .then(|| minio_kms::default_key(self.config.as_deref()));
        let key = minio_kms::named_key(req, default.as_deref())?;
        let on_key = teifs_policy::minio::kms_key_arn(&key);
        Ok(identity.decide(context, action, &on_key, None).is_allowed())
    }

    /// Calls an endpoint the caller may call, with what deciding it read: a tags call's
    /// bucket and call, or the bucket its query names.
    async fn call(
        &self,
        handler: Handler,
        req: S3Request<Body>,
        (identity, context, privileged): (&Identity, &Context, bool),
        on_bucket: Option<(String, control::TagCall)>,
        query_bucket: Option<String>,
    ) -> S3Result<S3Response<Body>> {
        match handler {
            Handler::GetAccountBlock => control::get_public_access_block(&self.store).await,
            Handler::PutAccountBlock => {
                control::put_public_access_block(&self.store, &self.rules, req).await
            }
            Handler::DeleteAccountBlock => {
                control::delete_public_access_block(&self.store, &self.rules).await
            }
            Handler::Tags(_) => {
                let (bucket, call) = on_bucket.expect("decided as a call on a bucket");
                call.call(&self.store, &self.rules, &bucket).await
            }
            Handler::Info => admin::info(&self.store, &self.iam, self.started).await,
            Handler::Config => admin::config(self.config.as_deref()),
            Handler::ExportIam => Ok(admin::export(&self.iam, false)),
            Handler::ExportIamSecrets => Ok(admin::export(&self.iam, true)),
            Handler::ImportIam => admin::import(&self.iam, req).await,
            Handler::RotateRootKey => {
                admin::rotate_root_key(&self.iam, self.root_keys.as_ref()).await
            }
            Handler::LdapPolicies => admin::ldap_policies(&self.iam, req.uri.query()),
            Handler::AttachLdapPolicies => admin::change_ldap_policies(&self.iam, req, true).await,
            Handler::DetachLdapPolicies => admin::change_ldap_policies(&self.iam, req, false).await,
            Handler::Snapshots => admin::snapshots(&self.store).await,
            Handler::TakeSnapshot => admin::take_snapshot(&self.store).await,
            Handler::ExportBuckets => bucket_export::export(&self.store, req.uri.query()).await,
            Handler::ImportBuckets => {
                bucket_export::import(
                    &self.store,
                    &self.rules,
                    self.events.notifier(),
                    (
                        &self.iam.account(),
                        (&self.access_log, &self.request_metrics),
                    ),
                    req,
                )
                .await
            }
            Handler::Trace => admin::trace(&self.tracers, req.uri.query()),
            Handler::SetBucketQuota => quota::set(&self.store, &query_bucket.expect(ON), req).await,
            Handler::GetBucketQuota => quota::get(&self.store, &query_bucket.expect(ON)).await,
            Handler::AddUser => minio_iam::add_user(&self.iam, req).await,
            Handler::ChangeMyPassword => minio_iam::change_my_password(&self.iam, req).await,
            Handler::RemoveUser => minio_iam::remove_user(&self.iam, &req),
            Handler::ListUsers => minio_iam::list_users(&self.iam, &req).await,
            Handler::UserInfo => minio_iam::user_info(&self.iam, &req),
            Handler::SetUserStatus => minio_iam::set_user_status(&self.iam, &req),
            Handler::UpdateGroupMembers => minio_iam::update_group_members(&self.iam, req).await,
            Handler::GetGroup => minio_iam::group(&self.iam, &req),
            Handler::ListGroups => Ok(minio_iam::groups(&self.iam)),
            Handler::SetGroupStatus => minio_iam::set_group_status(&self.iam, &req),
            Handler::AddCannedPolicy => minio_iam::add_canned_policy(&self.iam, req).await,
            Handler::InfoCannedPolicy => minio_iam::info_canned_policy(&self.iam, &req),
            Handler::ListCannedPolicies => minio_iam::list_canned_policies(&self.iam),
            Handler::RemoveCannedPolicy => minio_iam::remove_canned_policy(&self.iam, &req),
            Handler::AttachPolicy => minio_iam::associate(&self.iam, req, true).await,
            Handler::DetachPolicy => minio_iam::associate(&self.iam, req, false).await,
            Handler::PolicyEntities => minio_iam::policy_entities(&self.iam, &req).await,
            Handler::AccountInfo => minio_iam::account_info(self, identity, context, &req).await,
            Handler::AddServiceAccount => {
                minio_service_accounts::add(&self.iam, identity, privileged, req).await
            }
            Handler::UpdateServiceAccount => minio_service_accounts::update(&self.iam, req).await,
            Handler::InfoServiceAccount => {
                minio_service_accounts::info(&self.iam, identity, privileged, &req).await
            }
            Handler::ListServiceAccounts => {
                minio_service_accounts::list(&self.iam, identity, privileged, &req).await
            }
            Handler::DeleteServiceAccount => {
                minio_service_accounts::delete(&self.iam, identity, privileged, &req)
            }
            Handler::ListAccessKeysBulk => {
                minio_service_accounts::list_bulk(&self.iam, (identity, context), privileged, &req)
                    .await
            }
            Handler::InfoAccessKey => {
                minio_service_accounts::info_access_key(&self.iam, identity, privileged, &req).await
            }
            Handler::TemporaryAccountInfo => minio_service_accounts::temporary_account_info(&req),
            Handler::MinioInfo(kind) => kind.call(self, &req).await,
            Handler::MinioService => minio_service::call(self, &req),
            Handler::MinioMetrics(call) => call.call(self, &req),
            Handler::MinioHeal(call) => call.call(self, req).await,
            Handler::MinioKms(call) => call.call(self, &req, (identity, context)).await,
            Handler::MinioSpeedtest(call) => call.call(self, &req, (identity, context)).await,
            Handler::MinioLdap(call) => call.call(self, req, (identity, context), privileged).await,
            Handler::MinioConfig(call) => call.call(self, req).await,
            Handler::Query => unreachable!("the Query APIs are served by iam_api"),
        }
    }

    /// Listens for the events the request asks for: one bucket's, with
    /// `s3:ListenBucketNotification` on it, or every bucket's, with `s3:ListenNotification`.
    async fn listen(
        &self,
        scope: listen::Scope,
        req: S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        observe::name(
            &req.extensions,
            match scope {
                listen::Scope::Bucket(_) => "ListenBucketNotification",
                listen::Scope::Every => "ListenNotification",
            },
        );
        if let (Some(seen), Some(credentials)) =
            (req.extensions.get::<Arc<Seen>>(), &req.credentials)
        {
            seen.signed_by(&credentials.access_key);
        }
        // A bucket's policy may let anyone listen, as it may let anyone read.
        let identity = match req.credentials {
            Some(_) => self.authenticate(&req)?,
            None => Arc::new(Identity::anonymous()),
        };
        let client = req.extensions.get::<Client>().copied().unwrap_or_default();
        let context = base_context(&identity, &req.headers, client, &self.iam.account());
        let allowed = match &scope {
            listen::Scope::Bucket(bucket) => {
                let rules = self.rules.of(bucket).await?;
                allows(
                    &identity,
                    &context,
                    "s3:ListenBucketNotification",
                    &teifs_policy::bucket_arn(bucket),
                    Some(&rules),
                )
            }
            listen::Scope::Every => identity
                .decide(&context, "s3:ListenNotification", ANY, None)
                .is_allowed(),
        };
        if !allowed {
            return Err(denied());
        }
        if let listen::Scope::Bucket(bucket) = &scope {
            self.store.head_bucket(bucket).await.s3()?;
        }
        let request = listen::Request::read(scope, req.uri.query().unwrap_or_default())?;
        let body = self
            .events
            .listeners()
            .follow(request, self.tracers.stopping());
        Ok(listen::response(body))
    }

    /// Who signed a request: refused when unsigned, or signed with a key IAM doesn't
    /// know (one deleted since the signature was checked, say) or a session that's over.
    fn authenticate(&self, req: &S3Request<Body>) -> S3Result<Arc<Identity>> {
        let credentials = req.credentials.as_ref().ok_or_else(denied)?;
        let token = crate::access::security_token(&req.headers, &req.uri);
        crate::access::identify(&self.iam, &credentials.access_key, token.as_deref())
    }
}

/// Whether a `MinIO` call is on the access key that signed it: `?accessKey=` names it.
fn on_own_key(req: &S3Request<Body>) -> bool {
    let Some(own) = minio_iam::caller_key(req) else {
        return false;
    };
    form_urlencoded::parse(req.uri.query().unwrap_or_default().as_bytes())
        .any(|(name, value)| name == "accessKey" && value == own)
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

/// An answer's body that s3s's request log shows by its size only, never its content: the
/// IAM, STS and admin APIs answer with access keys, session tokens and IAM exports, and
/// s3s logs whole responses at `DEBUG`.
pub(crate) fn unlogged(bytes: impl Into<Bytes>) -> Body {
    Body::http_body(http_body_util::Full::new(bytes.into()))
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

    #[test]
    fn unlogged_bodies_show_their_size_only() {
        let body = unlogged(b"<SecretAccessKey>wJalrXUtnFEMI</SecretAccessKey>".to_vec());
        let shown = format!("{body:?}");
        assert!(!shown.contains("wJalr"), "{shown}");
        assert_eq!(
            http_body::Body::size_hint(&body).exact(),
            Some(48),
            "{shown}"
        );
    }

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

    /// The endpoint tables of `docs/ADMIN_API.md`.
    fn reference() -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for (api, heading) in [
            (Api::Admin, "The admin API"),
            (Api::Control, "S3 Control"),
            (Api::Query, "IAM and STS"),
            (Api::Minio, "MinIO's admin and KMS APIs"),
        ] {
            let _ = write!(
                out,
                "\n### {heading}\n\n| Method | Path | What it does | Who may |\n|---|---|---|---|\n"
            );
            for e in endpoints().filter(|e| e.api == api) {
                let who = match (e.action, e.root_only) {
                    (Some(action), _) if e.own_key => {
                        format!("`{action}`, or anyone on their own key unless denied")
                    }
                    (Some(action), _) => match e.or_actions {
                        [] => format!("`{action}`"),
                        [or] => format!("`{action}` or `{or}`"),
                        [between @ .., last] => {
                            let mut listed = format!("`{action}`");
                            for other in between {
                                let _ = write!(listed, ", `{other}`");
                            }
                            format!("{listed} or `{last}`")
                        }
                    },
                    (None, false) if e.own_key => "anyone who signs, about themselves".to_owned(),
                    (None, true) => "root user".to_owned(),
                    (None, false) => "the action each call names".to_owned(),
                };
                let _ = writeln!(
                    out,
                    "| `{}` | `{}` | {} | {who} |",
                    e.method, e.path, e.about
                );
            }
        }
        out.push('\n');
        out
    }

    #[test]
    fn the_admin_api_reference_is_current() {
        const START: &str = "<!-- generated: endpoints -->\n";
        const END: &str = "<!-- end generated -->";
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/ADMIN_API.md");
        let doc = std::fs::read_to_string(path).unwrap();
        let (before, rest) = doc.split_once(START).expect("the start marker");
        let (_, after) = rest.split_once(END).expect("the end marker");
        let current = format!("{before}{START}{}{END}{after}", reference());
        if std::env::var_os("UPDATE_DOCS").is_some() {
            std::fs::write(path, &current).unwrap();
            return;
        }
        assert!(
            doc == current,
            "docs/ADMIN_API.md is out of date: run this test with UPDATE_DOCS=1"
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
                Needs::Signed => assert_eq!(e.handler, Handler::AccountInfo),
                Needs::ServiceAction => assert_eq!(e.handler, Handler::MinioService),
                Needs::Root => assert_ne!(e.api, Api::Query),
                Needs::Action(action, resource) => {
                    assert!(action.contains(':') && !resource.is_empty(), "{e:?}");
                    let service = match e.api {
                        Api::Admin => "teifs:",
                        Api::Minio if e.path.starts_with(MINIO_KMS) => "kms:",
                        Api::Minio => "admin:",
                        Api::Query | Api::Control => "s3:",
                    };
                    assert!(action.starts_with(service), "{e:?}");
                }
                Needs::AnyAction(actions) => {
                    assert_eq!(e.api, Api::Minio);
                    assert!(actions.len() >= 2, "{e:?}");
                    assert!(actions.iter().all(|a| a.starts_with("admin:")), "{e:?}");
                }
                Needs::OnBucket(action) => {
                    assert!(e.api == Api::Control && action.starts_with("s3:"), "{e:?}");
                    assert!(matches!(e.handler, Handler::Tags(_)), "{e:?}");
                }
                Needs::OnKmsKey(action) => {
                    assert!(e.path.starts_with(MINIO_KMS) && action.starts_with("kms:"));
                    assert!(matches!(e.handler, Handler::MinioKms(_)), "{e:?}");
                }
                Needs::OnQueryBucket(action)
                | Needs::OrOwnKey(action)
                | Needs::NotDenied(action)
                | Needs::OrOwnAccount(action) => {
                    assert!(e.api == Api::Minio && action.starts_with("admin:"), "{e:?}");
                }
            }
            if e.api == Api::Minio && !e.path.starts_with(MINIO_KMS) {
                assert!(e.path.starts_with(MINIO_ADMIN), "{e:?}");
                let v4 = e.path.replace(MINIO_ADMIN, MINIO_ADMIN_V4);
                assert!(std::ptr::eq(endpoint(e.api, &method, &v4).unwrap(), e));
            }
        }
        assert!(endpoint(Api::Control, &Method::PATCH, control::PUBLIC_ACCESS_BLOCK).is_none());
        assert!(endpoint(Api::Control, &Method::GET, "/v20180820/other").is_none());
        let tags = endpoint(
            Api::Control,
            &Method::GET,
            "/v20180820/tags/arn%3Aaws%3As3%3A%3A%3Ab",
        );
        assert_eq!(tags.unwrap().path, control::TAGS);
        assert!(endpoint(Api::Control, &Method::GET, "/v20180820/tags/").is_none());
        assert!(endpoint(Api::Control, &Method::PUT, "/v20180820/tags/x").is_none());
        assert!(endpoint(Api::Control, &Method::GET, "/v20180820/tag/x").is_none());
    }
}
