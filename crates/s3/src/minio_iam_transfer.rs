//! `MinIO`'s IAM export and import (`mc admin cluster iam export|import`): a zip of
//! `iam-assets/*.json` in `MinIO`'s formats, so IAM moves between TeiFS and `MinIO`.
//!
//! The zip holds users' and service accounts' secrets as they are, so unlike `MinIO`
//! (which lets `admin:ExportIAM` and `admin:ImportIAM` do it) only the root user may
//! export or import one, as with TeiFS's own export with secrets.

use std::{collections::BTreeMap, io::Read as _, time::SystemTime};

use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use teifs_iam::{
    MinioIamEntities, MinioIamImport, MinioImportGroup, MinioImportResult, MinioImportUser,
};
use teifs_types::admin::{ExportedServiceAccount, IamExport};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    admin::{self, json},
    minio_iam::minio_error,
    minio_profile::archive,
    routes::{Routes, s3_refusal, signed_body, unlogged},
};

/// The folder of the zip the files are in.
const ASSETS: &str = "iam-assets";
const POLICIES: &str = "policies.json";
const USERS: &str = "users.json";
const GROUPS: &str = "groups.json";
const SERVICE_ACCOUNTS: &str = "svcaccts.json";
const USER_MAPPINGS: &str = "user_mappings.json";
const GROUP_MAPPINGS: &str = "group_mappings.json";
const STS_MAPPINGS: &str = "stsuser_mappings.json";

/// What a built-in policy's name starts with in an export.
const BUILTIN_ARN: &str = "arn:aws:iam::aws:policy/";
/// `MinIO`'s expiry of a service account that never expires: the Unix epoch.
const NEVER: &str = "1970-01-01T00:00:00Z";
/// The largest zip an import takes, and the largest file in it.
const MAX_ZIP_BYTES: usize = 16 << 20;
const MAX_FILE_BYTES: u64 = 64 << 20;

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `GET export-iam`.
    Export,
    /// `PUT import-iam`: answers nothing.
    Import,
    /// `PUT import-iam-v2`: answers what it did.
    ImportV2,
}

impl Call {
    /// The call's name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Export => "ExportIAM",
            Self::Import => "ImportIAM",
            Self::ImportV2 => "ImportIAMV2",
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        mut req: S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        if self == Self::Export {
            let files = export(
                &routes.iam.export(true),
                routes.iam.root_access_key().as_deref(),
            );
            let zip = archive(files.into_iter()).map_err(|err| {
                tracing::error!(error = %err, "the IAM export couldn't be zipped");
                admin::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "The IAM export couldn't be zipped.",
                )
            })?;
            let mut response = S3Response::new(unlogged(zip));
            response.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            return Ok(response);
        }
        let body = signed_body(&mut req, MAX_ZIP_BYTES)
            .await
            .map_err(s3_refusal)?;
        let import = read(&body, routes.iam.root_access_key().as_deref(), now_ms())?;
        let result = routes.iam.minio_import(&import).map_err(minio_error)?;
        if self == Self::Import {
            return Ok(S3Response::new(Body::empty()));
        }
        Ok(json(&ImportResult::from(result)))
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| NEVER.to_owned())
}

/// A policy's name as `MinIO` names it: a built-in one without its ARN.
fn policy_name(name: &str) -> &str {
    name.strip_prefix(BUILTIN_ARN).unwrap_or(name)
}

/// `MinIO`'s `MappedPolicy`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MappedPolicy {
    #[serde(default)]
    version: i64,
    #[serde(rename = "policy", default)]
    policies: String,
    #[serde(default, skip_deserializing)]
    updated_at: String,
}

impl MappedPolicy {
    fn new(policies: &[String], now: &str) -> Self {
        Self {
            version: 1,
            policies: policies
                .iter()
                .map(|p| policy_name(p))
                .collect::<Vec<_>>()
                .join(","),
            updated_at: now.to_owned(),
        }
    }

    fn names(&self) -> Vec<String> {
        self.policies
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// madmin's `AddOrUpdateUserReq`, as `users.json` holds each user.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserEntry {
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    status: String,
}

/// `MinIO`'s `GroupInfo`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupEntry {
    #[serde(default)]
    version: i64,
    #[serde(default)]
    status: String,
    #[serde(default)]
    members: Option<Vec<String>>,
    #[serde(default, skip_deserializing)]
    updated_at: String,
}

/// madmin's `SRSvcAccCreate`, as `svcaccts.json` holds each service account.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceAccountEntry {
    #[serde(default)]
    parent: String,
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    session_policy: Value,
    #[serde(default)]
    status: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiration: Option<String>,
}

/// `MinIO`'s files for an account's IAM, exported with secrets: its own policies, its
/// users named as an access key of theirs (as `MinIO`'s are), groups, service accounts
/// (the root user's under `root`'s access key) and the policies mapped to each.
fn export(export: &IamExport, root: Option<&str>) -> Vec<(String, Vec<u8>)> {
    let now = rfc3339(OffsetDateTime::now_utc());
    let policies: BTreeMap<&str, Value> = export
        .policies
        .iter()
        .filter_map(|p| {
            let document = p.versions.iter().find(|v| v.is_default)?;
            Some((
                p.name.as_str(),
                serde_json::from_str(&document.document).ok()?,
            ))
        })
        .collect();
    let mut users = BTreeMap::new();
    let mut user_mappings = BTreeMap::new();
    for user in &export.users {
        let Some(secret) = user
            .access_keys
            .iter()
            .find(|k| k.id == user.name)
            .and_then(|k| k.secret.clone())
        else {
            continue;
        };
        let status = if user.disabled { "disabled" } else { "enabled" };
        users.insert(
            user.name.as_str(),
            UserEntry {
                secret_key: secret,
                status: status.to_owned(),
            },
        );
        if !user.attached.is_empty() {
            user_mappings.insert(user.name.as_str(), MappedPolicy::new(&user.attached, &now));
        }
    }
    let mut groups = BTreeMap::new();
    let mut group_mappings = BTreeMap::new();
    for group in &export.groups {
        let members = export
            .users
            .iter()
            .filter(|u| u.groups.contains(&group.name))
            .map(|u| u.name.clone())
            .collect();
        let status = if group.disabled {
            "disabled"
        } else {
            "enabled"
        };
        groups.insert(
            group.name.as_str(),
            GroupEntry {
                version: 1,
                status: status.to_owned(),
                members: Some(members),
                updated_at: now.clone(),
            },
        );
        if !group.attached.is_empty() {
            group_mappings.insert(
                group.name.as_str(),
                MappedPolicy::new(&group.attached, &now),
            );
        }
    }
    let mut sts_mappings = BTreeMap::new();
    for mapping in &export.ldap_policies {
        let map = if mapping.entity == "group" {
            &mut group_mappings
        } else {
            &mut sts_mappings
        };
        map.insert(
            mapping.dn.as_str(),
            MappedPolicy::new(&mapping.policies, &now),
        );
    }
    let service_accounts: BTreeMap<&str, ServiceAccountEntry> = export
        .service_accounts
        .iter()
        .filter_map(|a| Some((a.id.as_str(), service_account(a, root)?)))
        .collect();
    vec![
        file(POLICIES, &policies),
        file(USERS, &users),
        file(GROUPS, &groups),
        file(SERVICE_ACCOUNTS, &service_accounts),
        file(USER_MAPPINGS, &user_mappings),
        file(GROUP_MAPPINGS, &group_mappings),
        file(STS_MAPPINGS, &sts_mappings),
    ]
}

/// A file of the zip: its path and its JSON.
fn file(name: &str, value: &impl Serialize) -> (String, Vec<u8>) {
    let json = serde_json::to_vec(value).expect("an export serializes");
    (format!("{ASSETS}/{name}"), json)
}

/// A file's map, empty if the zip hasn't the file.
fn parse<T: serde::de::DeserializeOwned>(
    name: &str,
    bytes: Option<Zeroizing<Vec<u8>>>,
) -> S3Result<BTreeMap<String, T>> {
    let Some(bytes) = bytes else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_slice::<Option<BTreeMap<String, T>>>(&bytes)
        .map(Option::unwrap_or_default)
        .map_err(|e| {
            admin::error(
                StatusCode::BAD_REQUEST,
                "XMinioAdminConfigBadJSON",
                format!("{ASSETS}/{name}: {e}"),
            )
        })
}

fn service_account(a: &ExportedServiceAccount, root: Option<&str>) -> Option<ServiceAccountEntry> {
    let parent = a.parent.as_deref().or(root)?.to_owned();
    let mut claims = BTreeMap::new();
    claims.insert("parent".to_owned(), Value::from(parent.clone()));
    if let Some(username) = &a.ldap_username {
        claims.insert("ldapUser".to_owned(), Value::from(parent.clone()));
        claims.insert("ldapUsername".to_owned(), Value::from(username.clone()));
    }
    let session_policy = a
        .policy
        .as_deref()
        .and_then(|p| serde_json::from_str(p).ok())
        .unwrap_or(Value::Null);
    claims.insert(
        "sa-policy".to_owned(),
        Value::from(if session_policy.is_null() {
            "inherited-policy"
        } else {
            "embedded-policy"
        }),
    );
    let expiration = a.expires_ms.map_or_else(
        || NEVER.to_owned(),
        |ms| {
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
                .map_or_else(|_| NEVER.to_owned(), rfc3339)
        },
    );
    Some(ServiceAccountEntry {
        parent,
        access_key: a.id.clone(),
        secret_key: a.secret.clone()?,
        groups: None,
        claims,
        session_policy,
        status: if a.active { "on" } else { "off" }.to_owned(),
        name: a.name.clone(),
        description: a.description.clone(),
        expiration: Some(expiration),
    })
}

/// What a zip of `MinIO`'s files brings: each file is optional.
fn read(zip: &[u8], root: Option<&str>, now_ms: i64) -> S3Result<MinioIamImport> {
    let invalid =
        |message: String| admin::error(StatusCode::BAD_REQUEST, "InvalidRequest", message);
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip))
        .map_err(|e| invalid(format!("The body isn't a zip: {e}")))?;
    let mut file = |name: &str| -> S3Result<Option<Zeroizing<Vec<u8>>>> {
        let path = format!("{ASSETS}/{name}");
        let entry = match archive.by_name(&path) {
            Ok(entry) => entry,
            Err(zip::result::ZipError::FileNotFound) => return Ok(None),
            Err(e) => return Err(invalid(format!("{path}: {e}"))),
        };
        let mut bytes = Zeroizing::new(Vec::new());
        entry
            .take(MAX_FILE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| invalid(format!("{path}: {e}")))?;
        Ok(Some(bytes))
    };
    let policies: BTreeMap<String, Value> = parse(POLICIES, file(POLICIES)?)?;
    let users: BTreeMap<String, UserEntry> = parse(USERS, file(USERS)?)?;
    let groups: BTreeMap<String, GroupEntry> = parse(GROUPS, file(GROUPS)?)?;
    let accounts: BTreeMap<String, ServiceAccountEntry> =
        parse(SERVICE_ACCOUNTS, file(SERVICE_ACCOUNTS)?)?;
    let mappings = |name: &str, bytes| -> S3Result<Vec<(String, Vec<String>)>> {
        Ok(parse::<MappedPolicy>(name, bytes)?
            .into_iter()
            .map(|(name, m)| {
                let names = m.names();
                (name, names)
            })
            .collect())
    };
    let user_policies = mappings(USER_MAPPINGS, file(USER_MAPPINGS)?)?;
    let group_policies = mappings(GROUP_MAPPINGS, file(GROUP_MAPPINGS)?)?;
    let sts_policies = mappings(STS_MAPPINGS, file(STS_MAPPINGS)?)?;
    Ok(MinioIamImport {
        policies: policies
            .into_iter()
            .map(|(name, document)| {
                let empty = document
                    .get("Statement")
                    .is_none_or(|s| s.as_array().is_some_and(Vec::is_empty) || s.is_null());
                (name, (!empty).then(|| document.to_string()))
            })
            .collect(),
        users: users
            .into_iter()
            .map(|(access_key, user)| MinioImportUser {
                access_key,
                secret: Zeroizing::new(user.secret_key),
                enabled: user.status != "disabled",
            })
            .collect(),
        groups: groups
            .into_iter()
            .map(|(name, group)| MinioImportGroup {
                name,
                members: group.members.unwrap_or_default(),
                enabled: group.status != "disabled",
            })
            .collect(),
        service_accounts: accounts
            .into_iter()
            .map(|(id, a)| imported_account(id, a, root, now_ms))
            .collect(),
        user_policies,
        group_policies,
        sts_policies,
    })
}

fn imported_account(
    id: String,
    a: ServiceAccountEntry,
    root: Option<&str>,
    now_ms: i64,
) -> ExportedServiceAccount {
    let ldap_username = a
        .claims
        .get("ldapUsername")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let parent = if root == Some(a.parent.as_str()) && ldap_username.is_none() {
        None
    } else {
        Some(a.parent)
    };
    let policy = match a.session_policy {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text),
        document => Some(document.to_string()),
    };
    let expires_ms = a
        .expiration
        .as_deref()
        .and_then(|e| OffsetDateTime::parse(e, &Rfc3339).ok())
        .map(|at| i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX))
        .filter(|ms| *ms > 0);
    ExportedServiceAccount {
        id,
        parent,
        ldap_username,
        active: a.status != "off",
        policy,
        name: a.name,
        description: a.description,
        expires_ms,
        created_ms: now_ms,
        secret: Some(a.secret_key),
    }
}

/// madmin's `ImportIAMResult`.
#[derive(Debug, Serialize)]
struct ImportResult {
    #[serde(skip_serializing_if = "Entities::is_empty")]
    skipped: Entities,
    #[serde(skip_serializing_if = "Entities::is_empty")]
    removed: Entities,
    #[serde(skip_serializing_if = "Entities::is_empty")]
    added: Entities,
    #[serde(skip_serializing_if = "Failures::is_empty")]
    failed: Failures,
}

/// madmin's `IAMEntities`.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Entities {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    users: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    service_accounts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_policies: Vec<BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    group_policies: Vec<BTreeMap<String, Vec<String>>>,
    #[serde(rename = "stsPolicies", skip_serializing_if = "Vec::is_empty")]
    sts_policies: Vec<BTreeMap<String, Vec<String>>>,
}

impl Entities {
    fn is_empty(&self) -> bool {
        self.policies.is_empty()
            && self.users.is_empty()
            && self.groups.is_empty()
            && self.service_accounts.is_empty()
            && self.user_policies.is_empty()
            && self.group_policies.is_empty()
            && self.sts_policies.is_empty()
    }
}

fn maps(pairs: Vec<(String, Vec<String>)>) -> Vec<BTreeMap<String, Vec<String>>> {
    pairs
        .into_iter()
        .map(|(name, policies)| BTreeMap::from([(name, policies)]))
        .collect()
}

impl From<MinioIamEntities> for Entities {
    fn from(e: MinioIamEntities) -> Self {
        Self {
            policies: e.policies,
            users: e.users,
            groups: e.groups,
            service_accounts: e.service_accounts,
            user_policies: maps(e.user_policies),
            group_policies: maps(e.group_policies),
            sts_policies: maps(e.sts_policies),
        }
    }
}

/// madmin's `IAMErrEntities`.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Failures {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    users: Vec<Failed>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<Failed>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    service_accounts: Vec<Failed>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_policies: Vec<Failed>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    group_policies: Vec<Failed>,
    #[serde(rename = "stsPolicies", skip_serializing_if = "Vec::is_empty")]
    sts_policies: Vec<Failed>,
}

impl Failures {
    fn is_empty(&self) -> bool {
        self.users.is_empty()
            && self.groups.is_empty()
            && self.service_accounts.is_empty()
            && self.user_policies.is_empty()
            && self.group_policies.is_empty()
            && self.sts_policies.is_empty()
    }
}

/// madmin's `IAMErrEntity` and `IAMErrPolicyEntity`.
#[derive(Debug, Serialize)]
struct Failed {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policies: Option<Vec<String>>,
    error: String,
}

impl From<MinioImportResult> for ImportResult {
    fn from(r: MinioImportResult) -> Self {
        let named = |list: Vec<(String, String)>| {
            list.into_iter()
                .map(|(name, error)| Failed {
                    name,
                    policies: None,
                    error,
                })
                .collect()
        };
        let mapped = |list: Vec<(String, Vec<String>, String)>| {
            list.into_iter()
                .map(|(name, policies, error)| Failed {
                    name,
                    policies: Some(policies),
                    error,
                })
                .collect()
        };
        let f = r.failed;
        Self {
            skipped: r.skipped.into(),
            removed: r.removed.into(),
            added: r.added.into(),
            failed: Failures {
                users: named(f.users),
                groups: named(f.groups),
                service_accounts: named(f.service_accounts),
                user_policies: mapped(f.user_policies),
                group_policies: mapped(f.group_policies),
                sts_policies: mapped(f.sts_policies),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    fn account(parent: Option<&str>, ldap_username: Option<&str>) -> ExportedServiceAccount {
        ExportedServiceAccount {
            id: "svc".to_owned(),
            parent: parent.map(str::to_owned),
            ldap_username: ldap_username.map(str::to_owned),
            active: false,
            policy: Some(LISTER.to_owned()),
            name: "backup".to_owned(),
            description: String::new(),
            expires_ms: Some(1_900_000_000_000),
            created_ms: 1,
            secret: Some("svc-secret-key".to_owned()),
        }
    }

    const LISTER: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;

    /// An account through `MinIO`'s format and back.
    fn round_trip(a: &ExportedServiceAccount) -> (ServiceAccountEntry, ExportedServiceAccount) {
        let entry = service_account(a, Some("root-key")).unwrap();
        let json = serde_json::to_vec(&entry).unwrap();
        let read: ServiceAccountEntry = serde_json::from_slice(&json).unwrap();
        (
            entry,
            imported_account("svc".to_owned(), read, Some("root-key"), 5),
        )
    }

    #[test]
    fn service_accounts_keep_their_parent_policy_and_expiry() {
        let dn = "uid=dillon,ou=people,dc=example,dc=org";
        let ldap = account(Some(dn), Some("dillon"));
        let (entry, back) = round_trip(&ldap);
        assert_eq!(entry.claims["ldapUser"], dn);
        assert_eq!(entry.claims["ldapUsername"], "dillon");
        assert_eq!(entry.status, "off");
        assert_eq!(entry.expiration.as_deref(), Some("2030-03-17T17:46:40Z"));
        let policy = |a: &ExportedServiceAccount| {
            serde_json::from_str::<Value>(a.policy.as_deref().unwrap()).unwrap()
        };
        assert_eq!(policy(&back), policy(&ldap));
        assert_eq!(
            back,
            ExportedServiceAccount {
                created_ms: 5,
                policy: back.policy.clone(),
                ..ldap
            }
        );

        let (entry, back) = round_trip(&account(None, None));
        assert_eq!(entry.parent, "root-key");
        assert_eq!(back.parent, None, "the root user's again");
        let (_, back) = round_trip(&account(Some("bob"), None));
        assert_eq!(back.parent.as_deref(), Some("bob"));

        // `MinIO`'s session policy may come as a string, and its "never" is the epoch.
        let mut entry = service_account(&account(Some("bob"), None), None).unwrap();
        entry.session_policy = Value::from(LISTER);
        entry.expiration = Some(NEVER.to_owned());
        let back = imported_account("svc".to_owned(), entry, None, 5);
        assert_eq!(
            (back.policy.as_deref(), back.expires_ms),
            (Some(LISTER), None)
        );
    }

    #[test]
    fn mapped_policies_are_minio_s_names() {
        let mapped = MappedPolicy::new(
            &[
                "arn:aws:iam::aws:policy/readonly".to_owned(),
                "mine".to_owned(),
            ],
            "now",
        );
        assert_eq!(mapped.policies, "readonly,mine");
        assert_eq!(mapped.names(), ["readonly", "mine"]);
    }
}
