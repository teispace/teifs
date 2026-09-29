//! Moving an account's IAM between drives: [`Iam::export`] writes it out with entities
//! naming each other by name, and [`Iam::import`] makes it again in an empty IAM through
//! the same operations (and so the same checks) as the IAM API, all in one change: an
//! import that fails anywhere leaves nothing behind.

use std::{collections::BTreeMap, sync::Arc};

use teifs_meta::IamWrite;
use teifs_types::admin::{
    ExportedGroup, ExportedKey, ExportedPolicy, ExportedRole, ExportedUser, ExportedVersion,
    IAM_FORMAT, IamExport, ImportReport, Tag,
};

use crate::{
    ACCOUNT, Draft, Iam, IamError, NewRole, Owner, Result,
    rules::MAX_KEYS_PER_USER,
    state::{Key, State},
};

/// The shortest secret key an import takes: 192 bits of base64, less than any TeiFS or
/// AWS key has, so a weak secret can't be brought in.
const MIN_SECRET: usize = 32;

fn tags(tags: &[(String, String)]) -> Vec<Tag> {
    tags.iter()
        .map(|(key, value)| Tag {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

fn pairs(tags: &[Tag]) -> Vec<(String, String)> {
    tags.iter()
        .map(|t| (t.key.clone(), t.value.clone()))
        .collect()
}

/// The names of the policies with these ids, sorted.
fn policy_names<'a>(state: &State, ids: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut names: Vec<String> = ids
        .filter_map(|id| state.policies.get(id))
        .map(|p| p.row.name.clone())
        .collect();
    names.sort_by_cached_key(|n| n.to_ascii_lowercase());
    names
}

fn inline(documents: &BTreeMap<String, crate::state::Document>) -> BTreeMap<String, String> {
    documents
        .iter()
        .map(|(name, doc)| (name.clone(), doc.text.to_string()))
        .collect()
}

fn export(state: &State, secrets: bool) -> IamExport {
    let mut policies: Vec<ExportedPolicy> = state
        .policies
        .values()
        .map(|p| ExportedPolicy {
            name: p.row.name.clone(),
            path: p.row.path.clone(),
            description: p.row.description.clone(),
            tags: tags(&p.tags),
            versions: p
                .versions
                .iter()
                .map(|(number, v)| ExportedVersion {
                    document: v.document.text.to_string(),
                    is_default: *number == p.row.default_version,
                })
                .collect(),
        })
        .collect();
    policies.sort_by_cached_key(|p| p.name.to_ascii_lowercase());
    let mut groups: Vec<ExportedGroup> = state
        .groups
        .values()
        .map(|g| ExportedGroup {
            name: g.name.clone(),
            path: g.path.clone(),
            inline: inline(&g.inline),
            attached: policy_names(state, g.attached.iter()),
        })
        .collect();
    groups.sort_by_cached_key(|g| g.name.to_ascii_lowercase());
    let mut users: Vec<ExportedUser> = state
        .users
        .values()
        .map(|u| {
            let mut keys: Vec<&Arc<Key>> = state.keys.values().filter(|k| k.user == u.id).collect();
            keys.sort_by(|a, b| a.created_ms.cmp(&b.created_ms).then(a.id.cmp(&b.id)));
            let mut groups: Vec<String> = state.groups_of(&u.id).map(|g| g.name.clone()).collect();
            groups.sort_by_cached_key(|n| n.to_ascii_lowercase());
            ExportedUser {
                name: u.name.clone(),
                path: u.path.clone(),
                tags: tags(&u.tags),
                boundary: policy_names(state, u.boundary.iter()).pop(),
                groups,
                inline: inline(&u.inline),
                attached: policy_names(state, u.attached.iter()),
                access_keys: keys
                    .into_iter()
                    .map(|k| ExportedKey {
                        id: k.id.clone(),
                        active: k.active,
                        created_ms: k.created_ms,
                        secret: secrets.then(|| k.secret.as_str().to_owned()),
                    })
                    .collect(),
            }
        })
        .collect();
    users.sort_by_cached_key(|u| u.name.to_ascii_lowercase());
    let mut roles: Vec<ExportedRole> = state
        .roles
        .values()
        .map(|r| ExportedRole {
            name: r.name.clone(),
            path: r.path.clone(),
            description: r.description.clone(),
            trust_policy: r.trust.text.to_string(),
            max_session_duration: r.max_session,
            tags: tags(&r.tags),
            boundary: policy_names(state, r.boundary.iter()).pop(),
            inline: inline(&r.inline),
            attached: policy_names(state, r.attached.iter()),
        })
        .collect();
    roles.sort_by_cached_key(|r| r.name.to_ascii_lowercase());
    IamExport {
        format: IAM_FORMAT.to_owned(),
        account: state.account.to_string(),
        policies,
        groups,
        users,
        roles,
    }
}

/// Whether `account` is an AWS account id: 12 digits.
fn is_account(account: &str) -> bool {
    account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())
}

impl Iam {
    /// The account's IAM; access keys' secrets only if `secrets`.
    #[must_use]
    pub fn export(&self, secrets: bool) -> IamExport {
        export(&self.inner().state, secrets)
    }

    /// Makes `export` in this IAM, which must have no users, groups, roles, policies or
    /// keys;
    /// with `adopt_account`, the account takes the export's id too. All or nothing.
    pub fn import(&self, export: &IamExport, adopt_account: bool) -> Result<ImportReport> {
        if export.format != IAM_FORMAT {
            return Err(IamError::InvalidInput(format!(
                "Only exports in the {IAM_FORMAT} format can be imported, not {:?}.",
                export.format
            )));
        }
        if adopt_account && !is_account(&export.account) {
            return Err(IamError::InvalidInput(format!(
                "The export's account {:?} isn't 12 digits.",
                export.account
            )));
        }
        self.change(|d| {
            let s = &d.state;
            if !(s.users.is_empty()
                && s.groups.is_empty()
                && s.roles.is_empty()
                && s.policies.is_empty())
            {
                return Err(IamError::EntityAlreadyExists(
                    "IAM already has users, groups, roles or policies: import only into an \
                     empty IAM."
                        .into(),
                ));
            }
            if adopt_account && *d.state.account != *export.account {
                d.state.account = export.account.as_str().into();
                d.write(IamWrite::SetMeta(ACCOUNT.into(), export.account.clone()));
            }
            let arns = import_policies(d, &export.policies)?;
            let arn = |name: &str| {
                arns.get(&name.to_ascii_lowercase())
                    .cloned()
                    .ok_or_else(|| {
                        IamError::NoSuchEntity(format!("The export has no policy called {name}."))
                    })
            };
            for group in &export.groups {
                d.create_group(&group.name, Some(&group.path))?;
                for (name, document) in &group.inline {
                    d.put_inline(Owner::Group(&group.name), name, document)?;
                }
                for policy in &group.attached {
                    d.attach(Owner::Group(&group.name), &arn(policy)?)?;
                }
            }
            let mut report = ImportReport {
                account: d.state.account.to_string(),
                policies: export.policies.len(),
                groups: export.groups.len(),
                users: export.users.len(),
                roles: export.roles.len(),
                access_keys: 0,
                keys_without_secrets: Vec::new(),
            };
            for user in &export.users {
                let boundary = user.boundary.as_deref().map(arn).transpose()?;
                d.create_user(
                    &user.name,
                    Some(&user.path),
                    &pairs(&user.tags),
                    boundary.as_deref(),
                )?;
                for group in &user.groups {
                    d.add_user_to_group(group, &user.name)?;
                }
                for (name, document) in &user.inline {
                    d.put_inline(Owner::User(&user.name), name, document)?;
                }
                for policy in &user.attached {
                    d.attach(Owner::User(&user.name), &arn(policy)?)?;
                }
                for key in &user.access_keys {
                    if let Some(secret) = &key.secret {
                        d.import_key(&user.name, key, secret)?;
                        report.access_keys += 1;
                    } else {
                        report.keys_without_secrets.push(key.id.clone());
                    }
                }
            }
            import_roles(d, &export.roles, &arn)?;
            Ok(report)
        })
    }
}

/// Creates the roles once the users exist. A trust policy may name another role, so
/// every role is made first with a trust policy that trusts no one, then given its own.
fn import_roles(
    d: &mut Draft<'_>,
    roles: &[ExportedRole],
    arn: &impl Fn(&str) -> Result<String>,
) -> Result<()> {
    const NO_ONE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}"#;
    for role in roles {
        let boundary = role.boundary.as_deref().map(arn).transpose()?;
        d.create_role(
            &role.name,
            &NewRole {
                path: Some(&role.path),
                trust: NO_ONE,
                description: Some(&role.description),
                max_session: Some(role.max_session_duration),
                tags: &pairs(&role.tags),
                boundary: boundary.as_deref(),
            },
        )?;
        for (name, document) in &role.inline {
            d.put_inline(Owner::Role(&role.name), name, document)?;
        }
        for policy in &role.attached {
            d.attach(Owner::Role(&role.name), &arn(policy)?)?;
        }
    }
    for role in roles {
        d.set_trust(&role.name, &role.trust_policy)?;
    }
    Ok(())
}

/// Creates the policies with every version, the default one in effect: their ARNs by
/// lowercase name (names are unique without case).
fn import_policies(
    d: &mut Draft<'_>,
    policies: &[ExportedPolicy],
) -> Result<BTreeMap<String, String>> {
    let mut arns = BTreeMap::new();
    for policy in policies {
        let (Some(first), 1) = (
            policy.versions.first(),
            policy.versions.iter().filter(|v| v.is_default).count(),
        ) else {
            return Err(IamError::InvalidInput(format!(
                "The policy {} must have versions, exactly one of them the default.",
                policy.name
            )));
        };
        let info = d.create_policy(
            &policy.name,
            Some(&policy.path),
            Some(&policy.description),
            &first.document,
            &pairs(&policy.tags),
        )?;
        for version in &policy.versions[1..] {
            d.create_policy_version(&info.arn, &version.document, version.is_default)?;
        }
        arns.insert(policy.name.to_ascii_lowercase(), info.arn);
    }
    Ok(arns)
}

impl Draft<'_> {
    /// Adds an exported access key, with its id and secret, to a user.
    fn import_key(&mut self, user: &str, key: &ExportedKey, secret: &str) -> Result<()> {
        let id = &key.id;
        let id_ok = (16..=128).contains(&id.len())
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !id_ok {
            return Err(IamError::InvalidInput(format!(
                "The access key id {id:?} isn't 16 to 128 letters, digits or underscores."
            )));
        }
        let secret_ok = (MIN_SECRET..=128).contains(&secret.len())
            && secret.bytes().all(|b| b.is_ascii_graphic());
        if !secret_ok {
            return Err(IamError::InvalidInput(format!(
                "The secret of access key {id} isn't {MIN_SECRET} to 128 printable characters."
            )));
        }
        if !(0..=self.now).contains(&key.created_ms) {
            return Err(IamError::InvalidInput(format!(
                "The access key {id} was created at an impossible time."
            )));
        }
        if self.root == Some(id.as_str()) || self.state.keys.contains_key(id) {
            return Err(IamError::EntityAlreadyExists(format!(
                "The access key {id} is already in use."
            )));
        }
        let user = self.user(user)?;
        if self
            .state
            .keys
            .values()
            .filter(|k| k.user == user.id)
            .count()
            >= MAX_KEYS_PER_USER
        {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for AccessKeysPerUser: {MAX_KEYS_PER_USER}"
            )));
        }
        let secret = zeroize::Zeroizing::new(secret.to_owned());
        self.save_key(Key {
            sealed: self.key.seal_secret(id.as_bytes(), secret.as_bytes()),
            secret: Arc::new(secret),
            id: id.clone(),
            user: user.id.clone(),
            active: key.active,
            created_ms: key.created_ms,
        });
        Ok(())
    }
}
