//! Moving an account's IAM between drives: [`Iam::export`] writes it out with entities
//! naming each other by name, and [`Iam::import`] makes it again in an empty IAM through
//! the same operations (and so the same checks) as the IAM API, all in one change: an
//! import that fails anywhere leaves nothing behind.

use std::{collections::BTreeMap, sync::Arc};

use teifs_crypto::DataKey;
use teifs_meta::IamWrite;
use teifs_types::admin::{
    ExportedGroup, ExportedKey, ExportedOidcProvider, ExportedPolicy, ExportedRole,
    ExportedSamlProvider, ExportedServiceAccount, ExportedUser, ExportedVersion, IAM_FORMAT,
    IamExport, ImportReport, LdapPolicyMapping, Tag,
};

use crate::{
    ACCOUNT, Draft, Iam, IamError, LdapEntity, NewOidcProvider, NewRole, NewSamlProvider, Owner,
    Result, SamlProviderUpdate, ldap,
    rules::{self, MAX_KEYS_PER_USER},
    state::{Key, Parent, State},
};

/// What a built-in policy's ARN starts with, as an export names it.
const BUILTIN_ARN: &str = "arn:aws:iam::aws:policy/";

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

/// The names of the policies with these ids, sorted: a built-in one's ARN, which an
/// account's own policy may share the name of.
fn policy_names<'a>(state: &State, ids: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut names: Vec<String> = ids
        .filter_map(|id| state.policies.get(id))
        .map(|p| {
            if p.builtin {
                state.policy_arn(p)
            } else {
                p.row.name.clone()
            }
        })
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

/// The SAML providers, with their private keys if `key` is given to open them.
fn export_saml(state: &State, key: Option<&DataKey>) -> Vec<ExportedSamlProvider> {
    let mut providers: Vec<ExportedSamlProvider> = state
        .saml_providers
        .values()
        .map(|p| ExportedSamlProvider {
            name: p.name.clone(),
            metadata: p.metadata.to_string(),
            assertion_encryption_mode: p.encryption.map(|e| e.as_str().to_owned()),
            private_keys: key
                .map(|key| {
                    p.keys
                        .iter()
                        .filter_map(|k| key.open_secret(k.id.as_bytes(), &k.sealed).ok())
                        .map(|der| crate::saml::private_key::pem(&der))
                        .collect()
                })
                .unwrap_or_default(),
            tags: tags(&p.tags),
        })
        .collect();
    providers.sort_by_cached_key(|p| p.name.to_ascii_lowercase());
    providers
}

/// Makes the exported SAML providers, with their keys.
fn import_saml(d: &mut Draft<'_>, providers: &[ExportedSamlProvider]) -> Result<()> {
    for provider in providers {
        let mode = provider.assertion_encryption_mode.as_deref();
        if mode == Some("Required") && provider.private_keys.is_empty() {
            return Err(IamError::InvalidInput(format!(
                "SAML provider {} takes only encrypted assertions, and the export has no \
                 private key for it: export with secrets.",
                provider.name
            )));
        }
        let created = d.create_saml_provider(&NewSamlProvider {
            name: &provider.name,
            metadata: &provider.metadata,
            encryption: mode,
            private_key: provider.private_keys.first().map(String::as_str),
            tags: &pairs(&provider.tags),
        })?;
        for pem in provider.private_keys.iter().skip(1) {
            d.update_saml_provider(
                &created.arn,
                &SamlProviderUpdate {
                    add_key: Some(pem),
                    ..SamlProviderUpdate::default()
                },
            )?;
        }
    }
    Ok(())
}

fn export(state: &State, secrets: bool, key: &DataKey) -> IamExport {
    let mut policies: Vec<ExportedPolicy> = state
        .own_policies()
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
            disabled: g.disabled,
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
                disabled: u.disabled,
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
    let mut oidc_providers: Vec<ExportedOidcProvider> = state
        .oidc_providers
        .values()
        .map(|p| ExportedOidcProvider {
            url: p.url.clone(),
            client_ids: p.client_ids.clone(),
            thumbprints: p.thumbprints.clone(),
            tags: tags(&p.tags),
        })
        .collect();
    oidc_providers.sort_by_cached_key(|p| p.url.to_ascii_lowercase());
    IamExport {
        format: IAM_FORMAT.to_owned(),
        account: state.account.to_string(),
        policies,
        groups,
        users,
        roles,
        oidc_providers,
        saml_providers: export_saml(state, secrets.then_some(key)),
        ldap_policies: export_ldap(state),
        service_accounts: export_service_accounts(state, secrets),
    }
}

/// The service accounts, oldest first, with their secrets if `secrets`.
fn export_service_accounts(state: &State, secrets: bool) -> Vec<ExportedServiceAccount> {
    let mut accounts: Vec<ExportedServiceAccount> = state
        .service_accounts
        .values()
        .filter_map(|a| {
            let (parent, ldap_username) = match &a.parent {
                Parent::User(id) => (Some(state.users.get(id)?.name.clone()), None),
                Parent::Root => (None, None),
                Parent::Ldap { dn, username } => (Some(dn.clone()), Some(username.clone())),
            };
            Some(ExportedServiceAccount {
                id: a.id.clone(),
                parent,
                ldap_username,
                active: a.active,
                policy: a.policy.as_ref().map(|p| p.text.to_string()),
                name: a.name.clone(),
                description: a.description.clone(),
                expires_ms: a.expires_ms,
                created_ms: a.created_ms,
                secret: secrets.then(|| a.secret.as_str().to_owned()),
            })
        })
        .collect();
    accounts.sort_by(|a, b| (a.created_ms, &a.id).cmp(&(b.created_ms, &b.id)));
    accounts
}

/// The policies mapped to LDAP users and groups, by name.
fn export_ldap(state: &State) -> Vec<LdapPolicyMapping> {
    // In order of DN: the state keeps them so.
    state
        .ldap_policies
        .values()
        .map(|m| LdapPolicyMapping {
            dn: m.dn.clone(),
            entity: m.entity.as_str().to_owned(),
            policies: policy_names(state, m.policies.iter()),
        })
        .collect()
}

/// Maps the export's policies to its LDAP users and groups, checked as the admin API
/// checks them (but for the directory, which the import doesn't ask).
fn import_ldap(
    d: &mut Draft<'_>,
    mappings: &[LdapPolicyMapping],
    arn: &impl Fn(&str) -> Result<String>,
) -> Result<()> {
    for mapping in mappings {
        let dn = ldap::dn::normalize(&mapping.dn).map_err(IamError::InvalidInput)?;
        let entity = LdapEntity::parse(&mapping.entity).ok_or_else(|| {
            IamError::InvalidInput(format!(
                "{} is an LDAP {:?}: give user or group.",
                mapping.dn, mapping.entity
            ))
        })?;
        let policies = mapping
            .policies
            .iter()
            .map(|name| arn(name))
            .collect::<Result<Vec<_>>>()?;
        d.map_ldap_policies(&dn, entity, &policies, true)?;
    }
    Ok(())
}

/// Whether `account` is an AWS account id: 12 digits.
fn is_account(account: &str) -> bool {
    account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())
}

impl Iam {
    /// The account's IAM; access keys' secrets only if `secrets`.
    #[must_use]
    pub fn export(&self, secrets: bool) -> IamExport {
        let inner = self.inner();
        export(&inner.state, secrets, &inner.key)
    }

    /// Makes `export` in this IAM, which must have no users, groups, roles, policies,
    /// OpenID Connect providers or keys; with `adopt_account`, the account takes the export's id too. All or nothing.
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
                && s.own_policies().next().is_none()
                && s.oidc_providers.is_empty()
                && s.saml_providers.is_empty()
                && s.ldap_policies.is_empty()
                && s.service_accounts.is_empty())
            {
                return Err(IamError::EntityAlreadyExists(
                    "IAM already has users, groups, roles, policies or identity providers: \
                     import only into an empty IAM."
                        .into(),
                ));
            }
            if adopt_account && *d.state.account != *export.account {
                d.state.account = export.account.as_str().into();
                d.write(IamWrite::SetMeta(ACCOUNT.into(), export.account.clone()));
            }
            let arns = import_policies(d, &export.policies)?;
            let arn = |name: &str| exported_arn(&arns, name);
            for group in &export.groups {
                d.create_group(&group.name, Some(&group.path))?;
                if group.disabled {
                    let mut made = Arc::unwrap_or_clone(d.group(&group.name)?);
                    made.disabled = true;
                    d.save_group(made);
                }
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
                oidc_providers: export.oidc_providers.len(),
                saml_providers: export.saml_providers.len(),
                ldap_policies: export.ldap_policies.len(),
                access_keys: 0,
                service_accounts: 0,
                keys_without_secrets: Vec::new(),
            };
            import_users(d, &export.users, &arn, &mut report)?;
            for account in &export.service_accounts {
                if account.secret.is_some() {
                    d.import_service_account(account)?;
                    report.service_accounts += 1;
                } else {
                    report.keys_without_secrets.push(account.id.clone());
                }
            }
            // Before the roles, whose trust policies may name them.
            for provider in &export.oidc_providers {
                d.create_oidc_provider(&NewOidcProvider {
                    url: &provider.url,
                    client_ids: &provider.client_ids,
                    thumbprints: &provider.thumbprints,
                    tags: &pairs(&provider.tags),
                })?;
            }
            import_saml(d, &export.saml_providers)?;
            import_roles(d, &export.roles, &arn)?;
            import_ldap(d, &export.ldap_policies, &arn)?;
            Ok(report)
        })
    }
}

/// Creates the users with their keys, memberships and policies, counting the keys in
/// `report`.
fn import_users(
    d: &mut Draft<'_>,
    users: &[ExportedUser],
    arn: &impl Fn(&str) -> Result<String>,
    report: &mut ImportReport,
) -> Result<()> {
    for user in users {
        let boundary = user.boundary.as_deref().map(arn).transpose()?;
        d.create_user(
            &user.name,
            Some(&user.path),
            &pairs(&user.tags),
            boundary.as_deref(),
        )?;
        if user.disabled {
            let mut made = Arc::unwrap_or_clone(d.user(&user.name)?);
            made.disabled = true;
            d.save_user(made);
        }
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
    Ok(())
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

/// The ARN of the policy an export names: one of its own by name (`arns`), or a built-in
/// one by ARN.
fn exported_arn(arns: &BTreeMap<String, String>, name: &str) -> Result<String> {
    if name.starts_with(BUILTIN_ARN) {
        return Ok(name.to_owned());
    }
    arns.get(&name.to_ascii_lowercase())
        .cloned()
        .ok_or_else(|| IamError::NoSuchEntity(format!("The export has no policy called {name}.")))
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
        rules::access_key_id(id).map_err(IamError::InvalidInput)?;
        rules::secret_key(secret)
            .map_err(|e| IamError::InvalidInput(format!("Access key {id}: {e}")))?;
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
