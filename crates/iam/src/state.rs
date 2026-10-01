//! IAM's state in memory: every entity, by id, with its policies parsed. Changes clone
//! the state (entities are behind `Arc`s, so that's cheap), change the clone and swap it
//! in once the database has the same change.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use teifs_crypto::DataKey;
use teifs_meta::{
    AccessKeyRow, IamRows, InlineRow, LdapPolicyRow, LdapSessionRow, OidcProviderRow, PolicyRow,
    PolicyVersionRow, RoleRow,
};
use teifs_policy::{Kind as PolicyKind, Policy};
use zeroize::Zeroizing;

use crate::{IamError, LdapEntity, Result};

/// A policy document: the text as given (returned as is) and what it says.
#[derive(Debug, Clone)]
pub(crate) struct Document {
    pub(crate) text: Arc<str>,
    pub(crate) policy: Arc<Policy>,
    /// Characters other than white space: what IAM's size limits count.
    pub(crate) size: usize,
}

impl Document {
    /// Checks and parses a policy given to IAM for a user, group or role.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        Self::parse_as(text, PolicyKind::Identity)
    }

    /// Checks and parses a role's trust policy, within its size limit.
    pub(crate) fn trust(text: &str) -> Result<Self> {
        let document = Self::parse_as(text, PolicyKind::Trust)?;
        if document.size > crate::rules::TRUST_SIZE {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for ACLSizePerRole: {}",
                crate::rules::TRUST_SIZE
            )));
        }
        Ok(document)
    }

    fn parse_as(text: &str, kind: PolicyKind) -> Result<Self> {
        let size = crate::rules::document(text)?;
        let policy = Policy::parse(text, kind)
            .map_err(|e| IamError::MalformedPolicyDocument(e.to_string()))?;
        Ok(Self {
            text: text.into(),
            policy: Arc::new(policy),
            size,
        })
    }

    /// A stored document; one that no longer parses stops IAM from starting rather than
    /// being skipped (skipping a Deny would widen access).
    fn stored(text: &str, place: &str) -> Result<Self> {
        Self::parse(text).map_err(|e| IamError::Stored(format!("{place}: {e}")))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct User {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) created_ms: i64,
    /// The managed policy that is its permissions boundary.
    pub(crate) boundary: Option<String>,
    /// Keys compare without case (AWS, for users); the stored case is the latest given.
    pub(crate) tags: Vec<(String, String)>,
    pub(crate) inline: BTreeMap<String, Document>,
    pub(crate) attached: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Group {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) created_ms: i64,
    pub(crate) members: BTreeSet<String>,
    pub(crate) inline: BTreeMap<String, Document>,
    pub(crate) attached: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Role {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) description: String,
    pub(crate) created_ms: i64,
    /// Who may assume it.
    pub(crate) trust: Document,
    /// The users and roles `trust` names (ARN → unique id when it was set): a principal
    /// deleted and made again under the same name isn't trusted, as on AWS.
    pub(crate) principals: BTreeMap<String, String>,
    /// The longest session it allows, in seconds.
    pub(crate) max_session: u32,
    /// The managed policy that is its permissions boundary.
    pub(crate) boundary: Option<String>,
    /// Keys compare without case, as for users.
    pub(crate) tags: Vec<(String, String)>,
    pub(crate) inline: BTreeMap<String, Document>,
    pub(crate) attached: BTreeSet<String>,
}

impl Role {
    /// The row that stores it.
    pub(crate) fn row(&self) -> RoleRow {
        RoleRow {
            id: self.id.clone(),
            name: self.name.clone(),
            path: self.path.clone(),
            description: self.description.clone(),
            trust: self.trust.text.to_string(),
            principals: serde_json::to_string(&self.principals)
                .expect("a map of strings serializes"),
            max_session: self.max_session,
            created_ms: self.created_ms,
            boundary: self.boundary.clone(),
        }
    }
}

/// An OpenID Connect identity provider: whose tokens `AssumeRoleWithWebIdentity` takes.
#[derive(Debug, Clone)]
pub(crate) struct OidcProvider {
    pub(crate) id: String,
    /// Its URL, as given: the issuer (`iss`) its tokens name.
    pub(crate) url: String,
    /// The audiences (`aud`) its tokens may be for.
    pub(crate) client_ids: Vec<String>,
    /// The SHA-1 thumbprints of the certificates it may serve its keys with.
    pub(crate) thumbprints: Vec<String>,
    pub(crate) created_ms: i64,
    /// Keys compare without case, as for users.
    pub(crate) tags: Vec<(String, String)>,
}

impl OidcProvider {
    /// Its URL without the scheme: the last part of its ARN.
    pub(crate) fn name(&self) -> &str {
        self.url
            .split_once("://")
            .map_or(self.url.as_str(), |(_, name)| name)
    }

    /// The row that stores it.
    pub(crate) fn row(&self) -> OidcProviderRow {
        let json = |list: &Vec<String>| serde_json::to_string(list).expect("strings serialize");
        OidcProviderRow {
            id: self.id.clone(),
            name: self.name().to_owned(),
            url: self.url.clone(),
            client_ids: json(&self.client_ids),
            thumbprints: json(&self.thumbprints),
            created_ms: self.created_ms,
        }
    }
}

/// The managed policies mapped to an LDAP user's or group's DN.
#[derive(Debug, Clone)]
pub(crate) struct LdapMapping {
    /// The DN, written in one form.
    pub(crate) dn: String,
    pub(crate) entity: LdapEntity,
    /// The policies, by id.
    pub(crate) policies: BTreeSet<String>,
}

/// A directory user with live sessions, as the directory last said.
#[derive(Debug, Clone)]
pub(crate) struct LdapSeen {
    /// Its DN, written in one form.
    pub(crate) dn: String,
    /// The name it signed in with, which group filters may use.
    pub(crate) username: String,
    /// Its groups' DNs.
    pub(crate) groups: Vec<String>,
    /// When the directory last said, in milliseconds since the Unix epoch.
    pub(crate) checked_ms: i64,
    /// When its last session expires: the record goes then.
    pub(crate) expires_ms: i64,
    /// Sessions of an older generation are revoked.
    pub(crate) generation: u32,
    /// Whether the directory no longer has it.
    pub(crate) gone: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Version {
    pub(crate) document: Document,
    pub(crate) created_ms: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct Managed {
    pub(crate) row: PolicyRow,
    pub(crate) versions: BTreeMap<u32, Version>,
    /// Keys are case sensitive (AWS, for policies).
    pub(crate) tags: Vec<(String, String)>,
}

impl Managed {
    /// The version in effect.
    pub(crate) fn default_document(&self) -> &Document {
        &self
            .versions
            .get(&self.row.default_version)
            .expect("a managed policy always has its default version")
            .document
    }
}

#[derive(Clone)]
pub(crate) struct Key {
    pub(crate) id: String,
    pub(crate) user: String,
    /// The secret, sealed as stored (kept so a status change rewrites the same bytes).
    pub(crate) sealed: Vec<u8>,
    pub(crate) secret: Arc<Zeroizing<String>>,
    pub(crate) active: bool,
    pub(crate) created_ms: i64,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("user", &self.user)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// Everything IAM knows, by id.
#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    pub(crate) account: Arc<str>,
    pub(crate) users: BTreeMap<String, Arc<User>>,
    pub(crate) groups: BTreeMap<String, Arc<Group>>,
    pub(crate) roles: BTreeMap<String, Arc<Role>>,
    pub(crate) oidc_providers: BTreeMap<String, Arc<OidcProvider>>,
    pub(crate) policies: BTreeMap<String, Arc<Managed>>,
    pub(crate) keys: BTreeMap<String, Arc<Key>>,
    /// The policies mapped to LDAP DNs, by DN.
    pub(crate) ldap_policies: BTreeMap<String, Arc<LdapMapping>>,
    /// Directory users with live sessions, by DN.
    pub(crate) ldap_sessions: BTreeMap<String, Arc<LdapSeen>>,
}

impl State {
    /// The state the database holds; `key` opens the secrets.
    pub(crate) fn load(account: &str, rows: IamRows, key: &DataKey) -> Result<Self> {
        let mut state = Self {
            account: account.into(),
            policies: load_policies(rows.policies, rows.versions, rows.policy_tags)?,
            keys: load_keys(rows.keys, key)?,
            oidc_providers: load_oidc_providers(rows.oidc_providers, rows.oidc_provider_tags)?,
            ldap_policies: load_ldap_policies(rows.ldap_policies)?,
            ldap_sessions: load_ldap_sessions(rows.ldap_sessions)?,
            ..Self::default()
        };
        let mut users: BTreeMap<String, User> = rows
            .users
            .into_iter()
            .map(|u| {
                let user = User {
                    id: u.id.clone(),
                    name: u.name,
                    path: u.path,
                    created_ms: u.created_ms,
                    boundary: u.boundary,
                    tags: Vec::new(),
                    inline: BTreeMap::new(),
                    attached: BTreeSet::new(),
                };
                (u.id, user)
            })
            .collect();
        let mut groups: BTreeMap<String, Group> = rows
            .groups
            .into_iter()
            .map(|g| {
                let group = Group {
                    id: g.id.clone(),
                    name: g.name,
                    path: g.path,
                    created_ms: g.created_ms,
                    members: BTreeSet::new(),
                    inline: BTreeMap::new(),
                    attached: BTreeSet::new(),
                };
                (g.id, group)
            })
            .collect();
        let mut roles = load_roles(rows.roles, rows.role_tags)?;
        for (user, key, value) in rows.user_tags {
            if let Some(u) = users.get_mut(&user) {
                u.tags.push((key, value));
            }
        }
        for (group, user) in rows.members {
            if let Some(g) = groups.get_mut(&group) {
                g.members.insert(user);
            }
        }
        for InlineRow {
            owner,
            name,
            document,
        } in rows.inline
        {
            let document =
                Document::stored(&document, &format!("inline policy {name} of {owner}"))?;
            if let Some(u) = users.get_mut(&owner) {
                u.inline.insert(name, document);
            } else if let Some(g) = groups.get_mut(&owner) {
                g.inline.insert(name, document);
            } else if let Some(r) = roles.get_mut(&owner) {
                r.inline.insert(name, document);
            }
        }
        for (owner, policy) in rows.attached {
            if let Some(u) = users.get_mut(&owner) {
                u.attached.insert(policy);
            } else if let Some(g) = groups.get_mut(&owner) {
                g.attached.insert(policy);
            } else if let Some(r) = roles.get_mut(&owner) {
                r.attached.insert(policy);
            }
        }
        state.users = users.into_iter().map(|(id, u)| (id, Arc::new(u))).collect();
        state.groups = groups
            .into_iter()
            .map(|(id, g)| (id, Arc::new(g)))
            .collect();
        state.roles = roles.into_iter().map(|(id, r)| (id, Arc::new(r))).collect();
        Ok(state)
    }

    /// The user with this name (compared without case).
    pub(crate) fn user_named(&self, name: &str) -> Result<&Arc<User>> {
        self.users
            .values()
            .find(|u| u.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                IamError::NoSuchEntity(format!("The user with name {name} cannot be found."))
            })
    }

    /// The group with this name.
    pub(crate) fn group_named(&self, name: &str) -> Result<&Arc<Group>> {
        self.groups
            .values()
            .find(|g| g.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                IamError::NoSuchEntity(format!("The group with name {name} cannot be found."))
            })
    }

    /// The role with this name (compared without case).
    pub(crate) fn role_named(&self, name: &str) -> Result<&Arc<Role>> {
        self.roles
            .values()
            .find(|r| r.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                IamError::NoSuchEntity(format!("The role with name {name} cannot be found."))
            })
    }

    /// The OpenID Connect provider with this ARN (its URL compared without case).
    pub(crate) fn oidc_provider_by_arn(&self, arn: &str) -> Result<&Arc<OidcProvider>> {
        let name = arn
            .strip_prefix("arn:aws:iam::")
            .and_then(|rest| rest.split_once(':'))
            .and_then(|(account, rest)| Some((account, rest.strip_prefix("oidc-provider/")?)))
            .filter(|(_, name)| !name.is_empty());
        let Some((account, name)) = name else {
            return Err(IamError::InvalidInput(format!(
                "`{arn}` isn't an OpenID Connect provider's ARN"
            )));
        };
        self.oidc_providers
            .values()
            .find(|p| account == &*self.account && p.name().eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                IamError::NoSuchEntity(format!("OpenIDConnect Provider not found for arn {arn}"))
            })
    }

    /// The managed policy with this ARN.
    pub(crate) fn policy_by_arn(&self, arn: &str) -> Result<&Arc<Managed>> {
        let missing =
            || IamError::NoSuchEntity(format!("Policy {arn} does not exist or is not attachable."));
        let rest = arn
            .strip_prefix("arn:aws:iam::")
            .ok_or_else(|| IamError::InvalidInput(format!("`{arn}` isn't an IAM policy ARN")))?;
        let (account, rest) = rest
            .split_once(':')
            .ok_or_else(|| IamError::InvalidInput(format!("`{arn}` isn't an IAM policy ARN")))?;
        let Some(path_name) = rest.strip_prefix("policy/") else {
            return Err(IamError::InvalidInput(format!(
                "`{arn}` isn't an IAM policy ARN"
            )));
        };
        if account != &*self.account {
            return Err(missing());
        }
        let (path, name) = match path_name.rfind('/') {
            Some(i) => (&path_name[..=i], &path_name[i + 1..]),
            None => ("", path_name),
        };
        let path = format!("/{path}");
        self.policies
            .values()
            .find(|p| p.row.path == path && p.row.name.eq_ignore_ascii_case(name))
            .ok_or_else(missing)
    }

    /// The groups a user is in.
    pub(crate) fn groups_of<'a>(
        &'a self,
        user: &'a str,
    ) -> impl Iterator<Item = &'a Arc<Group>> + 'a {
        self.groups
            .values()
            .filter(move |g| g.members.contains(user))
    }

    /// How many users, groups and roles a managed policy is attached to.
    pub(crate) fn attachments(&self, policy: &str) -> usize {
        self.users
            .values()
            .filter(|u| u.attached.contains(policy))
            .count()
            + self
                .groups
                .values()
                .filter(|g| g.attached.contains(policy))
                .count()
            + self
                .roles
                .values()
                .filter(|r| r.attached.contains(policy))
                .count()
    }

    /// How many LDAP users and groups a managed policy is mapped to.
    pub(crate) fn ldap_uses(&self, policy: &str) -> usize {
        self.ldap_policies
            .values()
            .filter(|m| m.policies.contains(policy))
            .count()
    }

    /// How many users and roles have a managed policy as their permissions boundary.
    pub(crate) fn boundary_uses(&self, policy: &str) -> usize {
        self.users
            .values()
            .filter(|u| u.boundary.as_deref() == Some(policy))
            .count()
            + self
                .roles
                .values()
                .filter(|r| r.boundary.as_deref() == Some(policy))
                .count()
    }

    pub(crate) fn user_arn(&self, user: &User) -> String {
        arn(&self.account, "user", &user.path, &user.name)
    }

    pub(crate) fn group_arn(&self, group: &Group) -> String {
        arn(&self.account, "group", &group.path, &group.name)
    }

    pub(crate) fn role_arn(&self, role: &Role) -> String {
        arn(&self.account, "role", &role.path, &role.name)
    }

    pub(crate) fn oidc_provider_arn(&self, provider: &OidcProvider) -> String {
        format!(
            "arn:aws:iam::{}:oidc-provider/{}",
            self.account,
            provider.name()
        )
    }

    pub(crate) fn policy_arn(&self, policy: &PolicyRow) -> String {
        arn(&self.account, "policy", &policy.path, &policy.name)
    }

    /// Whether a name is taken by another entity of the same kind (without case).
    pub(crate) fn user_name_taken(&self, name: &str, except: Option<&str>) -> bool {
        self.users
            .values()
            .any(|u| Some(u.id.as_str()) != except && u.name.eq_ignore_ascii_case(name))
    }

    pub(crate) fn group_name_taken(&self, name: &str, except: Option<&str>) -> bool {
        self.groups
            .values()
            .any(|g| Some(g.id.as_str()) != except && g.name.eq_ignore_ascii_case(name))
    }

    /// The unique id of the user or role with this ARN in this account, if there's one.
    pub(crate) fn id_of(&self, arn: &str) -> Option<&str> {
        let users = self.users.values().map(|u| (self.user_arn(u), &u.id));
        let roles = self.roles.values().map(|r| (self.role_arn(r), &r.id));
        users
            .chain(roles)
            .find(|(a, _)| a == arn)
            .map(|(_, id)| id.as_str())
    }
}

fn load_ldap_policies(rows: Vec<LdapPolicyRow>) -> Result<BTreeMap<String, Arc<LdapMapping>>> {
    let mut mappings: BTreeMap<String, LdapMapping> = BTreeMap::new();
    for row in rows {
        let entity = LdapEntity::parse(&row.entity).ok_or_else(|| {
            IamError::Stored(format!(
                "the LDAP mapping of {} is a {}",
                row.dn, row.entity
            ))
        })?;
        mappings
            .entry(row.dn.clone())
            .or_insert_with(|| LdapMapping {
                dn: row.dn,
                entity,
                policies: BTreeSet::new(),
            })
            .policies
            .insert(row.policy_id);
    }
    Ok(mappings
        .into_iter()
        .map(|(dn, m)| (dn, Arc::new(m)))
        .collect())
}

fn load_ldap_sessions(rows: Vec<LdapSessionRow>) -> Result<BTreeMap<String, Arc<LdapSeen>>> {
    rows.into_iter()
        .map(|row| {
            let groups = serde_json::from_str(&row.groups)
                .map_err(|e| IamError::Stored(format!("the LDAP groups of {}: {e}", row.dn)))?;
            let seen = LdapSeen {
                dn: row.dn.clone(),
                username: row.username,
                groups,
                checked_ms: row.checked_ms,
                expires_ms: row.expires_ms,
                generation: row.generation,
                gone: row.gone,
            };
            Ok((row.dn, Arc::new(seen)))
        })
        .collect()
}

fn load_policies(
    rows: Vec<PolicyRow>,
    version_rows: Vec<PolicyVersionRow>,
    tag_rows: Vec<(String, String, String)>,
) -> Result<BTreeMap<String, Arc<Managed>>> {
    let mut policies = BTreeMap::new();
    let mut tags: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (policy, key, value) in tag_rows {
        tags.entry(policy).or_default().push((key, value));
    }
    let mut versions: BTreeMap<String, BTreeMap<u32, Version>> = BTreeMap::new();
    for v in version_rows {
        let document = Document::stored(
            &v.document,
            &format!("policy {} v{}", v.policy_id, v.version),
        )?;
        versions.entry(v.policy_id).or_default().insert(
            v.version,
            Version {
                document,
                created_ms: v.created_ms,
            },
        );
    }
    for row in rows {
        let versions = versions.remove(&row.id).unwrap_or_default();
        if !versions.contains_key(&row.default_version) {
            return Err(IamError::Stored(format!(
                "policy {} has no default version",
                row.name
            )));
        }
        let tags = tags.remove(&row.id).unwrap_or_default();
        policies.insert(
            row.id.clone(),
            Arc::new(Managed {
                row,
                versions,
                tags,
            }),
        );
    }
    Ok(policies)
}

/// Roles, with their tags; their policies are added by the caller.
fn load_roles(
    rows: Vec<RoleRow>,
    tags: Vec<(String, String, String)>,
) -> Result<BTreeMap<String, Role>> {
    let mut roles: BTreeMap<String, Role> = rows
        .into_iter()
        .map(|r| {
            let place = format!("role {}", r.name);
            let role = Role {
                trust: Document::parse_as(&r.trust, PolicyKind::Trust)
                    .map_err(|e| IamError::Stored(format!("{place}'s trust policy: {e}")))?,
                principals: serde_json::from_str(&r.principals)
                    .map_err(|e| IamError::Stored(format!("{place}'s principals: {e}")))?,
                id: r.id.clone(),
                name: r.name,
                path: r.path,
                description: r.description,
                created_ms: r.created_ms,
                max_session: r.max_session,
                boundary: r.boundary,
                tags: Vec::new(),
                inline: BTreeMap::new(),
                attached: BTreeSet::new(),
            };
            Ok((r.id, role))
        })
        .collect::<Result<_>>()?;
    for (role, key, value) in tags {
        if let Some(r) = roles.get_mut(&role) {
            r.tags.push((key, value));
        }
    }
    Ok(roles)
}

fn load_oidc_providers(
    rows: Vec<OidcProviderRow>,
    tags: Vec<(String, String, String)>,
) -> Result<BTreeMap<String, Arc<OidcProvider>>> {
    let mut providers: BTreeMap<String, OidcProvider> = rows
        .into_iter()
        .map(|p| {
            let list = |json: &str, what: &str| {
                serde_json::from_str(json).map_err(|e| {
                    IamError::Stored(format!("OpenID Connect provider {}'s {what}: {e}", p.url))
                })
            };
            let provider = OidcProvider {
                client_ids: list(&p.client_ids, "client ids")?,
                thumbprints: list(&p.thumbprints, "thumbprints")?,
                id: p.id.clone(),
                url: p.url,
                created_ms: p.created_ms,
                tags: Vec::new(),
            };
            Ok((p.id, provider))
        })
        .collect::<Result<_>>()?;
    for (provider, key, value) in tags {
        if let Some(p) = providers.get_mut(&provider) {
            p.tags.push((key, value));
        }
    }
    Ok(providers
        .into_iter()
        .map(|(id, p)| (id, Arc::new(p)))
        .collect())
}

fn load_keys(rows: Vec<AccessKeyRow>, key: &DataKey) -> Result<BTreeMap<String, Arc<Key>>> {
    let mut keys = BTreeMap::new();
    for row in rows {
        let mut secret = key
            .open_secret(row.id.as_bytes(), &row.secret)
            .map_err(|_| IamError::Stored(format!("access key {} doesn't open", row.id)))?;
        let secret = String::from_utf8(std::mem::take(&mut *secret))
            .map_err(|_| IamError::Stored(format!("access key {} isn't text", row.id)))?;
        keys.insert(
            row.id.clone(),
            Arc::new(Key {
                id: row.id,
                user: row.user_id,
                sealed: row.secret,
                secret: Arc::new(Zeroizing::new(secret)),
                active: row.active,
                created_ms: row.created_ms,
            }),
        );
    }
    Ok(keys)
}

/// The ARN of the `kind` (`user`, `group`, `role`, `policy`) called `name` under `path`.
pub(crate) fn arn(account: &str, kind: &str, path: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:{kind}{path}{name}")
}
