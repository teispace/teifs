//! IAM as `MinIO`'s admin API shows and changes it (`mc admin user|group|policy`). A
//! `MinIO` user is named by its access key: here it's the IAM user of that name, signing
//! with an access key of that id, so users made through either API are the other's too.
//! A user or group can be disabled (its keys and sessions don't sign; its policies don't
//! count). Policies are named, the account's own before a built-in one.

use std::{collections::BTreeSet, sync::Arc};

use teifs_meta::IamWrite;
use zeroize::Zeroizing;

use super::Owner;
use crate::{
    Draft, Iam, IamError, builtin,
    rules::{self, MAX_KEYS_PER_USER, MAX_VERSIONS},
    state::{Group, Key, Managed, State, User},
};

/// Why a `MinIO` admin call failed, as `MinIO` names it.
#[derive(Debug, thiserror::Error)]
pub enum MinioError {
    /// No user has that name.
    #[error("The specified user does not exist.")]
    NoSuchUser,
    /// No group has that name.
    #[error("The specified group does not exist.")]
    NoSuchGroup,
    /// No policy has that name.
    #[error("The canned policy does not exist.")]
    NoSuchPolicy,
    /// A group with members can't be removed.
    #[error("The specified group is not empty - cannot remove it.")]
    GroupNotEmpty,
    /// Attaching or detaching changed nothing.
    #[error("The specified policy change is already in effect.")]
    AlreadyApplied,
    /// A policy attached to someone can't be removed.
    #[error("The policy cannot be removed, as it is in use")]
    PolicyInUse,
    /// The access key can't be a user's.
    #[error("{0}")]
    InvalidAccessKey(String),
    /// The secret key can't be used.
    #[error("{0}")]
    InvalidSecretKey(String),
    /// Something else asked is impossible.
    #[error("{0}")]
    InvalidArgument(String),
    /// IAM refused, as its own API would.
    #[error(transparent)]
    Iam(#[from] IamError),
}

impl MinioError {
    /// `MinIO`'s error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSuchUser => "XMinioAdminNoSuchUser",
            Self::NoSuchGroup => "XMinioAdminNoSuchGroup",
            Self::NoSuchPolicy => "XMinioAdminNoSuchPolicy",
            Self::GroupNotEmpty => "XMinioAdminGroupNotEmpty",
            Self::AlreadyApplied => "XMinioAdminPolicyChangeAlreadyApplied",
            Self::PolicyInUse => "XMinioIAMPolicyInUse",
            Self::InvalidAccessKey(_) => "XMinioAdminInvalidAccessKey",
            Self::InvalidSecretKey(_) => "XMinioAdminInvalidSecretKey",
            Self::InvalidArgument(_)
            | Self::Iam(IamError::InvalidInput(_) | IamError::LimitExceeded(_)) => {
                "XMinioAdminInvalidArgument"
            }
            Self::Iam(IamError::MalformedPolicyDocument(_)) => "XMinioMalformedIAMPolicy",
            Self::Iam(e) => e.code(),
        }
    }

    /// The HTTP status `MinIO` answers it with.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NoSuchUser | Self::NoSuchGroup | Self::NoSuchPolicy => 404,
            Self::GroupNotEmpty
            | Self::AlreadyApplied
            | Self::PolicyInUse
            | Self::InvalidAccessKey(_)
            | Self::InvalidSecretKey(_)
            | Self::InvalidArgument(_)
            | Self::Iam(
                IamError::MalformedPolicyDocument(_)
                | IamError::InvalidInput(_)
                | IamError::LimitExceeded(_),
            ) => 400,
            Self::Iam(e) => e.status(),
        }
    }
}

type Result<T> = std::result::Result<T, MinioError>;

/// A user, as `MinIO` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinioUser {
    /// Its name, which is its access key's id when `MinIO`'s API made it.
    pub name: String,
    /// Whether its keys and sessions sign.
    pub enabled: bool,
    /// The names of the policies attached to it, sorted.
    pub policies: Vec<String>,
    /// The names of its groups, sorted.
    pub groups: Vec<String>,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A group, as `MinIO` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinioGroup {
    /// Its name.
    pub name: String,
    /// Whether its policies count for its members.
    pub enabled: bool,
    /// Its members' names, sorted.
    pub members: Vec<String>,
    /// The names of the policies attached to it, sorted.
    pub policies: Vec<String>,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A managed policy, as `MinIO` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinioPolicy {
    /// Its name.
    pub name: String,
    /// Its document in effect.
    pub document: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// When its document in effect last changed.
    pub updated_ms: i64,
}

/// A change to a user (`MinIO`'s `add-user`): what's `None` stays as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct MinioUserChange<'a> {
    /// The secret of the access key named as the user (needed for a new user).
    pub secret: Option<&'a str>,
    /// Whether the user signs.
    pub enabled: Option<bool>,
    /// The policies attached to it instead of those it has.
    pub policies: Option<&'a [String]>,
}

/// A group and the policies attached to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPolicies {
    /// The group's name.
    pub group: String,
    /// The policies' names, sorted.
    pub policies: Vec<String>,
}

/// A user, its policies and its groups' (`MinIO`'s policy entities).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPolicies {
    /// The user's name.
    pub user: String,
    /// The policies attached to it.
    pub policies: Vec<String>,
    /// Its groups that have policies.
    pub groups: Vec<GroupPolicies>,
}

/// A policy and who has it attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHolders {
    /// The policy's name.
    pub policy: String,
    /// The users it's attached to, sorted.
    pub users: Vec<String>,
    /// The groups it's attached to, sorted.
    pub groups: Vec<String>,
}

/// Who has which policies (`MinIO`'s `policy-entities`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyEntities {
    /// By user.
    pub users: Vec<UserPolicies>,
    /// By group.
    pub groups: Vec<GroupPolicies>,
    /// By policy.
    pub policies: Vec<PolicyHolders>,
}

fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort_by_cached_key(|n| n.to_ascii_lowercase());
    names
}

/// The names of the policies with these ids, sorted.
fn names(state: &State, ids: &BTreeSet<String>) -> Vec<String> {
    sorted(
        ids.iter()
            .filter_map(|id| state.policies.get(id))
            .map(|p| p.row.name.clone())
            .collect(),
    )
}

fn user_named<'s>(state: &'s State, name: &str) -> Result<&'s Arc<User>> {
    state.user_named(name).map_err(|_| MinioError::NoSuchUser)
}

fn group_named<'s>(state: &'s State, name: &str) -> Result<&'s Arc<Group>> {
    state.group_named(name).map_err(|_| MinioError::NoSuchGroup)
}

fn policy_named<'s>(state: &'s State, name: &str) -> Result<&'s Arc<Managed>> {
    state.policy_named(name).ok_or(MinioError::NoSuchPolicy)
}

/// The account's own policy of this name.
fn own_policy<'s>(state: &'s State, name: &str) -> Option<&'s Arc<Managed>> {
    state
        .own_policies()
        .find(|p| p.row.name.eq_ignore_ascii_case(name))
}

fn minio_user(state: &State, user: &User) -> MinioUser {
    MinioUser {
        name: user.name.clone(),
        enabled: !user.disabled,
        policies: names(state, &user.attached),
        groups: sorted(state.groups_of(&user.id).map(|g| g.name.clone()).collect()),
        created_ms: user.created_ms,
    }
}

fn minio_group(state: &State, group: &Group) -> MinioGroup {
    MinioGroup {
        name: group.name.clone(),
        enabled: !group.disabled,
        members: sorted(
            group
                .members
                .iter()
                .filter_map(|id| state.users.get(id))
                .map(|u| u.name.clone())
                .collect(),
        ),
        policies: names(state, &group.attached),
        created_ms: group.created_ms,
    }
}

fn minio_policy(policy: &Managed) -> MinioPolicy {
    MinioPolicy {
        name: policy.row.name.clone(),
        document: policy.default_document().text.to_string(),
        created_ms: policy.row.created_ms,
        updated_ms: policy.row.updated_ms,
    }
}

/// Whether anything uses a policy: users, groups or roles it's attached to, users and
/// roles it bounds, or LDAP DNs it's mapped to.
fn in_use(state: &State, id: &str) -> bool {
    state.attachments(id) > 0 || state.boundary_uses(id) > 0 || state.ldap_uses(id) > 0
}

impl Draft<'_> {
    /// [`Iam::minio_set_user`], as part of a change.
    fn minio_set_user(&mut self, access_key: &str, change: MinioUserChange<'_>) -> Result<()> {
        rules::access_key_id(access_key).map_err(MinioError::InvalidAccessKey)?;
        if self.root == Some(access_key) {
            return Err(MinioError::InvalidAccessKey(
                "The access key is the root user's.".into(),
            ));
        }
        let existing = self.state.user_named(access_key).ok().cloned();
        if let Some(user) = &existing
            && user.name != access_key
        {
            return Err(MinioError::InvalidAccessKey(format!(
                "A user named {} exists.",
                user.name
            )));
        }
        if let Some(key) = self.state.keys.get(access_key)
            && existing.as_ref().is_none_or(|u| u.id != key.user)
        {
            return Err(MinioError::InvalidAccessKey(
                "The access key is another user's.".into(),
            ));
        }
        let user = if let Some(user) = existing {
            user
        } else {
            if change.secret.is_none() {
                return Err(MinioError::InvalidSecretKey(
                    "A new user needs a secret key.".into(),
                ));
            }
            self.create_user(access_key, None, &[], None)?;
            self.user(access_key)?
        };
        if let Some(secret) = change.secret {
            rules::secret_key(secret).map_err(MinioError::InvalidSecretKey)?;
            self.put_key(&user.id, access_key, secret)?;
        }
        if let Some(enabled) = change.enabled {
            self.set_user_enabled(&user.name, enabled)?;
        }
        if let Some(policies) = change.policies {
            self.replace_policies(Owner::User(&user.name), policies)?;
        }
        Ok(())
    }

    /// Sets the secret of access key `id` of user `user`, making it if it isn't there.
    fn put_key(&mut self, user: &str, id: &str, secret: &str) -> Result<()> {
        let existing = self.state.keys.get(id).cloned();
        if existing.is_none()
            && self.state.keys.values().filter(|k| k.user == user).count() >= MAX_KEYS_PER_USER
        {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for AccessKeysPerUser: {MAX_KEYS_PER_USER}"
            ))
            .into());
        }
        let secret = Zeroizing::new(secret.to_owned());
        self.save_key(Key {
            sealed: self.key.seal_secret(id.as_bytes(), secret.as_bytes()),
            secret: Arc::new(secret),
            id: id.to_owned(),
            user: user.to_owned(),
            active: existing.as_ref().is_none_or(|k| k.active),
            created_ms: existing.map_or(self.now, |k| k.created_ms),
        });
        Ok(())
    }

    /// Enables or disables a user (`MinIO`'s user status).
    pub(crate) fn set_user_enabled(&mut self, name: &str, enabled: bool) -> Result<()> {
        let user = user_named(&self.state, name)?.clone();
        if user.disabled == enabled {
            let mut user = Arc::unwrap_or_clone(user);
            user.disabled = !enabled;
            self.save_user(user);
        }
        Ok(())
    }

    /// Enables or disables a group (`MinIO`'s group status).
    pub(crate) fn set_group_enabled(&mut self, name: &str, enabled: bool) -> Result<()> {
        let group = group_named(&self.state, name)?.clone();
        if group.disabled == enabled {
            let mut group = Arc::unwrap_or_clone(group);
            group.disabled = !enabled;
            self.save_group(group);
        }
        Ok(())
    }

    /// Attaches exactly `policies` (by name) to a user or group.
    fn replace_policies(&mut self, owner: Owner<'_>, policies: &[String]) -> Result<()> {
        let wanted = policies
            .iter()
            .map(|name| policy_named(&self.state, name).map(|p| p.row.id.clone()))
            .collect::<Result<BTreeSet<_>>>()?;
        let had = self.owner(owner)?.attached().clone();
        for id in had.difference(&wanted) {
            let arn = self.state.policy_arn(&self.state.policies[id]);
            self.detach(owner, &arn)?;
        }
        for id in wanted.difference(&had) {
            let arn = self.state.policy_arn(&self.state.policies[id]);
            self.attach(owner, &arn)?;
        }
        Ok(())
    }

    /// Deletes a user with its keys, inline policies, attachments and memberships.
    fn minio_remove_user(&mut self, name: &str) -> Result<()> {
        let user = user_named(&self.state, name)?.clone();
        let keys: Vec<String> = self
            .state
            .keys
            .values()
            .filter(|k| k.user == user.id)
            .map(|k| k.id.clone())
            .collect();
        for id in keys {
            self.state.keys.remove(&id);
            self.write(IamWrite::DeleteKey(id));
        }
        for inline in user.inline.keys() {
            self.write(IamWrite::DeleteInline(user.id.clone(), inline.clone()));
        }
        for policy in &user.attached {
            self.write(IamWrite::Detach(user.id.clone(), policy.clone()));
        }
        let groups: Vec<String> = self
            .state
            .groups_of(&user.id)
            .map(|g| g.name.clone())
            .collect();
        for group in groups {
            self.remove_user_from_group(&group, &user.name)?;
        }
        self.state.users.remove(&user.id);
        self.write(IamWrite::DeleteUser(user.id.clone()));
        Ok(())
    }

    /// [`Iam::minio_update_group`], as part of a change.
    fn minio_update_group(
        &mut self,
        name: &str,
        members: &[String],
        remove: bool,
        enabled: Option<bool>,
    ) -> Result<()> {
        if remove {
            let group = group_named(&self.state, name)?.clone();
            if members.is_empty() {
                if !group.members.is_empty() {
                    return Err(MinioError::GroupNotEmpty);
                }
                self.remove_group(&group);
                return Ok(());
            }
            for member in members {
                let user = user_named(&self.state, member)?.clone();
                if group.members.contains(&user.id) {
                    self.remove_user_from_group(&group.name, &user.name)?;
                }
            }
        } else {
            for member in members {
                user_named(&self.state, member)?;
            }
            if self.state.group_named(name).is_err() {
                self.create_group(name, None)?;
            }
            for member in members {
                self.add_user_to_group(name, member)?;
            }
        }
        if let Some(enabled) = enabled {
            self.set_group_enabled(name, enabled)?;
        }
        Ok(())
    }

    /// Deletes an empty group with its inline policies and attachments.
    fn remove_group(&mut self, group: &Group) {
        for inline in group.inline.keys() {
            self.write(IamWrite::DeleteInline(group.id.clone(), inline.clone()));
        }
        for policy in &group.attached {
            self.write(IamWrite::Detach(group.id.clone(), policy.clone()));
        }
        self.state.groups.remove(&group.id);
        self.write(IamWrite::DeleteGroup(group.id.clone()));
    }

    /// [`Iam::minio_put_policy`], as part of a change.
    fn minio_put_policy(&mut self, name: &str, document: &str, over_builtin: bool) -> Result<()> {
        if let Some(own) = own_policy(&self.state, name).cloned() {
            // As `MinIO` replaces a policy: a new version in effect, the oldest other
            // dropped when there are already as many as a policy keeps.
            if own.versions.len() >= MAX_VERSIONS {
                let oldest = own
                    .versions
                    .keys()
                    .copied()
                    .find(|v| *v != own.row.default_version)
                    .expect("a policy with several versions has one not in effect");
                let mut own = Arc::unwrap_or_clone(own.clone());
                own.versions.remove(&oldest);
                self.write(IamWrite::DeleteVersion(own.row.id.clone(), oldest));
                self.state
                    .policies
                    .insert(own.row.id.clone(), Arc::new(own));
            }
            let arn = self.state.policy_arn(&own);
            self.create_policy_version(&arn, document, true)?;
            return Ok(());
        }
        if !over_builtin
            && builtin::BUILTINS
                .iter()
                .any(|b| b.name.eq_ignore_ascii_case(name))
        {
            return Err(MinioError::InvalidArgument(format!(
                "{name} is a built-in policy: override it with overrideBuiltin=true."
            )));
        }
        self.create_policy(name, None, None, document, &[])?;
        Ok(())
    }

    /// [`Iam::minio_remove_policy`], as part of a change.
    fn minio_remove_policy(&mut self, name: &str) -> Result<()> {
        let Some(own) = own_policy(&self.state, name).cloned() else {
            return Err(if self.state.policy_named(name).is_some() {
                MinioError::InvalidArgument(format!(
                    "{name} is a built-in policy: it can't be removed."
                ))
            } else {
                MinioError::NoSuchPolicy
            });
        };
        if in_use(&self.state, &own.row.id) {
            return Err(MinioError::PolicyInUse);
        }
        self.state.policies.remove(&own.row.id);
        self.write(IamWrite::DeletePolicy(own.row.id.clone()));
        Ok(())
    }

    /// [`Iam::minio_associate`], as part of a change.
    fn minio_associate(
        &mut self,
        owner: Owner<'_>,
        policies: &[String],
        attach: bool,
    ) -> Result<Vec<String>> {
        if policies.is_empty() {
            return Err(MinioError::InvalidArgument(
                "No policy names were given.".into(),
            ));
        }
        match owner {
            Owner::User(name) => {
                user_named(&self.state, name)?;
            }
            Owner::Group(name) => {
                group_named(&self.state, name)?;
            }
            Owner::Role(_) => {
                return Err(MinioError::InvalidArgument(
                    "Policies are attached to users and groups.".into(),
                ));
            }
        }
        let mut changed = Vec::new();
        for name in policies {
            let policy = policy_named(&self.state, name)?.clone();
            let has = self.owner(owner)?.attached().contains(&policy.row.id);
            if has != attach {
                let arn = self.state.policy_arn(&policy);
                if attach {
                    self.attach(owner, &arn)?;
                } else {
                    self.detach(owner, &arn)?;
                }
                changed.push(policy.row.name.clone());
            }
        }
        if changed.is_empty() {
            return Err(MinioError::AlreadyApplied);
        }
        Ok(changed)
    }
}

/// `MinIO`'s admin API.
impl Iam {
    /// Makes user `access_key`, signing with an access key of that id, or changes it
    /// (`MinIO`'s `add-user`).
    pub fn minio_set_user(&self, access_key: &str, change: MinioUserChange<'_>) -> Result<()> {
        self.change(|d| d.minio_set_user(access_key, change))
    }

    /// A user (`user-info`).
    pub fn minio_user(&self, name: &str) -> Result<MinioUser> {
        self.view(|s| Ok(minio_user(s, user_named(s, name)?)))
    }

    /// Every user, by name (`list-users`).
    #[must_use]
    pub fn minio_users(&self) -> Vec<MinioUser> {
        self.view(|s| {
            let mut users: Vec<MinioUser> = s.users.values().map(|u| minio_user(s, u)).collect();
            users.sort_by_cached_key(|u| u.name.to_ascii_lowercase());
            users
        })
    }

    /// Deletes a user and everything that's only its (`remove-user`).
    pub fn minio_remove_user(&self, name: &str) -> Result<()> {
        self.change(|d| d.minio_remove_user(name))
    }

    /// Enables or disables a user (`set-user-status`).
    pub fn minio_set_user_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        self.change(|d| d.set_user_enabled(name, enabled))
    }

    /// Sets the secret of a user's access key `id` (`change-my-password`, for the key
    /// that signed it).
    pub fn minio_change_secret(&self, id: &str, secret: &str) -> Result<()> {
        rules::secret_key(secret).map_err(MinioError::InvalidSecretKey)?;
        self.change(|d| {
            let key = d.state.keys.get(id).cloned().ok_or_else(|| {
                MinioError::InvalidAccessKey(
                    "Only a user's own access key changes its secret.".into(),
                )
            })?;
            d.put_key(&key.user, id, secret)
        })
    }

    /// Adds members to a group, making it if needed, or removes them, or the group when
    /// none are named and it has none; sets its status if given (`update-group-members`).
    pub fn minio_update_group(
        &self,
        name: &str,
        members: &[String],
        remove: bool,
        enabled: Option<bool>,
    ) -> Result<()> {
        self.change(|d| d.minio_update_group(name, members, remove, enabled))
    }

    /// A group (`group`).
    pub fn minio_group(&self, name: &str) -> Result<MinioGroup> {
        self.view(|s| Ok(minio_group(s, group_named(s, name)?)))
    }

    /// Every group's name, sorted (`groups`).
    #[must_use]
    pub fn minio_groups(&self) -> Vec<String> {
        self.view(|s| sorted(s.groups.values().map(|g| g.name.clone()).collect()))
    }

    /// Enables or disables a group (`set-group-status`).
    pub fn minio_set_group_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        self.change(|d| d.set_group_enabled(name, enabled))
    }

    /// Makes policy `name` or gives it a new document in effect; a built-in policy's name
    /// only `over_builtin` (`add-canned-policy`).
    pub fn minio_put_policy(&self, name: &str, document: &str, over_builtin: bool) -> Result<()> {
        self.change(|d| d.minio_put_policy(name, document, over_builtin))
    }

    /// The policy a name names (`info-canned-policy`).
    pub fn minio_policy(&self, name: &str) -> Result<MinioPolicy> {
        self.view(|s| Ok(minio_policy(policy_named(s, name)?)))
    }

    /// Every policy a name names, by name: the account's own, and the built-in ones it
    /// hasn't overridden (`list-canned-policies`).
    #[must_use]
    pub fn minio_policies(&self) -> Vec<MinioPolicy> {
        self.view(|s| {
            let mut policies: Vec<MinioPolicy> = s
                .policies
                .values()
                .filter(|p| !p.builtin || own_policy(s, &p.row.name).is_none())
                .map(|p| minio_policy(p))
                .collect();
            policies.sort_by_cached_key(|p| p.name.to_ascii_lowercase());
            policies
        })
    }

    /// Deletes one of the account's policies that nothing uses (`remove-canned-policy`).
    pub fn minio_remove_policy(&self, name: &str) -> Result<()> {
        self.change(|d| d.minio_remove_policy(name))
    }

    /// Attaches (or detaches) policies by name to a user or group; the names of those
    /// that changed (`idp/builtin/policy/attach`, `detach`).
    pub fn minio_associate(
        &self,
        owner: Owner<'_>,
        policies: &[String],
        attach: bool,
    ) -> Result<Vec<String>> {
        self.change(|d| d.minio_associate(owner, policies, attach))
    }

    /// Who has which policies: of the users, groups and policies named, or of all when
    /// none are (`idp/builtin/policy-entities`). Names that aren't there are skipped.
    #[must_use]
    pub fn minio_policy_entities(
        &self,
        users: &[String],
        groups: &[String],
        policies: &[String],
    ) -> PolicyEntities {
        self.view(|s| policy_entities(s, users, groups, policies))
    }
}

fn group_policies(state: &State, group: &Group) -> GroupPolicies {
    GroupPolicies {
        group: group.name.clone(),
        policies: names(state, &group.attached),
    }
}

fn policy_entities(
    state: &State,
    users: &[String],
    groups: &[String],
    policies: &[String],
) -> PolicyEntities {
    let all = users.is_empty() && groups.is_empty() && policies.is_empty();
    let pick_users: Vec<&Arc<User>> = if all {
        state
            .users
            .values()
            .filter(|u| !u.attached.is_empty())
            .collect()
    } else {
        users
            .iter()
            .filter_map(|n| state.user_named(n).ok())
            .collect()
    };
    let pick_groups: Vec<&Arc<Group>> = if all {
        state
            .groups
            .values()
            .filter(|g| !g.attached.is_empty())
            .collect()
    } else {
        groups
            .iter()
            .filter_map(|n| state.group_named(n).ok())
            .collect()
    };
    let pick_policies: Vec<&Arc<Managed>> = if all {
        state
            .policies
            .values()
            .filter(|p| state.attachments(&p.row.id) > 0)
            .collect()
    } else {
        policies
            .iter()
            .filter_map(|n| state.policy_named(n))
            .collect()
    };
    let mut entities = PolicyEntities {
        users: pick_users
            .into_iter()
            .map(|u| UserPolicies {
                user: u.name.clone(),
                policies: names(state, &u.attached),
                groups: state
                    .groups_of(&u.id)
                    .filter(|g| !g.attached.is_empty())
                    .map(|g| group_policies(state, g))
                    .collect(),
            })
            .collect(),
        groups: pick_groups
            .into_iter()
            .map(|g| group_policies(state, g))
            .collect(),
        policies: pick_policies
            .into_iter()
            .map(|p| PolicyHolders {
                policy: p.row.name.clone(),
                users: sorted(
                    state
                        .users
                        .values()
                        .filter(|u| u.attached.contains(&p.row.id))
                        .map(|u| u.name.clone())
                        .collect(),
                ),
                groups: sorted(
                    state
                        .groups
                        .values()
                        .filter(|g| g.attached.contains(&p.row.id))
                        .map(|g| g.name.clone())
                        .collect(),
                ),
            })
            .collect(),
    };
    entities
        .users
        .sort_by_cached_key(|u| u.user.to_ascii_lowercase());
    entities
        .groups
        .sort_by_cached_key(|g| g.group.to_ascii_lowercase());
    entities
        .policies
        .sort_by_cached_key(|p| p.policy.to_ascii_lowercase());
    entities
}
