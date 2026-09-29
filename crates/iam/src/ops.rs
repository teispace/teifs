//! IAM's operations, with AWS's rules and messages.

use std::{collections::BTreeMap, sync::Arc};

use teifs_meta::{
    AccessKeyRow, GroupRow, IamWrite, InlineRow, PolicyRow, PolicyVersionRow, UserRow,
};
use zeroize::Zeroizing;

use crate::{
    Draft, Iam, IamError, Result, ids,
    rules::{
        self, MAX_ATTACHED, MAX_GROUPS, MAX_GROUPS_PER_USER, MAX_KEYS_PER_USER, MAX_POLICIES,
        MAX_TAGS, MAX_USERS, MAX_VERSIONS,
    },
    state::{Document, Group, Key, Managed, State, User, Version},
};

/// A user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// Its unique id (`AIDA…`).
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its ARN.
    pub arn: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its tags.
    pub tags: Vec<(String, String)>,
    /// The ARN of its permissions boundary.
    pub boundary: Option<String>,
}

/// A group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    /// Its unique id (`AGPA…`).
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its ARN.
    pub arn: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A customer-managed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInfo {
    /// Its unique id (`ANPA…`).
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its ARN.
    pub arn: String,
    /// Its description.
    pub description: String,
    /// The version in effect (`v1`, …).
    pub default_version: String,
    /// How many users and groups it's attached to.
    pub attachment_count: usize,
    /// How many users have it as their permissions boundary.
    pub boundary_usage_count: usize,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// When its default version last changed.
    pub updated_ms: i64,
    /// Its tags.
    pub tags: Vec<(String, String)>,
}

/// A version of a managed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersionInfo {
    /// `v1`, `v2`, ….
    pub version: String,
    /// The document, as given.
    pub document: String,
    /// Whether it's the version in effect.
    pub is_default: bool,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// An access key, without its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyInfo {
    /// The access key id.
    pub id: String,
    /// The name of the user it belongs to.
    pub user: String,
    /// Whether requests signed with it are accepted.
    pub active: bool,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A new access key and its secret, which is shown only now.
pub struct NewAccessKey {
    /// The key.
    pub info: AccessKeyInfo,
    /// Its secret key.
    pub secret: Zeroizing<String>,
}

impl std::fmt::Debug for NewAccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewAccessKey")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// A managed policy attached to a user or group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedPolicy {
    /// Its name.
    pub name: String,
    /// Its ARN.
    pub arn: String,
}

/// Who an inline or attached policy belongs to, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner<'a> {
    /// A user.
    User(&'a str),
    /// A group.
    Group(&'a str),
}

fn user_info(state: &State, user: &User) -> UserInfo {
    UserInfo {
        id: user.id.clone(),
        name: user.name.clone(),
        path: user.path.clone(),
        arn: state.user_arn(user),
        created_ms: user.created_ms,
        tags: user.tags.clone(),
        boundary: user
            .boundary
            .as_ref()
            .and_then(|id| state.policies.get(id))
            .map(|p| state.policy_arn(&p.row)),
    }
}

fn group_info(state: &State, group: &Group) -> GroupInfo {
    GroupInfo {
        id: group.id.clone(),
        name: group.name.clone(),
        path: group.path.clone(),
        arn: state.group_arn(group),
        created_ms: group.created_ms,
    }
}

fn policy_info(state: &State, policy: &Managed) -> PolicyInfo {
    PolicyInfo {
        id: policy.row.id.clone(),
        name: policy.row.name.clone(),
        path: policy.row.path.clone(),
        arn: state.policy_arn(&policy.row),
        description: policy.row.description.clone(),
        default_version: format!("v{}", policy.row.default_version),
        attachment_count: state.attachments(&policy.row.id),
        boundary_usage_count: state.boundary_uses(&policy.row.id),
        created_ms: policy.row.created_ms,
        updated_ms: policy.row.updated_ms,
        tags: policy.tags.clone(),
    }
}

fn version_info(policy: &Managed, number: u32, version: &Version) -> PolicyVersionInfo {
    PolicyVersionInfo {
        version: format!("v{number}"),
        document: version.document.text.to_string(),
        is_default: number == policy.row.default_version,
        created_ms: version.created_ms,
    }
}

fn key_info(state: &State, key: &Key) -> AccessKeyInfo {
    AccessKeyInfo {
        id: key.id.clone(),
        user: state
            .users
            .get(&key.user)
            .map(|u| u.name.clone())
            .unwrap_or_default(),
        active: key.active,
        created_ms: key.created_ms,
    }
}

fn by_name<T>(mut items: Vec<T>, name: impl Fn(&T) -> &str) -> Vec<T> {
    items.sort_by_cached_key(|item| name(item).to_ascii_lowercase());
    items
}

fn under(prefix: Option<&str>) -> Result<impl Fn(&str) -> bool + '_> {
    if let Some(prefix) = prefix {
        rules::path_prefix(prefix)?;
    }
    Ok(move |path: &str| prefix.is_none_or(|p| path.starts_with(p)))
}

/// How an entity compares tag keys: users without case, policies with (as AWS does).
#[derive(Clone, Copy)]
enum TagKeys {
    User,
    Policy,
}

impl TagKeys {
    fn same(self, a: &str, b: &str) -> bool {
        match self {
            Self::User => a.eq_ignore_ascii_case(b),
            Self::Policy => a == b,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Policy => "policy",
        }
    }
}

/// Checks a request's tags: valid, no key twice.
fn checked_tags(kind: TagKeys, tags: &[(String, String)]) -> Result<()> {
    for (key, value) in tags {
        rules::tag(key, value)?;
    }
    for (i, (key, _)) in tags.iter().enumerate() {
        if tags[..i].iter().any(|(k, _)| kind.same(k, key)) {
            return Err(IamError::InvalidInput(format!(
                "Duplicate tag keys found: {key}"
            )));
        }
    }
    Ok(())
}

/// `tags` with `new` merged in (a key already there takes the new value and spelling),
/// within the limit.
fn merged(
    kind: TagKeys,
    tags: &[(String, String)],
    new: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let mut tags = tags.to_vec();
    for (key, value) in new {
        tags.retain(|(k, _)| !kind.same(k, key));
        tags.push((key.clone(), value.clone()));
    }
    if tags.len() > MAX_TAGS {
        return Err(IamError::LimitExceeded(format!(
            "A {} can have at most {MAX_TAGS} tags.",
            kind.noun()
        )));
    }
    // The order the store lists them in, so a reload changes nothing.
    match kind {
        TagKeys::User => tags.sort_by_cached_key(|(k, _)| k.to_ascii_lowercase()),
        TagKeys::Policy => tags.sort(),
    }
    Ok(tags)
}

/// `tags` without `keys`, and the keys that were there.
fn removed<'k>(
    kind: TagKeys,
    tags: &mut Vec<(String, String)>,
    keys: &'k [String],
) -> Vec<&'k String> {
    let gone: Vec<&String> = keys
        .iter()
        .filter(|key| tags.iter().any(|(k, _)| kind.same(k, key)))
        .collect();
    tags.retain(|(k, _)| !keys.iter().any(|key| kind.same(k, key)));
    gone
}

impl Draft<'_> {
    pub(crate) fn write(&mut self, write: IamWrite) {
        self.writes.push(write);
    }

    pub(crate) fn user(&self, name: &str) -> Result<Arc<User>> {
        self.state.user_named(name).cloned()
    }

    fn group(&self, name: &str) -> Result<Arc<Group>> {
        self.state.group_named(name).cloned()
    }

    fn policy(&self, arn: &str) -> Result<Arc<Managed>> {
        self.state.policy_by_arn(arn).cloned()
    }

    fn save_user(&mut self, user: User) {
        self.write(IamWrite::PutUser(UserRow {
            id: user.id.clone(),
            name: user.name.clone(),
            path: user.path.clone(),
            created_ms: user.created_ms,
            boundary: user.boundary.clone(),
        }));
        self.state.users.insert(user.id.clone(), Arc::new(user));
    }

    fn save_group(&mut self, group: Group) {
        self.write(IamWrite::PutGroup(GroupRow {
            id: group.id.clone(),
            name: group.name.clone(),
            path: group.path.clone(),
            created_ms: group.created_ms,
        }));
        self.state.groups.insert(group.id.clone(), Arc::new(group));
    }

    fn save_policy(&mut self, policy: Managed) {
        self.write(IamWrite::PutPolicy(policy.row.clone()));
        self.state
            .policies
            .insert(policy.row.id.clone(), Arc::new(policy));
    }

    pub(crate) fn save_key(&mut self, key: Key) {
        self.write(IamWrite::PutKey(AccessKeyRow {
            id: key.id.clone(),
            user_id: key.user.clone(),
            secret: key.sealed.clone(),
            active: key.active,
            created_ms: key.created_ms,
        }));
        self.state.keys.insert(key.id.clone(), Arc::new(key));
    }

    /// A new unique id of `kind`, not in use (a collision is ~2^-85, but free to rule out).
    fn new_id(&self, kind: ids::Kind) -> String {
        loop {
            let id = ids::unique(kind);
            if !self.state.users.contains_key(&id)
                && !self.state.groups.contains_key(&id)
                && !self.state.policies.contains_key(&id)
            {
                return id;
            }
        }
    }

    /// Applies an owner's change to its inline policies or attachments.
    fn owner(&self, owner: Owner<'_>) -> Result<OwnerRef> {
        Ok(match owner {
            Owner::User(name) => OwnerRef::User(self.user(name)?),
            Owner::Group(name) => OwnerRef::Group(self.group(name)?),
        })
    }
}

/// The operations that change IAM, each with all of its checks: [`Iam`]'s methods run
/// one in a change of its own, and an import runs many in one.
impl Draft<'_> {
    /// [`Iam::create_user`], as part of a change.
    pub(crate) fn create_user(
        &mut self,
        name: &str,
        path: Option<&str>,
        tags: &[(String, String)],
        boundary: Option<&str>,
    ) -> Result<UserInfo> {
        rules::name("user name", name, rules::USER_NAME)?;
        let path = path.unwrap_or("/");
        rules::path(path)?;
        checked_tags(TagKeys::User, tags)?;
        let tags = merged(TagKeys::User, &[], tags)?;
        if self.state.user_name_taken(name, None) {
            return Err(IamError::EntityAlreadyExists(format!(
                "User with name {name} already exists."
            )));
        }
        if self.state.users.len() >= MAX_USERS {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for UsersPerAccount: {MAX_USERS}"
            )));
        }
        let boundary = boundary
            .map(|arn| self.policy(arn).map(|p| p.row.id.clone()))
            .transpose()?;
        let user = User {
            id: self.new_id(ids::Kind::User),
            name: name.to_owned(),
            path: path.to_owned(),
            created_ms: self.now,
            boundary,
            tags: tags.clone(),
            inline: BTreeMap::new(),
            attached: std::collections::BTreeSet::new(),
        };
        let id = user.id.clone();
        self.save_user(user);
        for (key, value) in &tags {
            self.write(IamWrite::PutUserTag(id.clone(), key.clone(), value.clone()));
        }
        Ok(user_info(&self.state, &self.state.users[&id]))
    }

    /// [`Iam::create_group`], as part of a change.
    pub(crate) fn create_group(&mut self, name: &str, path: Option<&str>) -> Result<GroupInfo> {
        rules::name("group name", name, rules::OTHER_NAME)?;
        let path = path.unwrap_or("/");
        rules::path(path)?;
        if self.state.group_name_taken(name, None) {
            return Err(IamError::EntityAlreadyExists(format!(
                "Group with name {name} already exists."
            )));
        }
        if self.state.groups.len() >= MAX_GROUPS {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for GroupsPerAccount: {MAX_GROUPS}"
            )));
        }
        let group = Group {
            id: self.new_id(ids::Kind::Group),
            name: name.to_owned(),
            path: path.to_owned(),
            created_ms: self.now,
            members: std::collections::BTreeSet::new(),
            inline: BTreeMap::new(),
            attached: std::collections::BTreeSet::new(),
        };
        let info = group_info(&self.state, &group);
        self.save_group(group);
        Ok(info)
    }

    /// [`Iam::add_user_to_group`], as part of a change.
    pub(crate) fn add_user_to_group(&mut self, group: &str, user: &str) -> Result<()> {
        let group = self.group(group)?;
        let user = self.user(user)?;
        if group.members.contains(&user.id) {
            return Ok(());
        }
        if self.state.groups_of(&user.id).count() >= MAX_GROUPS_PER_USER {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for GroupsPerUser: {MAX_GROUPS_PER_USER}"
            )));
        }
        let mut group = Arc::unwrap_or_clone(group);
        group.members.insert(user.id.clone());
        self.write(IamWrite::AddMember(group.id.clone(), user.id.clone()));
        self.state.groups.insert(group.id.clone(), Arc::new(group));
        Ok(())
    }

    /// [`Iam::create_policy`], as part of a change.
    pub(crate) fn create_policy(
        &mut self,
        name: &str,
        path: Option<&str>,
        description: Option<&str>,
        document: &str,
        tags: &[(String, String)],
    ) -> Result<PolicyInfo> {
        rules::name("policy name", name, rules::OTHER_NAME)?;
        checked_tags(TagKeys::Policy, tags)?;
        let tags = merged(TagKeys::Policy, &[], tags)?;
        let path = path.unwrap_or("/");
        rules::path(path)?;
        let description = description.unwrap_or_default();
        rules::description(description)?;
        let document = Document::parse(document)?;
        managed_size(&document)?;
        if self
            .state
            .policies
            .values()
            .any(|p| p.row.name.eq_ignore_ascii_case(name))
        {
            return Err(IamError::EntityAlreadyExists(format!(
                "A policy called {name} already exists. Duplicate names are not allowed."
            )));
        }
        if self.state.policies.len() >= MAX_POLICIES {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for PoliciesPerAccount: {MAX_POLICIES}"
            )));
        }
        let row = PolicyRow {
            id: self.new_id(ids::Kind::Policy),
            name: name.to_owned(),
            path: path.to_owned(),
            description: description.to_owned(),
            default_version: 1,
            latest_version: 1,
            created_ms: self.now,
            updated_ms: self.now,
        };
        self.write(IamWrite::PutPolicy(row.clone()));
        self.write(IamWrite::PutVersion(PolicyVersionRow {
            policy_id: row.id.clone(),
            version: 1,
            document: document.text.to_string(),
            created_ms: self.now,
        }));
        let policy = Managed {
            versions: BTreeMap::from([(
                1,
                Version {
                    document,
                    created_ms: self.now,
                },
            )]),
            row,
            tags,
        };
        for (key, value) in &policy.tags {
            self.write(IamWrite::PutPolicyTag(
                policy.row.id.clone(),
                key.clone(),
                value.clone(),
            ));
        }
        let info = policy_info(&self.state, &policy);
        self.state
            .policies
            .insert(policy.row.id.clone(), Arc::new(policy));
        Ok(info)
    }

    /// [`Iam::create_policy_version`], as part of a change.
    pub(crate) fn create_policy_version(
        &mut self,
        arn: &str,
        document: &str,
        set_default: bool,
    ) -> Result<PolicyVersionInfo> {
        let document = Document::parse(document)?;
        managed_size(&document)?;
        let mut policy = Arc::unwrap_or_clone(self.policy(arn)?);
        if policy.versions.len() >= MAX_VERSIONS {
            return Err(IamError::LimitExceeded(format!(
                "A managed policy can have up to {MAX_VERSIONS} versions. Before you create a new version, you \
                 must delete an existing version."
            )));
        }
        let number = policy.row.latest_version + 1;
        policy.row.latest_version = number;
        if set_default {
            policy.row.default_version = number;
            policy.row.updated_ms = self.now;
        }
        self.write(IamWrite::PutVersion(PolicyVersionRow {
            policy_id: policy.row.id.clone(),
            version: number,
            document: document.text.to_string(),
            created_ms: self.now,
        }));
        let version = Version {
            document,
            created_ms: self.now,
        };
        let info = version_info(&policy, number, &version);
        policy.versions.insert(number, version);
        self.save_policy(policy);
        Ok(info)
    }

    /// [`Iam::set_default_policy_version`], as part of a change.
    pub(crate) fn set_default_policy_version(&mut self, arn: &str, version: &str) -> Result<()> {
        let number = rules::version_id(version)?;
        let mut policy = Arc::unwrap_or_clone(self.policy(arn)?);
        if !policy.versions.contains_key(&number) {
            return Err(no_such_version(arn, version));
        }
        if policy.row.default_version != number {
            policy.row.default_version = number;
            policy.row.updated_ms = self.now;
            self.save_policy(policy);
        }
        Ok(())
    }

    /// [`Iam::attach`], as part of a change.
    pub(crate) fn attach(&mut self, owner: Owner<'_>, arn: &str) -> Result<()> {
        let owner = self.owner(owner)?;
        let policy = self.policy(arn)?;
        let id = policy.row.id.clone();
        if owner.attached().contains(&id) {
            return Ok(());
        }
        if owner.attached().len() >= MAX_ATTACHED {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for PoliciesPer{}: {MAX_ATTACHED}",
                if owner.kind() == "user" {
                    "User"
                } else {
                    "Group"
                }
            )));
        }
        self.write(IamWrite::Attach(owner.id().to_owned(), id.clone()));
        owner.update(self, |_, attached| {
            attached.insert(id);
        });
        Ok(())
    }

    /// [`Iam::put_inline`], as part of a change.
    pub(crate) fn put_inline(
        &mut self,
        owner: Owner<'_>,
        name: &str,
        document: &str,
    ) -> Result<()> {
        rules::name("policy name", name, rules::OTHER_NAME)?;
        let document = Document::parse(document)?;
        let owner = self.owner(owner)?;
        let others: usize = owner
            .inline()
            .iter()
            .filter(|(n, _)| *n != name)
            .map(|(_, doc)| doc.size)
            .sum();
        if others + document.size > owner.inline_limit() {
            return Err(IamError::LimitExceeded(format!(
                "Maximum policy size of {} bytes exceeded for {} {}",
                owner.inline_limit(),
                owner.kind(),
                owner.name()
            )));
        }
        self.write(IamWrite::PutInline(InlineRow {
            owner: owner.id().to_owned(),
            name: name.to_owned(),
            document: document.text.to_string(),
        }));
        owner.update(self, |inline, _| {
            inline.insert(name.to_owned(), document);
        });
        Ok(())
    }
}

/// A resolved [`Owner`].
enum OwnerRef {
    User(Arc<User>),
    Group(Arc<Group>),
}

impl OwnerRef {
    fn id(&self) -> &str {
        match self {
            Self::User(u) => &u.id,
            Self::Group(g) => &g.id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Group(_) => "group",
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::User(u) => &u.name,
            Self::Group(g) => &g.name,
        }
    }

    fn inline(&self) -> &BTreeMap<String, Document> {
        match self {
            Self::User(u) => &u.inline,
            Self::Group(g) => &g.inline,
        }
    }

    fn attached(&self) -> &std::collections::BTreeSet<String> {
        match self {
            Self::User(u) => &u.attached,
            Self::Group(g) => &g.attached,
        }
    }

    fn inline_limit(&self) -> usize {
        match self {
            Self::User(_) => rules::USER_INLINE_TOTAL,
            Self::Group(_) => rules::GROUP_INLINE_TOTAL,
        }
    }

    /// Changes the owner's inline policies or attachments and saves it.
    fn update(
        self,
        draft: &mut Draft<'_>,
        f: impl FnOnce(&mut BTreeMap<String, Document>, &mut std::collections::BTreeSet<String>),
    ) {
        match self {
            Self::User(u) => {
                let mut u = Arc::unwrap_or_clone(u);
                f(&mut u.inline, &mut u.attached);
                draft.state.users.insert(u.id.clone(), Arc::new(u));
            }
            Self::Group(g) => {
                let mut g = Arc::unwrap_or_clone(g);
                f(&mut g.inline, &mut g.attached);
                draft.state.groups.insert(g.id.clone(), Arc::new(g));
            }
        }
    }
}

/// Users.
impl Iam {
    /// Creates a user (`CreateUser`).
    pub fn create_user(
        &self,
        name: &str,
        path: Option<&str>,
        tags: &[(String, String)],
        boundary: Option<&str>,
    ) -> Result<UserInfo> {
        self.change(|d| d.create_user(name, path, tags, boundary))
    }

    /// A user (`GetUser`).
    pub fn user(&self, name: &str) -> Result<UserInfo> {
        self.read(|s| Ok(user_info(s, s.user_named(name)?)))
    }

    /// The user with this unique id, if any.
    pub fn user_by_id(&self, id: &str) -> Option<UserInfo> {
        self.read(|s| Ok(s.users.get(id).map(|u| user_info(s, u))))
            .ok()
            .flatten()
    }

    /// Users whose path starts with `prefix`, by name (`ListUsers`).
    pub fn users(&self, prefix: Option<&str>) -> Result<Vec<UserInfo>> {
        let under = under(prefix)?;
        self.read(|s| {
            let users = s
                .users
                .values()
                .filter(|u| under(&u.path))
                .map(|u| user_info(s, u))
                .collect();
            Ok(by_name(users, |u: &UserInfo| &u.name))
        })
    }

    /// Renames a user or moves it to another path (`UpdateUser`).
    pub fn update_user(
        &self,
        name: &str,
        new_name: Option<&str>,
        new_path: Option<&str>,
    ) -> Result<()> {
        if let Some(new_name) = new_name {
            rules::name("user name", new_name, rules::USER_NAME)?;
        }
        if let Some(new_path) = new_path {
            rules::path(new_path)?;
        }
        self.change(|d| {
            let mut user = Arc::unwrap_or_clone(d.user(name)?);
            if let Some(new_name) = new_name {
                if d.state.user_name_taken(new_name, Some(&user.id)) {
                    return Err(IamError::EntityAlreadyExists(format!(
                        "User with name {new_name} already exists."
                    )));
                }
                new_name.clone_into(&mut user.name);
            }
            if let Some(new_path) = new_path {
                new_path.clone_into(&mut user.path);
            }
            d.save_user(user);
            Ok(())
        })
    }

    /// Deletes a user with no access keys, policies or groups left (`DeleteUser`).
    pub fn delete_user(&self, name: &str) -> Result<()> {
        self.change(|d| {
            let user = d.user(name)?;
            let conflict = if d.state.keys.values().any(|k| k.user == user.id) {
                Some("access keys")
            } else if !user.inline.is_empty() {
                Some("inline policies")
            } else if !user.attached.is_empty() {
                Some("attached policies")
            } else if d.state.groups_of(&user.id).next().is_some() {
                Some("group memberships")
            } else {
                None
            };
            if let Some(what) = conflict {
                return Err(IamError::DeleteConflict(format!(
                    "Cannot delete entity, must remove {what} first."
                )));
            }
            d.state.users.remove(&user.id);
            d.write(IamWrite::DeleteUser(user.id.clone()));
            Ok(())
        })
    }

    /// Adds or replaces a user's tags; keys compare without case (`TagUser`).
    pub fn tag_user(&self, name: &str, tags: &[(String, String)]) -> Result<()> {
        checked_tags(TagKeys::User, tags)?;
        self.change(|d| {
            let mut user = Arc::unwrap_or_clone(d.user(name)?);
            user.tags = merged(TagKeys::User, &user.tags, tags)?;
            for (key, value) in tags {
                d.write(IamWrite::PutUserTag(
                    user.id.clone(),
                    key.clone(),
                    value.clone(),
                ));
            }
            d.state.users.insert(user.id.clone(), Arc::new(user));
            Ok(())
        })
    }

    /// Removes a user's tags; absent keys are ignored (`UntagUser`).
    pub fn untag_user(&self, name: &str, keys: &[String]) -> Result<()> {
        self.change(|d| {
            let mut user = Arc::unwrap_or_clone(d.user(name)?);
            for key in removed(TagKeys::User, &mut user.tags, keys) {
                d.write(IamWrite::DeleteUserTag(user.id.clone(), key.clone()));
            }
            d.state.users.insert(user.id.clone(), Arc::new(user));
            Ok(())
        })
    }

    /// Sets or removes a user's permissions boundary (`PutUserPermissionsBoundary`,
    /// `DeleteUserPermissionsBoundary`).
    pub fn set_user_boundary(&self, name: &str, arn: Option<&str>) -> Result<()> {
        self.change(|d| {
            let mut user = Arc::unwrap_or_clone(d.user(name)?);
            let boundary = arn
                .map(|arn| d.policy(arn).map(|p| p.row.id.clone()))
                .transpose()?;
            if boundary.is_none() && user.boundary.is_none() {
                return Err(IamError::NoSuchEntity(format!(
                    "The user {name} has no permissions boundary."
                )));
            }
            user.boundary = boundary;
            d.save_user(user);
            Ok(())
        })
    }
}

/// Access keys.
impl Iam {
    /// Creates an access key for a user; its secret is returned only now (`CreateAccessKey`).
    pub fn create_access_key(&self, user: &str) -> Result<NewAccessKey> {
        self.change(|d| {
            let user = d.user(user)?;
            if d.state.keys.values().filter(|k| k.user == user.id).count() >= MAX_KEYS_PER_USER {
                return Err(IamError::LimitExceeded(format!(
                    "Cannot exceed quota for AccessKeysPerUser: {MAX_KEYS_PER_USER}"
                )));
            }
            let id = loop {
                let id = ids::access_key();
                if !d.state.keys.contains_key(&id) && d.root != Some(id.as_str()) {
                    break id;
                }
            };
            let secret = ids::secret_key();
            let key = Key {
                sealed: d.key.seal_secret(id.as_bytes(), secret.as_bytes()),
                secret: Arc::new(secret.clone()),
                id,
                user: user.id.clone(),
                active: true,
                created_ms: d.now,
            };
            let info = key_info(&d.state, &key);
            d.save_key(key);
            Ok(NewAccessKey { info, secret })
        })
    }

    /// A user's access keys, oldest first (`ListAccessKeys`).
    pub fn access_keys(&self, user: &str) -> Result<Vec<AccessKeyInfo>> {
        self.read(|s| {
            let user = s.user_named(user)?;
            let mut keys: Vec<_> = s
                .keys
                .values()
                .filter(|k| k.user == user.id)
                .map(|k| key_info(s, k))
                .collect();
            keys.sort_by(|a, b| {
                a.created_ms
                    .cmp(&b.created_ms)
                    .then_with(|| a.id.cmp(&b.id))
            });
            Ok(keys)
        })
    }

    /// The user an access key belongs to (`GetAccessKeyLastUsed` names it).
    pub fn access_key(&self, id: &str) -> Result<AccessKeyInfo> {
        self.read(|s| {
            s.keys
                .get(id)
                .map(|k| key_info(s, k))
                .ok_or_else(|| no_such_key(id))
        })
    }

    /// Activates or deactivates a user's access key (`UpdateAccessKey`).
    pub fn update_access_key(&self, user: &str, id: &str, active: bool) -> Result<()> {
        self.change(|d| {
            let key = owned_key(d, user, id)?;
            if key.active != active {
                let mut key = Arc::unwrap_or_clone(key);
                key.active = active;
                d.save_key(key);
            }
            Ok(())
        })
    }

    /// Deletes a user's access key (`DeleteAccessKey`).
    pub fn delete_access_key(&self, user: &str, id: &str) -> Result<()> {
        self.change(|d| {
            let key = owned_key(d, user, id)?;
            d.state.keys.remove(&key.id);
            d.write(IamWrite::DeleteKey(key.id.clone()));
            Ok(())
        })
    }
}

fn no_such_key(id: &str) -> IamError {
    IamError::NoSuchEntity(format!("The Access Key with id {id} cannot be found."))
}

/// The key `id` if it belongs to `user`: another user's key is reported missing, not
/// forbidden, so key ids can't be probed through someone else's name.
fn owned_key(d: &Draft<'_>, user: &str, id: &str) -> Result<Arc<Key>> {
    let user = d.user(user)?;
    d.state
        .keys
        .get(id)
        .filter(|k| k.user == user.id)
        .cloned()
        .ok_or_else(|| no_such_key(id))
}

/// Groups.
impl Iam {
    /// Creates a group (`CreateGroup`).
    pub fn create_group(&self, name: &str, path: Option<&str>) -> Result<GroupInfo> {
        self.change(|d| d.create_group(name, path))
    }

    /// A group and its users, by name (`GetGroup`).
    pub fn group(&self, name: &str) -> Result<(GroupInfo, Vec<UserInfo>)> {
        self.read(|s| {
            let group = s.group_named(name)?;
            let users = group
                .members
                .iter()
                .filter_map(|id| s.users.get(id))
                .map(|u| user_info(s, u))
                .collect();
            Ok((group_info(s, group), by_name(users, |u: &UserInfo| &u.name)))
        })
    }

    /// Groups whose path starts with `prefix`, by name (`ListGroups`).
    pub fn groups(&self, prefix: Option<&str>) -> Result<Vec<GroupInfo>> {
        let under = under(prefix)?;
        self.read(|s| {
            let groups = s
                .groups
                .values()
                .filter(|g| under(&g.path))
                .map(|g| group_info(s, g))
                .collect();
            Ok(by_name(groups, |g: &GroupInfo| &g.name))
        })
    }

    /// The groups a user is in, by name (`ListGroupsForUser`).
    pub fn groups_for_user(&self, user: &str) -> Result<Vec<GroupInfo>> {
        self.read(|s| {
            let user = s.user_named(user)?;
            let groups = s.groups_of(&user.id).map(|g| group_info(s, g)).collect();
            Ok(by_name(groups, |g: &GroupInfo| &g.name))
        })
    }

    /// Renames a group or moves it to another path (`UpdateGroup`).
    pub fn update_group(
        &self,
        name: &str,
        new_name: Option<&str>,
        new_path: Option<&str>,
    ) -> Result<()> {
        if let Some(new_name) = new_name {
            rules::name("group name", new_name, rules::OTHER_NAME)?;
        }
        if let Some(new_path) = new_path {
            rules::path(new_path)?;
        }
        self.change(|d| {
            let mut group = Arc::unwrap_or_clone(d.group(name)?);
            if let Some(new_name) = new_name {
                if d.state.group_name_taken(new_name, Some(&group.id)) {
                    return Err(IamError::EntityAlreadyExists(format!(
                        "Group with name {new_name} already exists."
                    )));
                }
                new_name.clone_into(&mut group.name);
            }
            if let Some(new_path) = new_path {
                new_path.clone_into(&mut group.path);
            }
            d.save_group(group);
            Ok(())
        })
    }

    /// Deletes a group with no users or policies left (`DeleteGroup`).
    pub fn delete_group(&self, name: &str) -> Result<()> {
        self.change(|d| {
            let group = d.group(name)?;
            let conflict = if !group.members.is_empty() {
                Some("users")
            } else if !group.inline.is_empty() {
                Some("inline policies")
            } else if !group.attached.is_empty() {
                Some("attached policies")
            } else {
                None
            };
            if let Some(what) = conflict {
                return Err(IamError::DeleteConflict(format!(
                    "Cannot delete entity, must remove {what} first."
                )));
            }
            d.state.groups.remove(&group.id);
            d.write(IamWrite::DeleteGroup(group.id.clone()));
            Ok(())
        })
    }

    /// Adds a user to a group; adding a member again does nothing (`AddUserToGroup`).
    pub fn add_user_to_group(&self, group: &str, user: &str) -> Result<()> {
        self.change(|d| d.add_user_to_group(group, user))
    }

    /// Removes a user from a group (`RemoveUserFromGroup`).
    pub fn remove_user_from_group(&self, group: &str, user: &str) -> Result<()> {
        self.change(|d| {
            let group = d.group(group)?;
            let user = d.user(user)?;
            if !group.members.contains(&user.id) {
                return Err(IamError::NoSuchEntity(format!(
                    "User {} is not in group {}.",
                    user.name, group.name
                )));
            }
            let mut group = Arc::unwrap_or_clone(group);
            group.members.remove(&user.id);
            d.write(IamWrite::RemoveMember(group.id.clone(), user.id.clone()));
            d.state.groups.insert(group.id.clone(), Arc::new(group));
            Ok(())
        })
    }
}

fn managed_size(document: &Document) -> Result<()> {
    if document.size > rules::MANAGED_SIZE {
        return Err(IamError::LimitExceeded(format!(
            "Cannot exceed quota for PolicySize: {}",
            rules::MANAGED_SIZE
        )));
    }
    Ok(())
}

/// Managed policies.
impl Iam {
    /// Creates a managed policy with `document` as `v1` (`CreatePolicy`).
    pub fn create_policy(
        &self,
        name: &str,
        path: Option<&str>,
        description: Option<&str>,
        document: &str,
        tags: &[(String, String)],
    ) -> Result<PolicyInfo> {
        self.change(|d| d.create_policy(name, path, description, document, tags))
    }

    /// Adds or replaces a managed policy's tags; keys are case sensitive (`TagPolicy`).
    pub fn tag_policy(&self, arn: &str, tags: &[(String, String)]) -> Result<()> {
        checked_tags(TagKeys::Policy, tags)?;
        self.change(|d| {
            let mut policy = Arc::unwrap_or_clone(d.policy(arn)?);
            policy.tags = merged(TagKeys::Policy, &policy.tags, tags)?;
            for (key, value) in tags {
                d.write(IamWrite::PutPolicyTag(
                    policy.row.id.clone(),
                    key.clone(),
                    value.clone(),
                ));
            }
            d.state
                .policies
                .insert(policy.row.id.clone(), Arc::new(policy));
            Ok(())
        })
    }

    /// Removes a managed policy's tags; absent keys are ignored (`UntagPolicy`).
    pub fn untag_policy(&self, arn: &str, keys: &[String]) -> Result<()> {
        self.change(|d| {
            let mut policy = Arc::unwrap_or_clone(d.policy(arn)?);
            for key in removed(TagKeys::Policy, &mut policy.tags, keys) {
                d.write(IamWrite::DeletePolicyTag(
                    policy.row.id.clone(),
                    key.clone(),
                ));
            }
            d.state
                .policies
                .insert(policy.row.id.clone(), Arc::new(policy));
            Ok(())
        })
    }

    /// A managed policy (`GetPolicy`).
    pub fn policy(&self, arn: &str) -> Result<PolicyInfo> {
        self.read(|s| Ok(policy_info(s, s.policy_by_arn(arn)?)))
    }

    /// Managed policies whose path starts with `prefix`, by name; only those attached to
    /// something if `attached` (`ListPolicies` with Scope=Local).
    pub fn policies(&self, prefix: Option<&str>, attached: bool) -> Result<Vec<PolicyInfo>> {
        let under = under(prefix)?;
        self.read(|s| {
            let policies = s
                .policies
                .values()
                .filter(|p| under(&p.row.path) && (!attached || s.attachments(&p.row.id) > 0))
                .map(|p| policy_info(s, p))
                .collect();
            Ok(by_name(policies, |p: &PolicyInfo| &p.name))
        })
    }

    /// Deletes a managed policy that nothing uses and that has only its default version
    /// (`DeletePolicy`).
    pub fn delete_policy(&self, arn: &str) -> Result<()> {
        self.change(|d| {
            let policy = d.policy(arn)?;
            let id = &policy.row.id;
            if d.state.attachments(id) > 0 {
                return Err(IamError::DeleteConflict("Cannot delete a policy attached to entities.".into()));
            }
            if d.state.boundary_uses(id) > 0 {
                return Err(IamError::DeleteConflict(
                    "Cannot delete a policy used as a permissions boundary.".into(),
                ));
            }
            if policy.versions.len() > 1 {
                return Err(IamError::DeleteConflict(
                    "This policy has more than one version. Before you delete a policy, you must delete the \
                     policy's versions. The default version is deleted with the policy."
                        .into(),
                ));
            }
            d.state.policies.remove(id);
            d.write(IamWrite::DeletePolicy(id.clone()));
            Ok(())
        })
    }

    /// Adds a version to a managed policy, making it the default if `set_default`
    /// (`CreatePolicyVersion`).
    pub fn create_policy_version(
        &self,
        arn: &str,
        document: &str,
        set_default: bool,
    ) -> Result<PolicyVersionInfo> {
        self.change(|d| d.create_policy_version(arn, document, set_default))
    }

    /// A version of a managed policy (`GetPolicyVersion`).
    pub fn policy_version(&self, arn: &str, version: &str) -> Result<PolicyVersionInfo> {
        let number = rules::version_id(version)?;
        self.read(|s| {
            let policy = s.policy_by_arn(arn)?;
            let v = policy
                .versions
                .get(&number)
                .ok_or_else(|| no_such_version(arn, version))?;
            Ok(version_info(policy, number, v))
        })
    }

    /// A managed policy's versions, oldest first (`ListPolicyVersions`).
    pub fn policy_versions(&self, arn: &str) -> Result<Vec<PolicyVersionInfo>> {
        self.read(|s| {
            let policy = s.policy_by_arn(arn)?;
            Ok(policy
                .versions
                .iter()
                .map(|(n, v)| version_info(policy, *n, v))
                .collect())
        })
    }

    /// Deletes a version other than the default (`DeletePolicyVersion`).
    pub fn delete_policy_version(&self, arn: &str, version: &str) -> Result<()> {
        let number = rules::version_id(version)?;
        self.change(|d| {
            let mut policy = Arc::unwrap_or_clone(d.policy(arn)?);
            if !policy.versions.contains_key(&number) {
                return Err(no_such_version(arn, version));
            }
            if number == policy.row.default_version {
                return Err(IamError::DeleteConflict(
                    "Cannot delete the default version of a policy.".into(),
                ));
            }
            policy.versions.remove(&number);
            d.write(IamWrite::DeleteVersion(policy.row.id.clone(), number));
            d.state
                .policies
                .insert(policy.row.id.clone(), Arc::new(policy));
            Ok(())
        })
    }

    /// Makes a version the one in effect (`SetDefaultPolicyVersion`).
    pub fn set_default_policy_version(&self, arn: &str, version: &str) -> Result<()> {
        self.change(|d| d.set_default_policy_version(arn, version))
    }
}

fn no_such_version(arn: &str, version: &str) -> IamError {
    IamError::NoSuchEntity(format!("Policy {arn} version {version} does not exist."))
}

/// Attachments and inline policies.
impl Iam {
    /// Attaches a managed policy to a user or group; attaching it again does nothing
    /// (`AttachUserPolicy`, `AttachGroupPolicy`).
    pub fn attach(&self, owner: Owner<'_>, arn: &str) -> Result<()> {
        self.change(|d| d.attach(owner, arn))
    }

    /// Detaches a managed policy (`DetachUserPolicy`, `DetachGroupPolicy`).
    pub fn detach(&self, owner: Owner<'_>, arn: &str) -> Result<()> {
        self.change(|d| {
            let owner = d.owner(owner)?;
            let policy = d.policy(arn)?;
            let id = policy.row.id.clone();
            if !owner.attached().contains(&id) {
                return Err(IamError::NoSuchEntity(format!(
                    "Policy {arn} was not found."
                )));
            }
            d.write(IamWrite::Detach(owner.id().to_owned(), id.clone()));
            owner.update(d, |_, attached| {
                attached.remove(&id);
            });
            Ok(())
        })
    }

    /// The managed policies attached to a user or group, by name
    /// (`ListAttachedUserPolicies`, `ListAttachedGroupPolicies`).
    pub fn attached(&self, owner: Owner<'_>, prefix: Option<&str>) -> Result<Vec<AttachedPolicy>> {
        let under = under(prefix)?;
        self.read(|s| {
            let ids = match owner {
                Owner::User(name) => &s.user_named(name)?.attached,
                Owner::Group(name) => &s.group_named(name)?.attached,
            };
            let policies = ids
                .iter()
                .filter_map(|id| s.policies.get(id))
                .filter(|p| under(&p.row.path))
                .map(|p| AttachedPolicy {
                    name: p.row.name.clone(),
                    arn: s.policy_arn(&p.row),
                })
                .collect();
            Ok(by_name(policies, |p: &AttachedPolicy| &p.name))
        })
    }

    /// The groups and users a managed policy is attached to (`ListEntitiesForPolicy`).
    pub fn entities_for_policy(&self, arn: &str) -> Result<(Vec<GroupInfo>, Vec<UserInfo>)> {
        self.read(|s| {
            let id = &s.policy_by_arn(arn)?.row.id;
            let groups = s
                .groups
                .values()
                .filter(|g| g.attached.contains(id))
                .map(|g| group_info(s, g))
                .collect();
            let users = s
                .users
                .values()
                .filter(|u| u.attached.contains(id))
                .map(|u| user_info(s, u))
                .collect();
            Ok((
                by_name(groups, |g: &GroupInfo| &g.name),
                by_name(users, |u: &UserInfo| &u.name),
            ))
        })
    }

    /// The users that have a managed policy as their permissions boundary, by name
    /// (`ListEntitiesForPolicy` with `PolicyUsageFilter=PermissionsBoundary`).
    pub fn users_with_boundary(&self, arn: &str) -> Result<Vec<UserInfo>> {
        self.read(|s| {
            let id = &s.policy_by_arn(arn)?.row.id;
            let users = s
                .users
                .values()
                .filter(|u| u.boundary.as_ref() == Some(id))
                .map(|u| user_info(s, u))
                .collect();
            Ok(by_name(users, |u: &UserInfo| &u.name))
        })
    }

    /// Adds or replaces an inline policy (`PutUserPolicy`, `PutGroupPolicy`).
    pub fn put_inline(&self, owner: Owner<'_>, name: &str, document: &str) -> Result<()> {
        self.change(|d| d.put_inline(owner, name, document))
    }

    /// An inline policy's document (`GetUserPolicy`, `GetGroupPolicy`).
    pub fn inline(&self, owner: Owner<'_>, name: &str) -> Result<String> {
        self.read(|s| {
            let (inline, kind) = match owner {
                Owner::User(n) => (&s.user_named(n)?.inline, "user"),
                Owner::Group(n) => (&s.group_named(n)?.inline, "group"),
            };
            inline.get(name).map(|d| d.text.to_string()).ok_or_else(|| {
                IamError::NoSuchEntity(format!(
                    "The {kind} policy with name {name} cannot be found."
                ))
            })
        })
    }

    /// The names of a user's or group's inline policies, sorted (`ListUserPolicies`,
    /// `ListGroupPolicies`).
    pub fn inline_names(&self, owner: Owner<'_>) -> Result<Vec<String>> {
        self.read(|s| {
            let inline = match owner {
                Owner::User(n) => &s.user_named(n)?.inline,
                Owner::Group(n) => &s.group_named(n)?.inline,
            };
            Ok(inline.keys().cloned().collect())
        })
    }

    /// Deletes an inline policy (`DeleteUserPolicy`, `DeleteGroupPolicy`).
    pub fn delete_inline(&self, owner: Owner<'_>, name: &str) -> Result<()> {
        self.change(|d| {
            let owner = d.owner(owner)?;
            if !owner.inline().contains_key(name) {
                return Err(IamError::NoSuchEntity(format!(
                    "The {} policy with name {name} cannot be found.",
                    owner.kind()
                )));
            }
            d.write(IamWrite::DeleteInline(
                owner.id().to_owned(),
                name.to_owned(),
            ));
            owner.update(d, |inline, _| {
                inline.remove(name);
            });
            Ok(())
        })
    }
}
