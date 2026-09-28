//! IAM's state in memory: every entity, by id, with its policies parsed. Changes clone
//! the state (entities are behind `Arc`s, so that's cheap), change the clone and swap it
//! in once the database has the same change.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use teifs_crypto::DataKey;
use teifs_meta::{AccessKeyRow, IamRows, InlineRow, PolicyRow, PolicyVersionRow};
use teifs_policy::{Kind as PolicyKind, Policy};
use zeroize::Zeroizing;

use crate::{IamError, Result};

/// A policy document: the text as given (returned as is) and what it says.
#[derive(Debug, Clone)]
pub(crate) struct Document {
    pub(crate) text: Arc<str>,
    pub(crate) policy: Arc<Policy>,
    /// Characters other than white space: what IAM's size limits count.
    pub(crate) size: usize,
}

impl Document {
    /// Checks and parses a document given to IAM.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let size = crate::rules::document(text)?;
        let policy = Policy::parse(text, PolicyKind::Identity)
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
pub(crate) struct Version {
    pub(crate) document: Document,
    pub(crate) created_ms: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct Managed {
    pub(crate) row: PolicyRow,
    pub(crate) versions: BTreeMap<u32, Version>,
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
    pub(crate) policies: BTreeMap<String, Arc<Managed>>,
    pub(crate) keys: BTreeMap<String, Arc<Key>>,
}

impl State {
    /// The state the database holds; `key` opens the secrets.
    pub(crate) fn load(account: &str, rows: IamRows, key: &DataKey) -> Result<Self> {
        let mut state = Self {
            account: account.into(),
            policies: load_policies(rows.policies, rows.versions)?,
            keys: load_keys(rows.keys, key)?,
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
            }
        }
        for (owner, policy) in rows.attached {
            if let Some(u) = users.get_mut(&owner) {
                u.attached.insert(policy);
            } else if let Some(g) = groups.get_mut(&owner) {
                g.attached.insert(policy);
            }
        }
        state.users = users.into_iter().map(|(id, u)| (id, Arc::new(u))).collect();
        state.groups = groups
            .into_iter()
            .map(|(id, g)| (id, Arc::new(g)))
            .collect();
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

    /// How many users and groups a managed policy is attached to.
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
    }

    /// How many users have a managed policy as their permissions boundary.
    pub(crate) fn boundary_uses(&self, policy: &str) -> usize {
        self.users
            .values()
            .filter(|u| u.boundary.as_deref() == Some(policy))
            .count()
    }

    pub(crate) fn user_arn(&self, user: &User) -> String {
        format!(
            "arn:aws:iam::{}:user{}{}",
            self.account, user.path, user.name
        )
    }

    pub(crate) fn group_arn(&self, group: &Group) -> String {
        format!(
            "arn:aws:iam::{}:group{}{}",
            self.account, group.path, group.name
        )
    }

    pub(crate) fn policy_arn(&self, policy: &PolicyRow) -> String {
        format!(
            "arn:aws:iam::{}:policy{}{}",
            self.account, policy.path, policy.name
        )
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
}

fn load_policies(
    rows: Vec<PolicyRow>,
    version_rows: Vec<PolicyVersionRow>,
) -> Result<BTreeMap<String, Arc<Managed>>> {
    let mut policies = BTreeMap::new();
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
        policies.insert(row.id.clone(), Arc::new(Managed { row, versions }));
    }
    Ok(policies)
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
