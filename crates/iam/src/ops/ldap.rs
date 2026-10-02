//! What LDAP sign-in keeps: the managed policies mapped to directory users' and groups'
//! DNs (MinIO's `mc idp ldap policy attach`), and a record of each user with live
//! sessions: its groups as the directory last said, and its generation, which goes up
//! when the directory no longer has it: sessions of an older generation are revoked.

use std::{collections::BTreeSet, sync::Arc};

use teifs_meta::{IamWrite, LdapSessionRow};

use crate::{
    Draft, GroupPolicies, Iam, IamError, PolicyEntities, PolicyHolders, Result, UserPolicies,
    ldap::{
        LdapError,
        client::{Found, Kind},
        dn,
    },
    state::{LdapMapping, LdapSeen, State},
};

/// Whether a DN is a directory user's or a group's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LdapEntity {
    /// A user: its own sessions get the policies.
    User,
    /// A group: its members' sessions get the policies.
    Group,
}

impl LdapEntity {
    /// `user` or `group`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "user" => Some(Self::User),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

/// The policies mapped to a DN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapPolicies {
    /// The DN, written in one form.
    pub dn: String,
    /// A user's or a group's.
    pub entity: LdapEntity,
    /// The managed policies' names.
    pub policies: Vec<String>,
}

/// What a change to a DN's policies did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapPolicyChange {
    /// The DN, written in one form.
    pub dn: String,
    /// A user's or a group's.
    pub entity: LdapEntity,
    /// The policies the change added or removed, by name.
    pub changed: Vec<String>,
    /// The policies mapped to it now, by name.
    pub policies: Vec<String>,
}

/// A directory user, as the directory said just now: whom an LDAP user's service account
/// is made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapUser<'a> {
    /// Its DN, written in one form.
    pub dn: &'a str,
    /// The name it signs in with.
    pub username: &'a str,
    /// Its groups' DNs, written in one form.
    pub groups: &'a [String],
}

/// A user the directory signed in, as a session's record keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LdapSignIn<'a> {
    pub(crate) dn: &'a str,
    pub(crate) username: &'a str,
    pub(crate) groups: &'a [String],
    /// When the session it gets expires, in milliseconds since the Unix epoch.
    pub(crate) expires_ms: i64,
}

fn names(state: &State, ids: &BTreeSet<String>) -> Vec<String> {
    let mut names: Vec<String> = ids
        .iter()
        .filter_map(|id| state.policies.get(id))
        .map(|p| p.row.name.clone())
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    names
}

/// The managed policy a name or ARN names, by id.
fn policy_id(state: &State, name: &str) -> Result<String> {
    state
        .policy_named(name)
        .map(|p| p.row.id.clone())
        .ok_or_else(|| IamError::NoSuchEntity(format!("Policy {name} does not exist.")))
}

/// The mappings of these users (DN and groups' DNs), groups and policies, or every
/// mapping when none are asked for.
fn ldap_entities(
    state: &State,
    users: &[(String, Vec<String>)],
    groups: &[String],
    policies: &[String],
) -> PolicyEntities {
    let all = users.is_empty() && groups.is_empty() && policies.is_empty();
    let mapped = |dn: &str, entity: LdapEntity| {
        state
            .ldap_policies
            .values()
            .find(|m| m.entity == entity && m.dn.eq_ignore_ascii_case(dn))
            .map(|m| names(state, &m.policies))
            .unwrap_or_default()
    };
    let group_policies = |dn: &str| {
        let policies = mapped(dn, LdapEntity::Group);
        (!policies.is_empty()).then(|| GroupPolicies {
            group: dn.to_owned(),
            policies,
        })
    };
    let mut entities = PolicyEntities::default();
    let by_entity = |entity| {
        state
            .ldap_policies
            .values()
            .filter(move |m| m.entity == entity)
            .map(|m| m.dn.clone())
    };
    let asked_users: Vec<(String, Vec<String>)> = if all {
        by_entity(LdapEntity::User)
            .map(|dn| (dn, Vec::new()))
            .collect()
    } else {
        users.to_vec()
    };
    for (dn, member_of) in asked_users {
        let user = UserPolicies {
            policies: mapped(&dn, LdapEntity::User),
            groups: member_of.iter().filter_map(|g| group_policies(g)).collect(),
            user: dn,
        };
        if !user.policies.is_empty() || !user.groups.is_empty() {
            entities.users.push(user);
        }
    }
    let asked_groups: Vec<String> = if all {
        by_entity(LdapEntity::Group).collect()
    } else {
        groups.to_vec()
    };
    entities.groups = asked_groups
        .iter()
        .filter_map(|g| group_policies(g))
        .collect();
    let asked_policies: Vec<&Arc<crate::state::Managed>> = if all {
        let mapped: BTreeSet<&String> = state
            .ldap_policies
            .values()
            .flat_map(|m| m.policies.iter())
            .collect();
        mapped
            .into_iter()
            .filter_map(|id| state.policies.get(id))
            .collect()
    } else {
        policies
            .iter()
            .filter_map(|n| state.policy_named(n))
            .collect()
    };
    for policy in asked_policies {
        let holders = |entity| {
            state
                .ldap_policies
                .values()
                .filter(|m| m.entity == entity && m.policies.contains(&policy.row.id))
                .map(|m| m.dn.clone())
                .collect::<Vec<_>>()
        };
        let holders = PolicyHolders {
            policy: policy.row.name.clone(),
            users: holders(LdapEntity::User),
            groups: holders(LdapEntity::Group),
        };
        if !holders.users.is_empty() || !holders.groups.is_empty() {
            entities.policies.push(holders);
        }
    }
    entities.users.sort_by(|a, b| a.user.cmp(&b.user));
    entities.groups.sort_by(|a, b| a.group.cmp(&b.group));
    entities
        .policies
        .sort_by_cached_key(|p| p.policy.to_ascii_lowercase());
    entities
}

impl Draft<'_> {
    /// [`Iam::map_ldap_policies`], as part of a change.
    pub(crate) fn map_ldap_policies(
        &mut self,
        dn: &str,
        entity: LdapEntity,
        policies: &[String],
        attach: bool,
    ) -> Result<LdapPolicyChange> {
        if policies.is_empty() {
            return Err(IamError::InvalidInput("Name at least one policy.".into()));
        }
        let mut mapping = match self.state.ldap_policies.get(dn) {
            Some(m) if m.entity != entity => {
                return Err(IamError::InvalidInput(format!(
                    "{dn} has policies as an LDAP {}, not as a {}.",
                    m.entity.as_str(),
                    entity.as_str()
                )));
            }
            Some(m) => LdapMapping::clone(m),
            None => LdapMapping {
                dn: dn.to_owned(),
                entity,
                policies: BTreeSet::new(),
            },
        };
        let mut changed = BTreeSet::new();
        for name in policies {
            let id = policy_id(&self.state, name)?;
            if attach && mapping.policies.insert(id.clone()) {
                self.write(IamWrite::PutLdapPolicy(
                    dn.to_owned(),
                    entity.as_str().to_owned(),
                    id.clone(),
                ));
                changed.insert(id);
            } else if !attach && mapping.policies.remove(&id) {
                self.write(IamWrite::DeleteLdapPolicy(dn.to_owned(), id.clone()));
                changed.insert(id);
            }
        }
        let change = LdapPolicyChange {
            dn: dn.to_owned(),
            entity,
            changed: names(&self.state, &changed),
            policies: names(&self.state, &mapping.policies),
        };
        if mapping.policies.is_empty() {
            self.state.ldap_policies.remove(dn);
        } else {
            self.state
                .ldap_policies
                .insert(dn.to_owned(), Arc::new(mapping));
        }
        Ok(change)
    }

    /// Records what the directory said of a user: its groups (`None` keeps those last
    /// said), and sessions until `expires_ms` at least. A user found gone before is back.
    /// Answers the generation its sessions take.
    pub(crate) fn see_ldap_user(
        &mut self,
        dn: &str,
        username: &str,
        groups: Option<&[String]>,
        expires_ms: i64,
    ) -> u32 {
        let before = self.state.ldap_sessions.get(dn).cloned();
        let seen = LdapSeen {
            dn: dn.to_owned(),
            username: username.to_owned(),
            groups: groups.map_or_else(
                || {
                    before
                        .as_ref()
                        .map(|b| b.groups.clone())
                        .unwrap_or_default()
                },
                <[String]>::to_vec,
            ),
            checked_ms: self.now,
            expires_ms: before
                .as_ref()
                .map_or(expires_ms, |b| b.expires_ms.max(expires_ms)),
            generation: before.as_ref().map_or(0, |b| b.generation),
            gone: false,
        };
        let generation = seen.generation;
        self.save_ldap_session(seen);
        generation
    }

    fn save_ldap_session(&mut self, seen: LdapSeen) {
        self.write(IamWrite::PutLdapSession(seen.row()));
        self.state
            .ldap_sessions
            .insert(seen.dn.clone(), Arc::new(seen));
    }
}

impl Iam {
    /// Maps managed policies (names or ARNs) to the directory user's or group's `dn`,
    /// which the caller found in the directory and wrote in one form; or, `attach` false,
    /// removes them. Sessions of the user (or the group's members) have the change at
    /// their next request.
    ///
    /// # Errors
    ///
    /// `NoSuchEntity` for a policy that doesn't exist; `InvalidInput` when the DN is
    /// mapped as the other entity, or no policy is named.
    pub fn map_ldap_policies(
        &self,
        dn: &str,
        entity: LdapEntity,
        policies: &[String],
        attach: bool,
    ) -> Result<LdapPolicyChange> {
        self.change(|d| d.map_ldap_policies(dn, entity, policies, attach))
    }

    /// [`Iam::map_ldap_policies`] for a DN given in any spelling: the directory must have
    /// it as a user (or a group) under the base DNs, and it's kept as the directory spells
    /// it. A DN the directory no longer has can still have its policies detached.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when there's no directory, the DN is malformed or not under the
    /// base DNs; `NoSuchEntity` when the directory doesn't have it; `Directory` when
    /// the directory can't be asked; as [`Iam::map_ldap_policies`] otherwise.
    pub async fn change_ldap_policies(
        &self,
        dn: &str,
        entity: LdapEntity,
        policies: &[String],
        attach: bool,
    ) -> Result<LdapPolicyChange> {
        let directory = self
            .ldap()
            .ok_or_else(|| IamError::InvalidInput(format!("{}.", LdapError::NotSetUp)))?;
        let written = dn::normalize(dn).map_err(IamError::InvalidInput)?;
        let kind = match entity {
            LdapEntity::User => Kind::User,
            LdapEntity::Group => Kind::Group,
        };
        let found = directory
            .find(dn, kind)
            .await
            .map_err(|e| IamError::Directory(e.to_string()))?;
        let dn = match found {
            Some(Found {
                dn,
                under_base: true,
            }) => dn,
            Some(Found { dn, .. }) if !attach => dn,
            Some(Found { dn, .. }) => {
                return Err(IamError::InvalidInput(format!(
                    "{dn} isn't under the LDAP {} base DNs.",
                    entity.as_str()
                )));
            }
            None if !attach && self.read(|s| Ok(s.ldap_policies.contains_key(&written)))? => {
                written
            }
            None => {
                return Err(IamError::NoSuchEntity(format!(
                    "The LDAP directory has no {} {written}.",
                    entity.as_str()
                )));
            }
        };
        self.map_ldap_policies(&dn, entity, policies, attach)
    }

    /// A directory user named by its DN, in any spelling, or by the name it signs in
    /// with, as `MinIO` checks one: its DN written in one form, or none when the
    /// directory doesn't have it under the user base DNs.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when there's no directory; `Directory` when it can't be asked.
    pub async fn find_ldap_user(&self, name: &str) -> Result<Option<String>> {
        let directory = self
            .ldap()
            .ok_or_else(|| IamError::InvalidInput(format!("{}.", LdapError::NotSetUp)))?;
        let directory_error = |e: LdapError| IamError::Directory(e.to_string());
        if crate::ldap::is_dn(name) {
            let found = directory
                .find(name, Kind::User)
                .await
                .map_err(directory_error)?;
            return Ok(found.filter(|f| f.under_base).map(|f| f.dn));
        }
        Ok(directory
            .user(name)
            .await
            .map_err(directory_error)?
            .map(|user| user.dn))
    }

    /// Who has which policies mapped (`idp/ldap/policy-entities`): of the users (by DN
    /// or name, with their groups as the directory says now), groups (by DN) and
    /// policies named, or of every mapping when none are. Names the directory doesn't
    /// have are taken as DNs, so mappings of DNs it no longer has still show.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when there's no directory; `Directory` when it can't be asked.
    pub async fn ldap_policy_entities(
        &self,
        users: &[String],
        groups: &[String],
        policies: &[String],
    ) -> Result<PolicyEntities> {
        let directory = self
            .ldap()
            .ok_or_else(|| IamError::InvalidInput(format!("{}.", LdapError::NotSetUp)))?;
        let directory_error = |e: LdapError| IamError::Directory(e.to_string());
        let mut asked_users = Vec::new();
        for name in users {
            let found = if crate::ldap::is_dn(name) {
                match directory
                    .find(name, Kind::User)
                    .await
                    .map_err(directory_error)?
                {
                    Some(Found {
                        dn,
                        under_base: true,
                    }) => {
                        let username = self.read(|s| {
                            Ok(s.ldap_sessions
                                .get(&dn)
                                .map(|seen| seen.username.clone())
                                .unwrap_or_default())
                        })?;
                        let groups = directory
                            .refresh(&dn, &username)
                            .await
                            .map_err(directory_error)?;
                        groups.map(|groups| (dn, groups))
                    }
                    _ => None,
                }
            } else {
                directory
                    .user(name)
                    .await
                    .map_err(directory_error)?
                    .map(|user| (user.dn, user.groups))
            };
            match found {
                Some(user) => asked_users.push(user),
                None => {
                    if let Ok(dn) = dn::normalize(name) {
                        asked_users.push((dn, Vec::new()));
                    }
                }
            }
        }
        let mut asked_groups = Vec::new();
        for name in groups {
            match directory
                .find(name, Kind::Group)
                .await
                .map_err(directory_error)?
            {
                Some(Found {
                    dn,
                    under_base: true,
                }) => asked_groups.push(dn),
                _ => {
                    if let Ok(dn) = dn::normalize(name) {
                        asked_groups.push(dn);
                    }
                }
            }
        }
        self.read(|s| Ok(ldap_entities(s, &asked_users, &asked_groups, policies)))
    }

    /// Asks the directory about each user with live sessions: a user it no longer has
    /// loses its sessions, and the others' sessions get their groups as they are now.
    /// The server runs it every few minutes. A user the directory couldn't be asked
    /// about is asked again next time.
    pub async fn check_ldap_users(&self) -> Result<()> {
        let Some(directory) = self.ldap().cloned() else {
            return Ok(());
        };
        for (dn, username) in self.ldap_users_to_check()? {
            match directory.refresh(&dn, &username).await {
                Ok(groups) => self.update_ldap_user(&dn, groups.as_deref())?,
                Err(err) => {
                    tracing::warn!(dn, error = %err, "can't check an LDAP user's groups");
                }
            }
        }
        Ok(())
    }

    /// The DNs with policies, users first, each in order; `dn`, written in one form,
    /// limits it to one, whatever the case of its values, as the directories compare them.
    pub fn ldap_policies(&self, dn: Option<&str>) -> Result<Vec<LdapPolicies>> {
        self.read(|s| {
            let mut all: Vec<LdapPolicies> = s
                .ldap_policies
                .values()
                .filter(|m| dn.is_none_or(|dn| m.dn.eq_ignore_ascii_case(dn)))
                .map(|m| LdapPolicies {
                    dn: m.dn.clone(),
                    entity: m.entity,
                    policies: names(s, &m.policies),
                })
                .collect();
            all.sort_by(|a, b| a.entity.cmp(&b.entity).then_with(|| a.dn.cmp(&b.dn)));
            Ok(all)
        })
    }

    /// The directory users TeiFS keeps something of: policies mapped to them, a record
    /// of their sessions, or service accounts; by DN, in order.
    pub fn ldap_users(&self) -> Result<Vec<String>> {
        self.read(|s| {
            let users: BTreeSet<String> = s
                .ldap_policies
                .values()
                .filter(|m| m.entity == LdapEntity::User)
                .map(|m| m.dn.clone())
                .chain(s.ldap_sessions.keys().cloned())
                .chain(
                    s.service_accounts
                        .values()
                        .filter_map(|a| a.parent.ldap_dn().map(str::to_owned)),
                )
                .collect();
            Ok(users.into_iter().collect())
        })
    }

    /// Records a sign-in: the user's groups as the directory just said, and how long
    /// its sessions last at least. Answers the generation its new session takes: its
    /// sessions from before it was found gone stay revoked.
    pub(crate) fn record_ldap_sign_in(&self, signed_in: &LdapSignIn<'_>) -> Result<u32> {
        self.change(|d| {
            Ok(d.see_ldap_user(
                signed_in.dn,
                signed_in.username,
                Some(signed_in.groups),
                signed_in.expires_ms,
            ))
        })
    }

    /// The users with live sessions or service accounts, to check against the directory:
    /// (DN, the name it signed in with). Records of users with neither any more are
    /// dropped first.
    pub(crate) fn ldap_users_to_check(&self) -> Result<Vec<(String, String)>> {
        self.change(|d| {
            let now = d.now;
            let owners: BTreeSet<&str> = d
                .state
                .service_accounts
                .values()
                .filter_map(|a| a.parent.ldap_dn())
                .collect();
            let expired: Vec<String> = d
                .state
                .ldap_sessions
                .values()
                .filter(|s| s.expires_ms <= now && !owners.contains(s.dn.as_str()))
                .map(|s| s.dn.clone())
                .collect();
            for dn in expired {
                d.state.ldap_sessions.remove(&dn);
                d.write(IamWrite::DeleteLdapSession(dn));
            }
            Ok(d.state
                .ldap_sessions
                .values()
                .map(|s| (s.dn.clone(), s.username.clone()))
                .collect())
        })
    }

    /// What the directory says of a user with live sessions now: its groups, or `None`
    /// when it's gone, which revokes every session it has so far. Nothing is written
    /// when nothing changed.
    pub(crate) fn update_ldap_user(&self, dn: &str, groups: Option<&[String]>) -> Result<()> {
        self.change(|d| {
            let Some(before) = d.state.ldap_sessions.get(dn).cloned() else {
                return Ok(());
            };
            let mut seen = LdapSeen::clone(&before);
            match groups {
                Some(groups) if groups == before.groups.as_slice() && !before.gone => {
                    return Ok(());
                }
                Some(groups) => {
                    seen.groups = groups.to_vec();
                    seen.gone = false;
                }
                None if before.gone => return Ok(()),
                None => {
                    tracing::info!(
                        dn,
                        "an LDAP user is gone from the directory: its sessions and service \
                         accounts are revoked"
                    );
                    seen.generation = before.generation.saturating_add(1);
                    seen.gone = true;
                    d.remove_ldap_service_accounts_of(dn);
                }
            }
            seen.checked_ms = d.now;
            d.save_ldap_session(seen);
            Ok(())
        })
    }
}

impl LdapSeen {
    pub(crate) fn row(&self) -> LdapSessionRow {
        LdapSessionRow {
            dn: self.dn.clone(),
            username: self.username.clone(),
            groups: serde_json::to_string(&self.groups).expect("a list of strings serializes"),
            checked_ms: self.checked_ms,
            expires_ms: self.expires_ms,
            generation: self.generation,
            gone: self.gone,
        }
    }
}
