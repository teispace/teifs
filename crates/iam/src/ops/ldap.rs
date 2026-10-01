//! What LDAP sign-in keeps: the managed policies mapped to directory users' and groups'
//! DNs (MinIO's `mc idp ldap policy attach`), and a record of each user with live
//! sessions: its groups as the directory last said, and its generation, which goes up
//! when the directory no longer has it: sessions of an older generation are revoked.

use std::{collections::BTreeSet, sync::Arc};

use teifs_meta::{IamWrite, LdapSessionRow};

use crate::{
    Draft, Iam, IamError, Result,
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

    /// Records a sign-in: the user's groups as the directory just said, and how long
    /// its sessions last at least. Answers the generation its new session takes: its
    /// sessions from before it was found gone stay revoked.
    pub(crate) fn record_ldap_sign_in(&self, signed_in: &LdapSignIn<'_>) -> Result<u32> {
        self.change(|d| {
            let before = d.state.ldap_sessions.get(signed_in.dn).cloned();
            let seen = LdapSeen {
                dn: signed_in.dn.to_owned(),
                username: signed_in.username.to_owned(),
                groups: signed_in.groups.to_vec(),
                checked_ms: d.now,
                expires_ms: before.as_ref().map_or(signed_in.expires_ms, |b| {
                    b.expires_ms.max(signed_in.expires_ms)
                }),
                generation: before.as_ref().map_or(0, |b| b.generation),
                gone: false,
            };
            let generation = seen.generation;
            d.save_ldap_session(seen);
            Ok(generation)
        })
    }

    /// The users with live sessions, to check against the directory: (DN, the name it
    /// signed in with). Records whose sessions have all expired are dropped first.
    pub(crate) fn ldap_users_to_check(&self) -> Result<Vec<(String, String)>> {
        self.change(|d| {
            let now = d.now;
            let expired: Vec<String> = d
                .state
                .ldap_sessions
                .values()
                .filter(|s| s.expires_ms <= now)
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
                        "an LDAP user is gone from the directory: its sessions are revoked"
                    );
                    seen.generation = before.generation.saturating_add(1);
                    seen.gone = true;
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
