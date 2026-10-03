//! Roles: who may assume them (their trust policy), what their sessions may do, and
//! their tags and permissions boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use teifs_meta::IamWrite;
use teifs_policy::{Date, StsKey};

use super::{TagKeys, by_name, checked_tags, merged, removed, under};
use crate::{
    Draft, Iam, IamError, Identity, Issued, Result, ids,
    rules::{self, MAX_ROLES},
    sessions::{Claims, Who, now_seconds},
    state::{Document, Role, State},
};

/// A role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInfo {
    /// Its unique id (`AROA…`).
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its ARN.
    pub arn: String,
    /// Its description (empty if it has none).
    pub description: String,
    /// Its trust policy, as given.
    pub trust: String,
    /// The longest session it allows, in seconds.
    pub max_session: u32,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its tags.
    pub tags: Vec<(String, String)>,
    /// The ARN of its permissions boundary.
    pub boundary: Option<String>,
}

pub(super) fn role_info(state: &State, role: &Role) -> RoleInfo {
    RoleInfo {
        id: role.id.clone(),
        name: role.name.clone(),
        path: role.path.clone(),
        arn: state.role_arn(role),
        description: role.description.clone(),
        trust: role.trust.text.to_string(),
        max_session: role.max_session,
        created_ms: role.created_ms,
        tags: role.tags.clone(),
        boundary: role
            .boundary
            .as_ref()
            .and_then(|id| state.policies.get(id))
            .map(|p| state.policy_arn(p)),
    }
}

/// What a role is made with, besides its name (`CreateRole`'s parameters).
#[derive(Debug, Clone, Copy, Default)]
pub struct NewRole<'a> {
    /// Its path; `/` if not given.
    pub path: Option<&'a str>,
    /// Its trust policy.
    pub trust: &'a str,
    /// Its description.
    pub description: Option<&'a str>,
    /// The longest session it allows; an hour if not given.
    pub max_session: Option<u32>,
    /// Its tags.
    pub tags: &'a [(String, String)],
    /// The ARN of its permissions boundary.
    pub boundary: Option<&'a str>,
}

/// The users and roles of this account that a trust policy names, bound to their
/// unique ids; one that doesn't exist makes the policy invalid, as on AWS, and so does
/// an OpenID Connect or SAML provider of this account it names as `Federated`.
fn bind_principals(state: &State, trust: &Document) -> Result<BTreeMap<String, String>> {
    let mut bound = BTreeMap::new();
    for arn in trust.policy.principal_arns() {
        let ours = arn
            .strip_prefix("arn:aws:iam::")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(account, resource)| {
                account == &*state.account
                    && (resource.starts_with("user/") || resource.starts_with("role/"))
            });
        if !ours {
            // Sessions and other accounts' principals can't be looked up; they stay
            // as written.
            continue;
        }
        let id = state.id_of(arn).ok_or_else(|| {
            IamError::MalformedPolicyDocument(format!(
                "Invalid principal in policy: \"AWS\":\"{arn}\""
            ))
        })?;
        bound.insert(arn.to_owned(), id.to_owned());
    }
    // This account's OpenID Connect and SAML providers must exist, as on AWS; other
    // identity providers (another account's, `cognito-identity.amazonaws.com`) stay as
    // written and match no one.
    for provider in trust.policy.federated_providers() {
        let resource = provider
            .strip_prefix("arn:aws:iam::")
            .and_then(|rest| rest.split_once(':'))
            .filter(|(account, _)| *account == &*state.account)
            .map(|(_, resource)| resource);
        let missing = match resource {
            Some(r) if r.starts_with("oidc-provider/") => {
                state.oidc_provider_by_arn(provider).is_err()
            }
            Some(r) if r.starts_with("saml-provider/") => {
                state.saml_provider_by_arn(provider).is_err()
            }
            _ => false,
        };
        if missing {
            return Err(IamError::MalformedPolicyDocument(format!(
                "Invalid principal in policy: \"Federated\":\"{provider}\""
            )));
        }
    }
    Ok(bound)
}

impl Draft<'_> {
    pub(crate) fn role(&self, name: &str) -> Result<Arc<Role>> {
        self.state.role_named(name).cloned()
    }

    pub(super) fn save_role(&mut self, role: Role) {
        self.write(IamWrite::PutRole(role.row()));
        self.state.roles.insert(role.id.clone(), Arc::new(role));
    }

    /// [`Iam::create_role`], as part of a change.
    pub(crate) fn create_role(&mut self, name: &str, new: &NewRole<'_>) -> Result<RoleInfo> {
        rules::name("role name", name, rules::USER_NAME)?;
        let path = new.path.unwrap_or("/");
        rules::path(path)?;
        let description = new.description.unwrap_or_default();
        rules::description(description)?;
        let max_session = new
            .max_session
            .map_or(Ok(*rules::ROLE_SESSION.start()), rules::max_session)?;
        checked_tags(TagKeys::User, new.tags)?;
        let tags = merged(TagKeys::User, &[], new.tags)?;
        let trust = Document::trust(new.trust)?;
        if self
            .state
            .roles
            .values()
            .any(|r| r.name.eq_ignore_ascii_case(name))
        {
            return Err(IamError::EntityAlreadyExists(format!(
                "Role with name {name} already exists."
            )));
        }
        if self.state.roles.len() >= MAX_ROLES {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for RolesPerAccount: {MAX_ROLES}"
            )));
        }
        let boundary = new
            .boundary
            .map(|arn| self.policy(arn).map(|p| p.row.id.clone()))
            .transpose()?;
        let role = Role {
            id: self.new_id(ids::Kind::Role),
            name: name.to_owned(),
            path: path.to_owned(),
            description: description.to_owned(),
            created_ms: self.now,
            principals: bind_principals(&self.state, &trust)?,
            trust,
            max_session,
            boundary,
            tags: tags.clone(),
            inline: BTreeMap::new(),
            attached: BTreeSet::new(),
        };
        let id = role.id.clone();
        self.save_role(role);
        for (key, value) in &tags {
            self.write(IamWrite::PutRoleTag(id.clone(), key.clone(), value.clone()));
        }
        Ok(role_info(&self.state, &self.state.roles[&id]))
    }

    /// [`Iam::update_trust`], as part of a change.
    pub(crate) fn set_trust(&mut self, name: &str, document: &str) -> Result<()> {
        let trust = Document::trust(document)?;
        let mut role = Arc::unwrap_or_clone(self.role(name)?);
        role.principals = bind_principals(&self.state, &trust)?;
        role.trust = trust;
        self.save_role(role);
        Ok(())
    }
}

/// Roles.
impl Iam {
    /// Creates a role (`CreateRole`).
    pub fn create_role(&self, name: &str, new: &NewRole<'_>) -> Result<RoleInfo> {
        self.change(|d| d.create_role(name, new))
    }

    /// Temporary credentials for an AWS service acting as the role at `role_arn`, as
    /// S3 Batch Operations runs a job's tasks: the role's trust policy must let the
    /// `service` principal (`batchoperations.s3.amazonaws.com`) assume it. The session
    /// lasts `seconds`, or the role's longest session if that's shorter.
    pub fn service_session(
        &self,
        role_arn: &str,
        service: &str,
        session_name: &str,
        seconds: u32,
    ) -> Result<Issued> {
        let role = self
            .read(|s| Ok(s.id_of(role_arn).and_then(|id| s.roles.get(id)).cloned()))?
            .ok_or_else(|| {
                IamError::NoSuchEntity(format!("The role {role_arn} cannot be found."))
            })?;
        let identity = Identity::service(service);
        let context = identity
            .context(Date::from_unix_seconds(now_seconds()))
            .with_sts(StsKey::RoleSessionName, session_name);
        if !identity.allows_with(
            &context,
            "sts:AssumeRole",
            role_arn,
            Some(&role.trust.policy),
        ) {
            return Err(IamError::AccessDenied(format!(
                "The role {role_arn} doesn't trust {service} to assume it."
            )));
        }
        let who = Who::Role {
            role: role.id.clone(),
            name: session_name.to_owned(),
            chained: false,
        };
        self.issue_at_least(&Claims::issued_now(who, seconds.min(role.max_session)), 0)
    }

    /// A role (`GetRole`).
    pub fn role(&self, name: &str) -> Result<RoleInfo> {
        self.read(|s| Ok(role_info(s, s.role_named(name)?)))
    }

    /// Roles whose path starts with `prefix`, by name (`ListRoles`).
    pub fn roles(&self, prefix: Option<&str>) -> Result<Vec<RoleInfo>> {
        let under = under(prefix)?;
        self.read(|s| {
            let roles = s
                .roles
                .values()
                .filter(|r| under(&r.path))
                .map(|r| role_info(s, r))
                .collect();
            Ok(by_name(roles, |r: &RoleInfo| &r.name))
        })
    }

    /// Changes a role's description or longest session (`UpdateRole`,
    /// `UpdateRoleDescription`); what isn't given stays.
    pub fn update_role(
        &self,
        name: &str,
        description: Option<&str>,
        max_session: Option<u32>,
    ) -> Result<RoleInfo> {
        if let Some(description) = description {
            rules::description(description)?;
        }
        let max_session = max_session.map(rules::max_session).transpose()?;
        self.change(|d| {
            let mut role = Arc::unwrap_or_clone(d.role(name)?);
            if let Some(description) = description {
                description.clone_into(&mut role.description);
            }
            if let Some(max_session) = max_session {
                role.max_session = max_session;
            }
            let id = role.id.clone();
            d.save_role(role);
            Ok(role_info(&d.state, &d.state.roles[&id]))
        })
    }

    /// Replaces a role's trust policy (`UpdateAssumeRolePolicy`).
    pub fn update_trust(&self, name: &str, document: &str) -> Result<()> {
        self.change(|d| d.set_trust(name, document))
    }

    /// Deletes a role with no policies left (`DeleteRole`).
    pub fn delete_role(&self, name: &str) -> Result<()> {
        self.change(|d| {
            let role = d.role(name)?;
            let conflict = if !role.inline.is_empty() {
                Some("inline policies")
            } else if !role.attached.is_empty() {
                Some("attached policies")
            } else {
                None
            };
            if let Some(what) = conflict {
                return Err(IamError::DeleteConflict(format!(
                    "Cannot delete entity, must remove {what} first."
                )));
            }
            d.state.roles.remove(&role.id);
            d.write(IamWrite::DeleteRole(role.id.clone()));
            Ok(())
        })
    }

    /// Adds or replaces a role's tags; keys compare without case (`TagRole`).
    pub fn tag_role(&self, name: &str, tags: &[(String, String)]) -> Result<()> {
        checked_tags(TagKeys::User, tags)?;
        self.change(|d| {
            let mut role = Arc::unwrap_or_clone(d.role(name)?);
            role.tags = merged(TagKeys::User, &role.tags, tags)?;
            for (key, value) in tags {
                d.write(IamWrite::PutRoleTag(
                    role.id.clone(),
                    key.clone(),
                    value.clone(),
                ));
            }
            d.state.roles.insert(role.id.clone(), Arc::new(role));
            Ok(())
        })
    }

    /// Removes a role's tags; absent keys are ignored (`UntagRole`).
    pub fn untag_role(&self, name: &str, keys: &[String]) -> Result<()> {
        self.change(|d| {
            let mut role = Arc::unwrap_or_clone(d.role(name)?);
            for key in removed(TagKeys::User, &mut role.tags, keys) {
                d.write(IamWrite::DeleteRoleTag(role.id.clone(), key.clone()));
            }
            d.state.roles.insert(role.id.clone(), Arc::new(role));
            Ok(())
        })
    }

    /// Sets or removes a role's permissions boundary (`PutRolePermissionsBoundary`,
    /// `DeleteRolePermissionsBoundary`).
    pub fn set_role_boundary(&self, name: &str, arn: Option<&str>) -> Result<()> {
        self.change(|d| {
            let mut role = Arc::unwrap_or_clone(d.role(name)?);
            let boundary = arn
                .map(|arn| d.policy(arn).map(|p| p.row.id.clone()))
                .transpose()?;
            if boundary.is_none() && role.boundary.is_none() {
                return Err(IamError::NoSuchEntity(format!(
                    "The role {name} has no permissions boundary."
                )));
            }
            role.boundary = boundary;
            d.save_role(role);
            Ok(())
        })
    }

    /// The roles that have a managed policy as their permissions boundary, by name.
    pub fn roles_with_boundary(&self, arn: &str) -> Result<Vec<RoleInfo>> {
        self.read(|s| {
            let id = &s.policy_by_arn(arn)?.row.id;
            let roles = s
                .roles
                .values()
                .filter(|r| r.boundary.as_ref() == Some(id))
                .map(|r| role_info(s, r))
                .collect();
            Ok(by_name(roles, |r: &RoleInfo| &r.name))
        })
    }
}
