//! `MinIO`'s service accounts (`mc admin user svcacct`): access keys that act as their
//! parent, a user or the root user, narrowed by a policy of their own if they have one,
//! with a name, a description and an expiry. They're kept apart from users' access keys,
//! which IAM's API lists and caps at two.

use std::sync::Arc;

use teifs_meta::IamWrite;
use teifs_types::admin::ExportedServiceAccount;
use zeroize::Zeroizing;

use super::minio::{MinioError, documents, merged, user_named};
use crate::{
    Draft, Iam, IamError, Identity, SessionKind, builtin, ids,
    ops::ldap::LdapUser,
    rules,
    state::{Document, OpenIdParent, Parent, ServiceAccount, State},
};

type Result<T> = std::result::Result<T, MinioError>;

/// The longest name `MinIO` gives a service account.
const NAME: usize = 32;
/// The longest description.
const DESCRIPTION: usize = 256;
/// The largest policy, in characters other than white space.
const POLICY: usize = 4096;
/// The soonest and latest an expiry may be, from now: 15 minutes and 365 days.
const SOONEST_MS: i64 = 15 * 60 * 1000;
const LATEST_MS: i64 = 365 * 24 * 3600 * 1000;

/// A service account to make (`add-service-account`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NewServiceAccount<'a> {
    /// Its access key; one is made when `None`.
    pub access_key: Option<&'a str>,
    /// Its secret key, given with the access key; one is made when `None`.
    pub secret: Option<&'a str>,
    /// The policy that narrows it; `None` for all its parent may do.
    pub policy: Option<&'a str>,
    /// Its name (may be empty).
    pub name: &'a str,
    /// Its description (may be empty).
    pub description: &'a str,
    /// When it stops signing, in milliseconds since the Unix epoch; `None` (or 0) for
    /// never.
    pub expires_ms: Option<i64>,
}

/// A change to a service account (`update-service-account`): what's `None` stays.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceAccountChange<'a> {
    /// A new secret key.
    pub secret: Option<&'a str>,
    /// Whether it signs.
    pub enabled: Option<bool>,
    /// A new policy, or `Some(None)` to have all its parent may do.
    pub policy: Option<Option<&'a str>>,
    /// A new name.
    pub name: Option<&'a str>,
    /// A new description.
    pub description: Option<&'a str>,
    /// A new expiry, or `Some(None)` (or 0) for never.
    pub expires_ms: Option<Option<i64>>,
}

/// A service account just made, with the only copy of its secret.
pub struct AddedServiceAccount {
    /// Its access key.
    pub access_key: String,
    /// Its secret key.
    pub secret: Zeroizing<String>,
    /// When it stops signing.
    pub expires_ms: Option<i64>,
}

impl std::fmt::Debug for AddedServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddedServiceAccount")
            .field("access_key", &self.access_key)
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

/// An OpenID Connect user's service account, as `MinIO` lists it by user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenIdServiceAccount {
    /// `MinIO`'s name for the user.
    pub user: String,
    /// The user's `sub`.
    pub sub: String,
    /// The account.
    pub account: MinioServiceAccount,
}

/// A service account, as `MinIO` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinioServiceAccount {
    /// Its access key.
    pub access_key: String,
    /// Its parent's name: a user's, or the root user's access key.
    pub parent: String,
    /// Whether it signs.
    pub enabled: bool,
    /// Whether it has all its parent may do (no policy of its own).
    pub implied: bool,
    /// Its policy, or its parent's policies' statements in one document when implied.
    pub policy: String,
    /// Its name.
    pub name: String,
    /// Its description.
    pub description: String,
    /// When it stops signing, in milliseconds since the Unix epoch.
    pub expires_ms: Option<i64>,
    /// When it was made.
    pub created_ms: i64,
}

/// A name `MinIO`'s client takes: up to 32 bytes, starting with a letter.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || (name.len() <= NAME && name.starts_with(|c: char| c.is_ascii_alphabetic()))
    {
        Ok(())
    } else {
        Err(MinioError::InvalidResource(format!(
            "A service account's name is up to {NAME} characters and starts with a letter."
        )))
    }
}

fn check_description(description: &str) -> Result<()> {
    if description.len() <= DESCRIPTION {
        Ok(())
    } else {
        Err(MinioError::InvalidResource(format!(
            "A service account's description is up to {DESCRIPTION} bytes."
        )))
    }
}

/// An expiry, whole seconds, between 15 minutes and 365 days from `now`; 0 is never.
fn check_expiry(expires_ms: Option<i64>, now: i64) -> Result<Option<i64>> {
    let Some(ms) = expires_ms.filter(|ms| *ms != 0) else {
        return Ok(None);
    };
    let ms = ms - ms.rem_euclid(1000);
    if ms < now + SOONEST_MS || ms > now + LATEST_MS {
        return Err(MinioError::InvalidArgument(
            "A service account expires between 15 minutes and 365 days from now.".into(),
        ));
    }
    Ok(Some(ms))
}

fn parse_policy(text: &str) -> Result<Document> {
    let document = Document::parse(text)?;
    if document.size > POLICY {
        return Err(MinioError::PolicyTooLarge);
    }
    Ok(document)
}

/// Whether an access key is in use: a user's key or name, a service account's, or the
/// root user's.
fn taken(state: &State, root: Option<&str>, id: &str) -> bool {
    state.keys.contains_key(id)
        || state.service_accounts.contains_key(id)
        || state.user_named(id).is_ok()
        || root == Some(id)
}

/// The parent's name: a user's, the root user's access key, a directory user's DN, or
/// `MinIO`'s name for an OpenID Connect user.
fn parent_name(state: &State, root: Option<&str>, account: &ServiceAccount) -> String {
    match &account.parent {
        Parent::User(id) => state.users.get(id).map(|u| u.name.clone()),
        Parent::Root => root.map(str::to_owned),
        Parent::Ldap { dn, .. } => Some(dn.clone()),
        Parent::OpenId(openid) => state
            .oidc_providers
            .get(&openid.provider)
            .map(|p| openid.name(&p.url)),
    }
    .unwrap_or_default()
}

/// The managed policies mapped to a directory user's DN and its groups' DNs, as the
/// directory last said.
fn ldap_documents<'a>(state: &'a State, dn: &'a str) -> impl Iterator<Item = &'a str> {
    let groups = state
        .ldap_sessions
        .get(dn)
        .map(|seen| seen.groups.as_slice())
        .unwrap_or_default();
    std::iter::once(dn)
        .chain(groups.iter().map(String::as_str))
        .filter_map(|dn| state.ldap_policies.get(dn))
        .flat_map(|m| m.policies.iter())
        .filter_map(|id| state.policies.get(id))
        .map(|p| &*p.default_document().text)
}

fn describe(state: &State, root: Option<&str>, account: &ServiceAccount) -> MinioServiceAccount {
    let policy = match (&account.policy, &account.parent) {
        (Some(policy), _) => policy.text.to_string(),
        (None, Parent::Ldap { dn, .. }) => merged(ldap_documents(state, dn)),
        (None, Parent::OpenId(openid)) => merged(
            openid
                .policies
                .iter()
                .filter_map(|id| state.policies.get(id))
                .map(|p| &*p.default_document().text),
        ),
        (None, Parent::User(id)) => state.users.get(id).map_or_else(
            || merged([]),
            |user| {
                let groups = state.groups_of(&user.id).filter(|g| !g.disabled);
                merged(
                    documents(state, &user.inline, &user.attached)
                        .chain(groups.flat_map(|g| documents(state, &g.inline, &g.attached))),
                )
            },
        ),
        (None, Parent::Root) => merged(
            builtin::BUILTINS
                .iter()
                .filter(|b| b.name == "consoleAdmin")
                .map(|b| b.document),
        ),
    };
    MinioServiceAccount {
        access_key: account.id.clone(),
        parent: parent_name(state, root, account),
        enabled: account.active,
        implied: account.policy.is_none(),
        policy,
        name: account.name.clone(),
        description: account.description.clone(),
        expires_ms: account.expires_ms,
        created_ms: account.created_ms,
    }
}

impl Draft<'_> {
    /// The user named `parent`, or the root user for the root user's key.
    fn parent(&self, parent: &str) -> Result<Parent> {
        if self.root == Some(parent) {
            return Ok(Parent::Root);
        }
        Ok(Parent::User(user_named(&self.state, parent)?.id.clone()))
    }

    fn save_service_account(&mut self, account: ServiceAccount) {
        self.write(IamWrite::PutServiceAccount(account.row()));
        self.state
            .service_accounts
            .insert(account.id.clone(), Arc::new(account));
    }

    /// Makes a service account for `parent`, whose name (a user's, the root user's key,
    /// a directory user's) its access key may not be.
    fn add_service_account(
        &mut self,
        parent: Parent,
        parent_name: &str,
        new: NewServiceAccount<'_>,
    ) -> Result<AddedServiceAccount> {
        check_name(new.name)?;
        check_description(new.description)?;
        let expires_ms = check_expiry(new.expires_ms, self.now)?;
        let policy = new.policy.map(parse_policy).transpose()?;
        let (id, secret) = match (new.access_key, new.secret) {
            (Some(id), Some(secret)) => {
                rules::access_key_id(id).map_err(MinioError::InvalidAccessKey)?;
                rules::secret_key(secret).map_err(MinioError::InvalidSecretKey)?;
                if self.root == Some(id) {
                    return Err(MinioError::RootCredentials);
                }
                if id.eq_ignore_ascii_case(parent_name) {
                    return Err(MinioError::ActionNotAllowed(
                        "A service account's access key can't be its parent's name.".into(),
                    ));
                }
                if taken(&self.state, self.root, id) {
                    return Err(MinioError::ServiceAccountNotAllowed(
                        "the service account access key already taken".into(),
                    ));
                }
                (id.to_owned(), Zeroizing::new(secret.to_owned()))
            }
            (Some(_), None) => return Err(MinioError::NoSecretKey),
            (None, Some(_)) => return Err(MinioError::NoAccessKey),
            (None, None) => {
                let id = loop {
                    let id = ids::access_key();
                    if !taken(&self.state, self.root, &id) {
                        break id;
                    }
                };
                (id, ids::secret_key())
            }
        };
        let secret = Arc::new(secret);
        self.save_service_account(ServiceAccount {
            sealed: self.key.seal_secret(id.as_bytes(), secret.as_bytes()),
            secret: Arc::clone(&secret),
            id: id.clone(),
            parent,
            active: true,
            policy,
            name: new.name.to_owned(),
            description: new.description.to_owned(),
            expires_ms,
            created_ms: self.now,
        });
        Ok(AddedServiceAccount {
            access_key: id,
            secret: Zeroizing::new(secret.to_string()),
            expires_ms,
        })
    }

    fn update_service_account(&mut self, id: &str, change: ServiceAccountChange<'_>) -> Result<()> {
        let mut account = Arc::unwrap_or_clone(
            self.state
                .service_accounts
                .get(id)
                .cloned()
                .ok_or(MinioError::NoSuchServiceAccount)?,
        );
        if let Some(name) = change.name {
            check_name(name)?;
            name.clone_into(&mut account.name);
        }
        if let Some(description) = change.description {
            check_description(description)?;
            description.clone_into(&mut account.description);
        }
        if let Some(expires_ms) = change.expires_ms {
            account.expires_ms = check_expiry(expires_ms, self.now)?;
        }
        if let Some(policy) = change.policy {
            account.policy = policy.map(parse_policy).transpose()?;
        }
        if let Some(enabled) = change.enabled {
            account.active = enabled;
        }
        if let Some(secret) = change.secret {
            rules::secret_key(secret).map_err(MinioError::InvalidSecretKey)?;
            account.sealed = self.key.seal_secret(id.as_bytes(), secret.as_bytes());
            account.secret = Arc::new(Zeroizing::new(secret.to_owned()));
        }
        self.save_service_account(account);
        Ok(())
    }

    /// Makes an exported service account, with its id, secret and dates.
    pub(crate) fn import_service_account(
        &mut self,
        account: &ExportedServiceAccount,
    ) -> crate::Result<()> {
        let id = &account.id;
        let invalid = |e: String| IamError::InvalidInput(format!("Service account {id}: {e}"));
        let secret = account.secret.as_deref().unwrap_or_default();
        rules::access_key_id(id).map_err(IamError::InvalidInput)?;
        rules::secret_key(secret).map_err(invalid)?;
        check_name(&account.name).map_err(|e| invalid(e.to_string()))?;
        check_description(&account.description).map_err(|e| invalid(e.to_string()))?;
        if !(0..=self.now).contains(&account.created_ms) {
            return Err(invalid("it was created at an impossible time.".into()));
        }
        if taken(&self.state, self.root, id) {
            return Err(IamError::EntityAlreadyExists(format!(
                "The access key {id} is already in use."
            )));
        }
        let policy = match account.policy.as_deref().map(parse_policy).transpose() {
            Ok(policy) => policy,
            Err(MinioError::Iam(e)) => return Err(e),
            Err(e) => return Err(invalid(e.to_string())),
        };
        let parent = match (&account.parent, &account.ldap_username) {
            (None, _) if let Some(openid) = &account.openid => {
                let provider = self
                    .state
                    .oidc_provider_by_issuer(&openid.provider)
                    .ok_or_else(|| {
                        invalid(format!(
                            "its OpenID Connect provider {} isn't here.",
                            openid.provider
                        ))
                    })?;
                Parent::OpenId(Box::new(OpenIdParent {
                    provider: provider.id.clone(),
                    sub: openid.sub.clone(),
                    aud: openid.aud.clone(),
                    // As a session would have them: those that exist.
                    policies: openid
                        .policies
                        .iter()
                        .filter_map(|name| self.state.policy_named(name))
                        .map(|p| p.row.id.clone())
                        .collect(),
                }))
            }
            (Some(dn), Some(username)) => {
                let dn = crate::ldap::normalize(dn).map_err(invalid)?;
                self.see_ldap_user(&dn, username, None, 0);
                Parent::Ldap {
                    dn,
                    username: username.clone(),
                }
            }
            (Some(name), None) => Parent::User(self.user(name)?.id.clone()),
            (None, _) => Parent::Root,
        };
        let secret = Zeroizing::new(secret.to_owned());
        self.save_service_account(ServiceAccount {
            sealed: self.key.seal_secret(id.as_bytes(), secret.as_bytes()),
            secret: Arc::new(secret),
            id: id.clone(),
            parent,
            active: account.active,
            policy,
            name: account.name.clone(),
            description: account.description.clone(),
            expires_ms: account.expires_ms,
            created_ms: account.created_ms,
        });
        Ok(())
    }

    /// Deletes the service accounts of the directory user `dn`.
    pub(crate) fn remove_ldap_service_accounts_of(&mut self, dn: &str) {
        let ids: Vec<String> = self
            .state
            .service_accounts
            .values()
            .filter(|a| a.parent.ldap_dn() == Some(dn))
            .map(|a| a.id.clone())
            .collect();
        for id in ids {
            self.state.service_accounts.remove(&id);
            self.write(IamWrite::DeleteServiceAccount(id));
        }
    }

    /// Deletes the service accounts of the OpenID Connect users of the provider with
    /// unique id `provider`.
    pub(crate) fn remove_openid_service_accounts_of(&mut self, provider: &str) {
        let ids: Vec<String> = self
            .state
            .service_accounts
            .values()
            .filter(|a| a.parent.openid_provider() == Some(provider))
            .map(|a| a.id.clone())
            .collect();
        for id in ids {
            self.state.service_accounts.remove(&id);
            self.write(IamWrite::DeleteServiceAccount(id));
        }
    }

    /// Deletes the service accounts of the user with unique id `user`.
    pub(crate) fn remove_service_accounts_of(&mut self, user: &str) {
        let ids: Vec<String> = self
            .state
            .service_accounts
            .values()
            .filter(|a| a.parent.user() == Some(user))
            .map(|a| a.id.clone())
            .collect();
        for id in ids {
            self.state.service_accounts.remove(&id);
            self.write(IamWrite::DeleteServiceAccount(id));
        }
    }
}

/// `MinIO`'s service accounts.
impl Iam {
    /// Makes a service account for `parent`, a user's name or the root user's access
    /// key (`add-service-account`).
    pub fn minio_add_service_account(
        &self,
        parent: &str,
        new: NewServiceAccount<'_>,
    ) -> Result<AddedServiceAccount> {
        self.change(|d| {
            let id = d.parent(parent)?;
            d.add_service_account(id, parent, new)
        })
    }

    /// Makes a service account for a directory user the caller found in the directory
    /// (`idp/ldap/add-service-account`): it has the policies mapped to the user's DN and
    /// its groups', which the directory is asked about every few minutes, and it's
    /// removed when the directory no longer has the user.
    pub fn minio_add_ldap_service_account(
        &self,
        user: &LdapUser<'_>,
        new: NewServiceAccount<'_>,
    ) -> Result<AddedServiceAccount> {
        self.change(|d| {
            d.see_ldap_user(user.dn, user.username, Some(user.groups), 0);
            d.add_service_account(
                Parent::Ldap {
                    dn: user.dn.to_owned(),
                    username: user.username.to_owned(),
                },
                user.username,
                new,
            )
        })
    }

    /// Makes a service account for the OpenID Connect user whose session `identity` is
    /// (`add-service-account` signed with a web identity's session): it keeps what the
    /// session knew of the user, its provider, `sub` and client, and has the managed
    /// policies the session was issued with, as `MinIO` copies the session's claims.
    /// It's removed with its provider.
    ///
    /// # Errors
    ///
    /// `identity` isn't such a session, or what [`Self::minio_add_service_account`]
    /// refuses.
    pub fn minio_add_openid_service_account(
        &self,
        identity: &Identity,
        new: NewServiceAccount<'_>,
    ) -> Result<AddedServiceAccount> {
        let session = identity.session();
        let (Some(name), Some(parent)) = (
            session.and_then(crate::Session::openid_user),
            session.and_then(crate::Session::openid_parent),
        ) else {
            return Err(MinioError::NoSuchUser);
        };
        self.change(|d| {
            if !d.state.oidc_providers.contains_key(&parent.provider) {
                return Err(MinioError::NoSuchUser);
            }
            d.add_service_account(Parent::OpenId(Box::new(parent)), name, new)
        })
    }

    /// Changes a service account (`update-service-account`).
    pub fn minio_update_service_account(
        &self,
        access_key: &str,
        change: ServiceAccountChange<'_>,
    ) -> Result<()> {
        self.change(|d| d.update_service_account(access_key, change))
    }

    /// A service account (`info-service-account`).
    pub fn minio_service_account(&self, access_key: &str) -> Result<MinioServiceAccount> {
        let root = self.root_access_key();
        self.view(|s| {
            let account = s
                .service_accounts
                .get(access_key)
                .ok_or(MinioError::NoSuchServiceAccount)?;
            Ok(describe(s, root.as_deref(), account))
        })
    }

    /// The service accounts of `parent`, a user's name, the root user's access key, a
    /// directory user's DN written in one form, or `MinIO`'s name for an OpenID Connect
    /// user, oldest first; none for a name that's none of them (`list-service-accounts`).
    #[must_use]
    pub fn minio_service_accounts(&self, parent: &str) -> Vec<MinioServiceAccount> {
        let root = self.root_access_key();
        self.view(|s| {
            let user = s.user_named(parent).ok().map(|u| u.id.as_str());
            let is_parent = |a: &ServiceAccount| match &a.parent {
                Parent::Root => root.as_deref() == Some(parent),
                Parent::User(id) => user == Some(id.as_str()),
                Parent::Ldap { dn, .. } => dn.eq_ignore_ascii_case(parent),
                Parent::OpenId(openid) => s
                    .oidc_providers
                    .get(&openid.provider)
                    .is_some_and(|p| openid.name(&p.url) == parent),
            };
            let mut accounts: Vec<MinioServiceAccount> = s
                .service_accounts
                .values()
                .filter(|a| is_parent(a))
                .map(|a| describe(s, root.as_deref(), a))
                .collect();
            accounts
                .sort_by(|a, b| (a.created_ms, &a.access_key).cmp(&(b.created_ms, &b.access_key)));
            accounts
        })
    }

    /// The service accounts of OpenID Connect users whose provider exists, by user
    /// (`MinIO`'s name for it) and oldest first.
    #[must_use]
    pub fn minio_openid_service_accounts(&self) -> Vec<OpenIdServiceAccount> {
        let root = self.root_access_key();
        self.view(|s| {
            let mut accounts: Vec<OpenIdServiceAccount> = s
                .service_accounts
                .values()
                .filter_map(|a| {
                    let Parent::OpenId(openid) = &a.parent else {
                        return None;
                    };
                    let provider = s.oidc_providers.get(&openid.provider)?;
                    Some(OpenIdServiceAccount {
                        user: openid.name(&provider.url),
                        sub: openid.sub.clone(),
                        account: describe(s, root.as_deref(), a),
                    })
                })
                .collect();
            accounts.sort_by(|a, b| {
                (&a.user, a.account.created_ms, &a.account.access_key).cmp(&(
                    &b.user,
                    b.account.created_ms,
                    &b.account.access_key,
                ))
            });
            accounts
        })
    }

    /// Deletes a service account (`delete-service-account`).
    pub fn minio_remove_service_account(&self, access_key: &str) -> Result<()> {
        self.change(|d| {
            if d.state.service_accounts.remove(access_key).is_none() {
                return Err(MinioError::NoSuchServiceAccount);
            }
            d.write(IamWrite::DeleteServiceAccount(access_key.to_owned()));
            Ok(())
        })
    }

    /// The `MinIO` user a caller acts as, whose service accounts it may manage itself: a
    /// user's name (for its keys, its service accounts and `MinIO`'s `AssumeRole`
    /// sessions), the root user's access key (for the root user and its service
    /// accounts), a directory user's DN (for its LDAP sessions and service accounts), or
    /// `MinIO`'s name for an OpenID Connect user (for its web identity sessions without
    /// an IAM role and its service accounts). `None` for other sessions.
    #[must_use]
    pub fn minio_parent(&self, identity: &Identity) -> Option<String> {
        let root = self.root_access_key();
        if identity.is_root() {
            return root;
        }
        if let Some(user) = identity.session().and_then(crate::Session::ldap_user) {
            return Some(user.dn.to_owned());
        }
        if let Some(user) = identity.session().and_then(crate::Session::openid_user) {
            return Some(user.to_owned());
        }
        let kind = identity.session().map(crate::Session::kind);
        if !matches!(kind, None | Some(SessionKind::User | SessionKind::Service)) {
            return None;
        }
        match identity.entity() {
            Some((_, id)) => self.view(|s| s.users.get(id).map(|u| u.name.clone())),
            None if kind == Some(SessionKind::Service) => root,
            None => None,
        }
    }
}
