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
    Draft, Iam, IamError, Identity, SessionKind, builtin, ids, rules,
    state::{Document, ServiceAccount, State},
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

/// The parent's name: a user's, or the root user's access key.
fn parent_name(state: &State, root: Option<&str>, account: &ServiceAccount) -> String {
    match &account.parent {
        Some(id) => state.users.get(id).map(|u| u.name.clone()),
        None => root.map(str::to_owned),
    }
    .unwrap_or_default()
}

fn describe(state: &State, root: Option<&str>, account: &ServiceAccount) -> MinioServiceAccount {
    let policy = match (&account.policy, &account.parent) {
        (Some(policy), _) => policy.text.to_string(),
        (None, Some(id)) => state.users.get(id).map_or_else(
            || merged([]),
            |user| {
                let groups = state.groups_of(&user.id).filter(|g| !g.disabled);
                merged(
                    documents(state, &user.inline, &user.attached)
                        .chain(groups.flat_map(|g| documents(state, &g.inline, &g.attached))),
                )
            },
        ),
        (None, None) => merged(
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
    /// The unique id of the user named `parent`, or `None` for the root user's key.
    fn parent(&self, parent: &str) -> Result<Option<String>> {
        if self.root == Some(parent) {
            return Ok(None);
        }
        Ok(Some(user_named(&self.state, parent)?.id.clone()))
    }

    fn save_service_account(&mut self, account: ServiceAccount) {
        self.write(IamWrite::PutServiceAccount(account.row()));
        self.state
            .service_accounts
            .insert(account.id.clone(), Arc::new(account));
    }

    fn add_service_account(
        &mut self,
        parent: &str,
        new: NewServiceAccount<'_>,
    ) -> Result<AddedServiceAccount> {
        check_name(new.name)?;
        check_description(new.description)?;
        let expires_ms = check_expiry(new.expires_ms, self.now)?;
        let policy = new.policy.map(parse_policy).transpose()?;
        let parent_id = self.parent(parent)?;
        let (id, secret) = match (new.access_key, new.secret) {
            (Some(id), Some(secret)) => {
                rules::access_key_id(id).map_err(MinioError::InvalidAccessKey)?;
                rules::secret_key(secret).map_err(MinioError::InvalidSecretKey)?;
                if self.root == Some(id) {
                    return Err(MinioError::RootCredentials);
                }
                if id.eq_ignore_ascii_case(parent) {
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
            parent: parent_id,
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
        let parent = match &account.parent {
            Some(name) => Some(self.user(name)?.id.clone()),
            None => None,
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

    /// Deletes the service accounts of the user with unique id `user`.
    pub(crate) fn remove_service_accounts_of(&mut self, user: &str) {
        let ids: Vec<String> = self
            .state
            .service_accounts
            .values()
            .filter(|a| a.parent.as_deref() == Some(user))
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
        self.change(|d| d.add_service_account(parent, new))
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

    /// The service accounts of `parent`, a user's name or the root user's access key,
    /// oldest first; none for a name that's neither (`list-service-accounts`).
    #[must_use]
    pub fn minio_service_accounts(&self, parent: &str) -> Vec<MinioServiceAccount> {
        let root = self.root_access_key();
        self.view(|s| {
            let parent = if root.as_deref() == Some(parent) {
                None
            } else if let Ok(user) = s.user_named(parent) {
                Some(user.id.as_str())
            } else {
                return Vec::new();
            };
            let mut accounts: Vec<MinioServiceAccount> = s
                .service_accounts
                .values()
                .filter(|a| a.parent.as_deref() == parent)
                .map(|a| describe(s, root.as_deref(), a))
                .collect();
            accounts
                .sort_by(|a, b| (a.created_ms, &a.access_key).cmp(&(b.created_ms, &b.access_key)));
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
    /// sessions) or the root user's access key (for the root user and its service
    /// accounts). `None` for other sessions.
    #[must_use]
    pub fn minio_parent(&self, identity: &Identity) -> Option<String> {
        let root = self.root_access_key();
        if identity.is_root() {
            return root;
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
