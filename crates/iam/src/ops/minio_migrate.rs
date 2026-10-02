//! `MinIO`'s IAM import (`mc admin cluster iam import`): what another server exported,
//! merged into this IAM as `MinIO` merges it. Each policy, user, group, service account
//! and mapping is one change of its own; one that can't be made is reported and the rest
//! go on, but for policies and users the import stops at the first that can't, as
//! `MinIO`'s does.

use teifs_types::admin::ExportedServiceAccount;
use zeroize::Zeroizing;

use super::{LdapEntity, MinioError, MinioUserChange, Owner};
use crate::{Draft, Iam, IamError, builtin, ldap};

type Result<T> = std::result::Result<T, MinioError>;

/// A user to import: its access key, its secret and whether it signs.
pub struct MinioImportUser {
    /// Its access key, which names it.
    pub access_key: String,
    /// Its secret key.
    pub secret: Zeroizing<String>,
    /// Whether it signs.
    pub enabled: bool,
}

impl std::fmt::Debug for MinioImportUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinioImportUser")
            .field("access_key", &self.access_key)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

/// A group to import: its members, added to those it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinioImportGroup {
    /// Its name.
    pub name: String,
    /// Its members' names.
    pub members: Vec<String>,
    /// Whether its policies count.
    pub enabled: bool,
}

/// What `mc admin cluster iam import` brings, as `MinIO`'s export holds it.
#[derive(Debug, Default)]
pub struct MinioIamImport {
    /// Policies by name: a document to make or replace, `None` to remove.
    pub policies: Vec<(String, Option<String>)>,
    /// Users.
    pub users: Vec<MinioImportUser>,
    /// Groups.
    pub groups: Vec<MinioImportGroup>,
    /// Service accounts, which replace any of the same access key.
    pub service_accounts: Vec<ExportedServiceAccount>,
    /// Users' policies, by user: exactly these.
    pub user_policies: Vec<(String, Vec<String>)>,
    /// Groups' (or LDAP groups') policies, by name or DN: exactly these.
    pub group_policies: Vec<(String, Vec<String>)>,
    /// LDAP users' policies, by DN: exactly these.
    pub sts_policies: Vec<(String, Vec<String>)>,
}

/// Entities an import added, removed or skipped, as madmin's `IAMEntities` lists them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinioIamEntities {
    /// Policies.
    pub policies: Vec<String>,
    /// Users.
    pub users: Vec<String>,
    /// Groups.
    pub groups: Vec<String>,
    /// Service accounts.
    pub service_accounts: Vec<String>,
    /// Users and their policies.
    pub user_policies: Vec<(String, Vec<String>)>,
    /// Groups and their policies.
    pub group_policies: Vec<(String, Vec<String>)>,
    /// LDAP users and their policies.
    pub sts_policies: Vec<(String, Vec<String>)>,
}

/// Entities an import couldn't make, with why, as madmin's `IAMErrEntities` lists them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinioImportFailures {
    /// Users.
    pub users: Vec<(String, String)>,
    /// Groups.
    pub groups: Vec<(String, String)>,
    /// Service accounts.
    pub service_accounts: Vec<(String, String)>,
    /// Users' policies.
    pub user_policies: Vec<(String, Vec<String>, String)>,
    /// Groups' policies.
    pub group_policies: Vec<(String, Vec<String>, String)>,
    /// LDAP users' policies.
    pub sts_policies: Vec<(String, Vec<String>, String)>,
}

/// What an import did, as madmin's `ImportIAMResult`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinioImportResult {
    /// Left out: policies the same as the built-in one of their name.
    pub skipped: MinioIamEntities,
    /// Removed: policies imported empty.
    pub removed: MinioIamEntities,
    /// Made or changed.
    pub added: MinioIamEntities,
    /// Not made.
    pub failed: MinioImportFailures,
}

impl Iam {
    /// Merges what another server exported into this IAM (`MinIO`'s `import-iam`).
    ///
    /// # Errors
    ///
    /// The first policy that can't be made or removed, or user that can't be: one named
    /// as the root user or a service account, or with a name `MinIO` refuses.
    pub fn minio_import(&self, import: &MinioIamImport) -> Result<MinioImportResult> {
        let mut result = MinioImportResult::default();
        for (name, document) in &import.policies {
            match document {
                None => {
                    self.change(|d| d.minio_remove_policy(name))?;
                    result.removed.policies.push(name.clone());
                }
                Some(document) if is_builtin(name, document) => {
                    result.skipped.policies.push(name.clone());
                }
                Some(document) => {
                    self.change(|d| d.minio_put_policy(name, document, true))?;
                    result.added.policies.push(name.clone());
                }
            }
        }
        for user in &import.users {
            if self.root_access_key().as_deref() == Some(user.access_key.as_str()) {
                return Err(MinioError::RootCredentials);
            }
            if self.view(|s| s.service_accounts.contains_key(&user.access_key)) {
                return Err(MinioError::InvalidArgument(format!(
                    "{} is a service account's access key.",
                    user.access_key
                )));
            }
            if user.access_key.trim() != user.access_key {
                return Err(MinioError::InvalidArgument(format!(
                    "The access key {:?} starts or ends with a space.",
                    user.access_key
                )));
            }
            let change = MinioUserChange {
                secret: Some(user.secret.as_str()),
                enabled: Some(user.enabled),
                policies: None,
            };
            match self.minio_set_user(&user.access_key, change) {
                Ok(()) => result.added.users.push(user.access_key.clone()),
                Err(e) => result
                    .failed
                    .users
                    .push((user.access_key.clone(), e.to_string())),
            }
        }
        for group in &import.groups {
            let made = self.change(|d| {
                d.minio_update_group(&group.name, &group.members, false, Some(group.enabled))
            });
            match made {
                Ok(()) => result.added.groups.push(group.name.clone()),
                Err(e) => result
                    .failed
                    .groups
                    .push((group.name.clone(), e.to_string())),
            }
        }
        for account in &import.service_accounts {
            let made = self.change(|d| {
                if d.state.service_accounts.remove(&account.id).is_some() {
                    d.write(teifs_meta::IamWrite::DeleteServiceAccount(
                        account.id.clone(),
                    ));
                }
                d.import_service_account(account).map_err(MinioError::from)
            });
            match made {
                Ok(()) => result.added.service_accounts.push(account.id.clone()),
                Err(e) => result
                    .failed
                    .service_accounts
                    .push((account.id.clone(), e.to_string())),
            }
        }
        self.import_mappings(import, &mut result);
        Ok(result)
    }

    /// Sets the users', groups' and LDAP users' policies, as many as can be.
    fn import_mappings(&self, import: &MinioIamImport, result: &mut MinioImportResult) {
        for (user, policies) in &import.user_policies {
            let set = self.change(|d| d.replace_policies(Owner::User(user), policies));
            sort(
                set,
                (user, policies),
                &mut result.added.user_policies,
                &mut result.failed.user_policies,
            );
        }
        for (group, policies) in &import.group_policies {
            let set = self.change(|d| {
                if ldap::is_dn(group) {
                    d.replace_ldap_policies(group, LdapEntity::Group, policies)
                } else {
                    d.replace_policies(Owner::Group(group), policies)
                }
            });
            sort(
                set,
                (group, policies),
                &mut result.added.group_policies,
                &mut result.failed.group_policies,
            );
        }
        for (user, policies) in &import.sts_policies {
            let set = self.change(|d| {
                if !ldap::is_dn(user) {
                    return Err(MinioError::InvalidArgument(format!(
                        "{user} isn't an LDAP user's DN."
                    )));
                }
                d.replace_ldap_policies(user, LdapEntity::User, policies)
            });
            sort(
                set,
                (user, policies),
                &mut result.added.sts_policies,
                &mut result.failed.sts_policies,
            );
        }
    }
}

/// Lists a mapping as added or failed.
fn sort(
    set: Result<()>,
    (name, policies): (&String, &Vec<String>),
    added: &mut Vec<(String, Vec<String>)>,
    failed: &mut Vec<(String, Vec<String>, String)>,
) {
    match set {
        Ok(()) => added.push((name.clone(), policies.clone())),
        Err(e) => failed.push((name.clone(), policies.clone(), e.to_string())),
    }
}

/// Whether `document` is the built-in policy `name`'s, as `MinIO` exports its canned
/// policies with the rest.
fn is_builtin(name: &str, document: &str) -> bool {
    let parse = |text: &str| serde_json::from_str::<serde_json::Value>(text).ok();
    builtin::BUILTINS
        .iter()
        .find(|b| b.name.eq_ignore_ascii_case(name))
        .is_some_and(|b| parse(b.document).is_some_and(|d| Some(d) == parse(document)))
}

impl Draft<'_> {
    /// Maps exactly `policies` (by name) to an LDAP user or group.
    pub(super) fn replace_ldap_policies(
        &mut self,
        dn: &str,
        entity: LdapEntity,
        policies: &[String],
    ) -> Result<()> {
        let dn = ldap::normalize(dn).map_err(IamError::InvalidInput)?;
        let had: Vec<String> = self
            .state
            .ldap_policies
            .get(&dn)
            .map(|m| {
                m.policies
                    .iter()
                    .filter_map(|id| self.state.policies.get(id))
                    .map(|p| self.state.policy_arn(p))
                    .collect()
            })
            .unwrap_or_default();
        if !had.is_empty() {
            self.map_ldap_policies(&dn, entity, &had, false)?;
        }
        if !policies.is_empty() {
            self.map_ldap_policies(&dn, entity, policies, true)?;
        }
        Ok(())
    }
}
