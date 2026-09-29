//! IAM's tables in the system database. `teifs-iam` owns the rules (names, limits,
//! conflicts) and keeps the whole state in memory; here it's only loaded and changed,
//! each change in one transaction.
//!
//! Ids are globally unique with a type prefix, so inline policies and attachments name
//! their owner (a user or a group) by id alone.

use rusqlite::{Transaction, params};

use crate::{Result, System};

pub(crate) const MIGRATION: &str = "
    CREATE TABLE iam_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE iam_policies (
        id              TEXT    PRIMARY KEY,
        name            TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        path            TEXT    NOT NULL,
        description     TEXT    NOT NULL,
        default_version INTEGER NOT NULL,
        latest_version  INTEGER NOT NULL,
        created_ms      INTEGER NOT NULL,
        updated_ms      INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE iam_policy_tags (
        policy_id TEXT NOT NULL REFERENCES iam_policies (id) ON DELETE CASCADE,
        key       TEXT NOT NULL,
        value     TEXT NOT NULL,
        PRIMARY KEY (policy_id, key)
    ) WITHOUT ROWID;
    CREATE TABLE iam_policy_versions (
        policy_id  TEXT    NOT NULL REFERENCES iam_policies (id) ON DELETE CASCADE,
        version    INTEGER NOT NULL,
        document   TEXT    NOT NULL,
        created_ms INTEGER NOT NULL,
        PRIMARY KEY (policy_id, version)
    ) WITHOUT ROWID;
    CREATE TABLE iam_users (
        id         TEXT    PRIMARY KEY,
        name       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        path       TEXT    NOT NULL,
        created_ms INTEGER NOT NULL,
        boundary   TEXT    REFERENCES iam_policies (id)
    ) WITHOUT ROWID;
    CREATE TABLE iam_user_tags (
        user_id TEXT NOT NULL REFERENCES iam_users (id) ON DELETE CASCADE,
        key     TEXT NOT NULL COLLATE NOCASE,
        value   TEXT NOT NULL,
        PRIMARY KEY (user_id, key)
    ) WITHOUT ROWID;
    CREATE TABLE iam_groups (
        id         TEXT    PRIMARY KEY,
        name       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        path       TEXT    NOT NULL,
        created_ms INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE iam_members (
        group_id TEXT NOT NULL REFERENCES iam_groups (id),
        user_id  TEXT NOT NULL REFERENCES iam_users (id),
        PRIMARY KEY (group_id, user_id)
    ) WITHOUT ROWID;
    CREATE TABLE iam_inline (
        owner    TEXT NOT NULL,
        name     TEXT NOT NULL,
        document TEXT NOT NULL,
        PRIMARY KEY (owner, name)
    ) WITHOUT ROWID;
    CREATE TABLE iam_attached (
        owner     TEXT NOT NULL,
        policy_id TEXT NOT NULL REFERENCES iam_policies (id),
        PRIMARY KEY (owner, policy_id)
    ) WITHOUT ROWID;
    CREATE TABLE iam_access_keys (
        id         TEXT    PRIMARY KEY,
        user_id    TEXT    NOT NULL REFERENCES iam_users (id),
        secret     BLOB    NOT NULL,
        active     INTEGER NOT NULL,
        created_ms INTEGER NOT NULL
    ) WITHOUT ROWID;";

/// Roles: migration 5 (inline policies and attachments name them by id, like users).
pub(crate) const ROLES_MIGRATION: &str = "
    CREATE TABLE iam_roles (
        id          TEXT    PRIMARY KEY,
        name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        path        TEXT    NOT NULL,
        description TEXT    NOT NULL,
        trust       TEXT    NOT NULL,
        principals  TEXT    NOT NULL,
        max_session INTEGER NOT NULL,
        created_ms  INTEGER NOT NULL,
        boundary    TEXT    REFERENCES iam_policies (id)
    ) WITHOUT ROWID;
    CREATE TABLE iam_role_tags (
        role_id TEXT NOT NULL REFERENCES iam_roles (id) ON DELETE CASCADE,
        key     TEXT NOT NULL COLLATE NOCASE,
        value   TEXT NOT NULL,
        PRIMARY KEY (role_id, key)
    ) WITHOUT ROWID;";

/// OpenID Connect providers: migration 6. `name` is the URL without its scheme, the
/// last part of the provider's ARN.
pub(crate) const OIDC_MIGRATION: &str = "
    CREATE TABLE iam_oidc_providers (
        id          TEXT    PRIMARY KEY,
        name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        url         TEXT    NOT NULL,
        client_ids  TEXT    NOT NULL,
        thumbprints TEXT    NOT NULL,
        created_ms  INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE iam_oidc_provider_tags (
        provider_id TEXT NOT NULL REFERENCES iam_oidc_providers (id) ON DELETE CASCADE,
        key         TEXT NOT NULL COLLATE NOCASE,
        value       TEXT NOT NULL,
        PRIMARY KEY (provider_id, key)
    ) WITHOUT ROWID;";

/// A user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    /// Its unique id.
    pub id: String,
    /// Its name, unique without case.
    pub name: String,
    /// Its path (`/` or `/…/`).
    pub path: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// The id of the managed policy that is its permissions boundary.
    pub boundary: Option<String>,
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRow {
    /// Its unique id.
    pub id: String,
    /// Its name, unique without case.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its description.
    pub description: String,
    /// Its trust policy (who may assume it), as given.
    pub trust: String,
    /// The users and roles its trust policy names, bound to their unique ids when it was
    /// set (JSON, which `teifs-iam` owns): one deleted and made again isn't trusted.
    pub principals: String,
    /// The longest session it allows, in seconds.
    pub max_session: u32,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// The id of the managed policy that is its permissions boundary.
    pub boundary: Option<String>,
}

/// An OpenID Connect identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProviderRow {
    /// Its unique id.
    pub id: String,
    /// Its URL without the scheme (`idp.example.com/realms/a`), unique without case.
    pub name: String,
    /// Its URL, as given: the issuer its tokens name.
    pub url: String,
    /// The audiences it's trusted for (JSON, which `teifs-iam` owns).
    pub client_ids: String,
    /// The thumbprints of the certificates it's pinned to (JSON).
    pub thumbprints: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    /// Its unique id.
    pub id: String,
    /// Its name, unique without case.
    pub name: String,
    /// Its path.
    pub path: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A customer-managed policy (its documents are [`PolicyVersionRow`]s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRow {
    /// Its unique id.
    pub id: String,
    /// Its name, unique without case.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its description (set once).
    pub description: String,
    /// The version in effect.
    pub default_version: u32,
    /// The highest version ever created: numbers aren't reused after a delete.
    pub latest_version: u32,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// When its default version last changed.
    pub updated_ms: i64,
}

/// One version of a managed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersionRow {
    /// The policy's id.
    pub policy_id: String,
    /// The version number (`v1` is 1).
    pub version: u32,
    /// The JSON document, as given.
    pub document: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// An inline policy of a user or a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineRow {
    /// The id of the user or group it's in.
    pub owner: String,
    /// Its name, unique within the owner.
    pub name: String,
    /// The JSON document, as given.
    pub document: String,
}

/// An access key. The secret is sealed by `teifs-iam`; this crate never sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessKeyRow {
    /// The access key id.
    pub id: String,
    /// The id of the user it belongs to.
    pub user_id: String,
    /// The sealed secret key.
    pub secret: Vec<u8>,
    /// Whether requests signed with it are accepted.
    pub active: bool,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

impl std::fmt::Debug for AccessKeyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessKeyRow")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("active", &self.active)
            .field("created_ms", &self.created_ms)
            .finish_non_exhaustive()
    }
}

/// Everything IAM keeps, as loaded at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IamRows {
    /// Settings: the account id, the sealed IAM key.
    pub meta: Vec<(String, String)>,
    /// Users.
    pub users: Vec<UserRow>,
    /// Users' tags: (user id, key, value).
    pub user_tags: Vec<(String, String, String)>,
    /// Groups.
    pub groups: Vec<GroupRow>,
    /// Group memberships: (group id, user id).
    pub members: Vec<(String, String)>,
    /// Roles.
    pub roles: Vec<RoleRow>,
    /// Roles' tags: (role id, key, value).
    pub role_tags: Vec<(String, String, String)>,
    /// OpenID Connect providers.
    pub oidc_providers: Vec<OidcProviderRow>,
    /// Their tags: (provider id, key, value).
    pub oidc_provider_tags: Vec<(String, String, String)>,
    /// Managed policies.
    pub policies: Vec<PolicyRow>,
    /// Their tags: (policy id, key, value); keys are case sensitive.
    pub policy_tags: Vec<(String, String, String)>,
    /// Their versions.
    pub versions: Vec<PolicyVersionRow>,
    /// Inline policies.
    pub inline: Vec<InlineRow>,
    /// Attachments: (owner id, policy id).
    pub attached: Vec<(String, String)>,
    /// Access keys.
    pub keys: Vec<AccessKeyRow>,
}

/// One change to IAM's tables. `Put…` inserts or updates in place (never deletes and
/// re-inserts, which would drop what hangs off the row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IamWrite {
    /// Sets a setting.
    SetMeta(String, String),
    /// Adds or updates a user.
    PutUser(UserRow),
    /// Deletes a user (and its tags).
    DeleteUser(String),
    /// Sets a user's tag (keys compare without case; the given case is kept).
    PutUserTag(String, String, String),
    /// Removes a user's tag.
    DeleteUserTag(String, String),
    /// Adds or updates a group.
    PutGroup(GroupRow),
    /// Deletes a group.
    DeleteGroup(String),
    /// Adds a user to a group: (group id, user id).
    AddMember(String, String),
    /// Removes a user from a group.
    RemoveMember(String, String),
    /// Adds or updates a role.
    PutRole(RoleRow),
    /// Deletes a role (and its tags).
    DeleteRole(String),
    /// Sets a role's tag (keys compare without case; the given case is kept).
    PutRoleTag(String, String, String),
    /// Removes a role's tag.
    DeleteRoleTag(String, String),
    /// Adds or updates an OpenID Connect provider.
    PutOidcProvider(OidcProviderRow),
    /// Deletes an OpenID Connect provider (and its tags).
    DeleteOidcProvider(String),
    /// Sets a provider's tag (keys compare without case; the given case is kept).
    PutOidcProviderTag(String, String, String),
    /// Removes a provider's tag.
    DeleteOidcProviderTag(String, String),
    /// Adds or updates a managed policy.
    PutPolicy(PolicyRow),
    /// Deletes a managed policy and its versions.
    DeletePolicy(String),
    /// Sets a managed policy's tag (keys are case sensitive).
    PutPolicyTag(String, String, String),
    /// Removes a managed policy's tag.
    DeletePolicyTag(String, String),
    /// Adds a policy version.
    PutVersion(PolicyVersionRow),
    /// Deletes a policy version: (policy id, version).
    DeleteVersion(String, u32),
    /// Adds or replaces an inline policy.
    PutInline(InlineRow),
    /// Deletes an inline policy: (owner id, name).
    DeleteInline(String, String),
    /// Attaches a managed policy: (owner id, policy id).
    Attach(String, String),
    /// Detaches a managed policy.
    Detach(String, String),
    /// Adds or updates an access key.
    PutKey(AccessKeyRow),
    /// Deletes an access key.
    DeleteKey(String),
}

impl System {
    /// Everything IAM keeps.
    #[allow(clippy::too_many_lines, reason = "one query per table")]
    pub fn iam_rows(&self) -> Result<IamRows> {
        let conn = &self.conn;
        let all = |sql: &str| conn.prepare(sql);
        Ok(IamRows {
            meta: all("SELECT key, value FROM iam_meta ORDER BY key")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?,
            users: all("SELECT id, name, path, created_ms, boundary FROM iam_users ORDER BY id")?
                .query_map([], |r| {
                    Ok(UserRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        path: r.get(2)?,
                        created_ms: r.get(3)?,
                        boundary: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?,
            user_tags: tag_rows(
                conn,
                "SELECT user_id, key, value FROM iam_user_tags ORDER BY user_id, key",
            )?,
            groups: all("SELECT id, name, path, created_ms FROM iam_groups ORDER BY id")?
                .query_map([], |r| {
                    Ok(GroupRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        path: r.get(2)?,
                        created_ms: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?,
            members: all("SELECT group_id, user_id FROM iam_members ORDER BY group_id, user_id")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?,
            roles: roles(conn)?,
            role_tags: tag_rows(
                conn,
                "SELECT role_id, key, value FROM iam_role_tags ORDER BY role_id, key",
            )?,
            oidc_providers: oidc_providers(conn)?,
            oidc_provider_tags: tag_rows(
                conn,
                "SELECT provider_id, key, value FROM iam_oidc_provider_tags
                 ORDER BY provider_id, key",
            )?,
            policies: all(
                "SELECT id, name, path, description, default_version, latest_version, created_ms,
                   updated_ms
                 FROM iam_policies ORDER BY id",
            )?
            .query_map([], |r| {
                Ok(PolicyRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    path: r.get(2)?,
                    description: r.get(3)?,
                    default_version: r.get(4)?,
                    latest_version: r.get(5)?,
                    created_ms: r.get(6)?,
                    updated_ms: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?,
            policy_tags: tag_rows(
                conn,
                "SELECT policy_id, key, value FROM iam_policy_tags ORDER BY policy_id, key",
            )?,
            versions: all(
                "SELECT policy_id, version, document, created_ms FROM iam_policy_versions
                 ORDER BY policy_id, version",
            )?
            .query_map([], |r| {
                Ok(PolicyVersionRow {
                    policy_id: r.get(0)?,
                    version: r.get(1)?,
                    document: r.get(2)?,
                    created_ms: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?,
            inline: all("SELECT owner, name, document FROM iam_inline ORDER BY owner, name")?
                .query_map([], |r| {
                    Ok(InlineRow {
                        owner: r.get(0)?,
                        name: r.get(1)?,
                        document: r.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?,
            attached: all("SELECT owner, policy_id FROM iam_attached ORDER BY owner, policy_id")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?,
            keys: all(
                "SELECT id, user_id, secret, active, created_ms FROM iam_access_keys ORDER BY id",
            )?
            .query_map([], |r| {
                Ok(AccessKeyRow {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    secret: r.get(2)?,
                    active: r.get(3)?,
                    created_ms: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?,
        })
    }

    /// Applies changes in one transaction: all of them, or none.
    pub fn iam_apply(&mut self, writes: &[IamWrite]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for write in writes {
            apply(&tx, write)?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// (owner id, key, value) rows.
fn tag_rows(conn: &rusqlite::Connection, sql: &str) -> Result<Vec<(String, String, String)>> {
    Ok(conn
        .prepare(sql)?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

fn oidc_providers(conn: &rusqlite::Connection) -> Result<Vec<OidcProviderRow>> {
    Ok(conn
        .prepare(
            "SELECT id, name, url, client_ids, thumbprints, created_ms
             FROM iam_oidc_providers ORDER BY id",
        )?
        .query_map([], |r| {
            Ok(OidcProviderRow {
                id: r.get(0)?,
                name: r.get(1)?,
                url: r.get(2)?,
                client_ids: r.get(3)?,
                thumbprints: r.get(4)?,
                created_ms: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
}

fn roles(conn: &rusqlite::Connection) -> Result<Vec<RoleRow>> {
    Ok(conn
        .prepare(
            "SELECT id, name, path, description, trust, principals, max_session, created_ms,
               boundary
             FROM iam_roles ORDER BY id",
        )?
        .query_map([], |r| {
            Ok(RoleRow {
                id: r.get(0)?,
                name: r.get(1)?,
                path: r.get(2)?,
                description: r.get(3)?,
                trust: r.get(4)?,
                principals: r.get(5)?,
                max_session: r.get(6)?,
                created_ms: r.get(7)?,
                boundary: r.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
}

#[allow(clippy::too_many_lines, reason = "one statement per kind of write")]
fn apply(tx: &Transaction<'_>, write: &IamWrite) -> Result<()> {
    let run = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Result<()> {
        tx.prepare_cached(sql)?.execute(params)?;
        Ok(())
    };
    match write {
        IamWrite::SetMeta(key, value) => run(
            "INSERT INTO iam_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        ),
        IamWrite::PutUser(u) => run(
            "INSERT INTO iam_users (id, name, path, created_ms, boundary) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, path = excluded.path,
               boundary = excluded.boundary",
            params![u.id, u.name, u.path, u.created_ms, u.boundary],
        ),
        IamWrite::DeleteUser(id) => run("DELETE FROM iam_users WHERE id = ?1", params![id]),
        IamWrite::PutUserTag(user, key, value) => run(
            "INSERT INTO iam_user_tags (user_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (user_id, key) DO UPDATE SET key = excluded.key, value = excluded.value",
            params![user, key, value],
        ),
        IamWrite::DeleteUserTag(user, key) => run(
            "DELETE FROM iam_user_tags WHERE user_id = ?1 AND key = ?2",
            params![user, key],
        ),
        IamWrite::PutGroup(g) => run(
            "INSERT INTO iam_groups (id, name, path, created_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, path = excluded.path",
            params![g.id, g.name, g.path, g.created_ms],
        ),
        IamWrite::DeleteGroup(id) => run("DELETE FROM iam_groups WHERE id = ?1", params![id]),
        IamWrite::AddMember(group, user) => run(
            "INSERT OR IGNORE INTO iam_members (group_id, user_id) VALUES (?1, ?2)",
            params![group, user],
        ),
        IamWrite::RemoveMember(group, user) => run(
            "DELETE FROM iam_members WHERE group_id = ?1 AND user_id = ?2",
            params![group, user],
        ),
        IamWrite::PutRole(r) => run(
            "INSERT INTO iam_roles
               (id, name, path, description, trust, principals, max_session, created_ms,
                boundary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (id) DO UPDATE SET description = excluded.description,
               trust = excluded.trust, principals = excluded.principals,
               max_session = excluded.max_session, boundary = excluded.boundary",
            params![
                r.id,
                r.name,
                r.path,
                r.description,
                r.trust,
                r.principals,
                r.max_session,
                r.created_ms,
                r.boundary
            ],
        ),
        IamWrite::DeleteRole(id) => run("DELETE FROM iam_roles WHERE id = ?1", params![id]),
        IamWrite::PutRoleTag(role, key, value) => run(
            "INSERT INTO iam_role_tags (role_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (role_id, key) DO UPDATE SET key = excluded.key, value = excluded.value",
            params![role, key, value],
        ),
        IamWrite::DeleteRoleTag(role, key) => run(
            "DELETE FROM iam_role_tags WHERE role_id = ?1 AND key = ?2",
            params![role, key],
        ),
        IamWrite::PutOidcProvider(p) => run(
            "INSERT INTO iam_oidc_providers (id, name, url, client_ids, thumbprints, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (id) DO UPDATE SET client_ids = excluded.client_ids,
               thumbprints = excluded.thumbprints",
            params![p.id, p.name, p.url, p.client_ids, p.thumbprints, p.created_ms],
        ),
        IamWrite::DeleteOidcProvider(id) => {
            run("DELETE FROM iam_oidc_providers WHERE id = ?1", params![id])
        }
        IamWrite::PutOidcProviderTag(provider, key, value) => run(
            "INSERT INTO iam_oidc_provider_tags (provider_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (provider_id, key) DO UPDATE SET key = excluded.key,
               value = excluded.value",
            params![provider, key, value],
        ),
        IamWrite::DeleteOidcProviderTag(provider, key) => run(
            "DELETE FROM iam_oidc_provider_tags WHERE provider_id = ?1 AND key = ?2",
            params![provider, key],
        ),
        IamWrite::PutPolicy(p) => run(
            "INSERT INTO iam_policies
               (id, name, path, description, default_version, latest_version, created_ms,
                updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (id) DO UPDATE SET default_version = excluded.default_version,
               latest_version = excluded.latest_version, updated_ms = excluded.updated_ms",
            params![
                p.id,
                p.name,
                p.path,
                p.description,
                p.default_version,
                p.latest_version,
                p.created_ms,
                p.updated_ms
            ],
        ),
        IamWrite::DeletePolicy(id) => run("DELETE FROM iam_policies WHERE id = ?1", params![id]),
        IamWrite::PutPolicyTag(policy, key, value) => run(
            "INSERT INTO iam_policy_tags (policy_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (policy_id, key) DO UPDATE SET value = excluded.value",
            params![policy, key, value],
        ),
        IamWrite::DeletePolicyTag(policy, key) => run(
            "DELETE FROM iam_policy_tags WHERE policy_id = ?1 AND key = ?2",
            params![policy, key],
        ),
        IamWrite::PutVersion(v) => run(
            "INSERT INTO iam_policy_versions (policy_id, version, document, created_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![v.policy_id, v.version, v.document, v.created_ms],
        ),
        IamWrite::DeleteVersion(policy, version) => run(
            "DELETE FROM iam_policy_versions WHERE policy_id = ?1 AND version = ?2",
            params![policy, version],
        ),
        IamWrite::PutInline(i) => run(
            "INSERT INTO iam_inline (owner, name, document) VALUES (?1, ?2, ?3)
             ON CONFLICT (owner, name) DO UPDATE SET document = excluded.document",
            params![i.owner, i.name, i.document],
        ),
        IamWrite::DeleteInline(owner, name) => run(
            "DELETE FROM iam_inline WHERE owner = ?1 AND name = ?2",
            params![owner, name],
        ),
        IamWrite::Attach(owner, policy) => run(
            "INSERT OR IGNORE INTO iam_attached (owner, policy_id) VALUES (?1, ?2)",
            params![owner, policy],
        ),
        IamWrite::Detach(owner, policy) => run(
            "DELETE FROM iam_attached WHERE owner = ?1 AND policy_id = ?2",
            params![owner, policy],
        ),
        IamWrite::PutKey(k) => run(
            "INSERT INTO iam_access_keys (id, user_id, secret, active, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET active = excluded.active",
            params![k.id, k.user_id, k.secret, k.active, k.created_ms],
        ),
        IamWrite::DeleteKey(id) => run("DELETE FROM iam_access_keys WHERE id = ?1", params![id]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (tempfile::TempDir, System) {
        let dir = tempfile::tempdir().unwrap();
        let system = System::open(&dir.path().join("system.db")).unwrap();
        (dir, system)
    }

    fn user(id: &str, name: &str) -> UserRow {
        UserRow {
            id: id.into(),
            name: name.into(),
            path: "/".into(),
            created_ms: 1,
            boundary: None,
        }
    }

    fn policy(id: &str) -> PolicyRow {
        PolicyRow {
            id: id.into(),
            name: format!("name-{id}"),
            path: "/".into(),
            description: String::new(),
            default_version: 1,
            latest_version: 1,
            created_ms: 1,
            updated_ms: 1,
        }
    }

    #[test]
    fn everything_round_trips() {
        let (_dir, mut system) = open();
        let key = AccessKeyRow {
            id: "TKIA1".into(),
            user_id: "U1".into(),
            secret: vec![1, 2, 3],
            active: true,
            created_ms: 5,
        };
        let writes = [
            IamWrite::SetMeta("account".into(), "123456789012".into()),
            IamWrite::PutPolicy(policy("P1")),
            IamWrite::PutVersion(PolicyVersionRow {
                policy_id: "P1".into(),
                version: 1,
                document: "{}".into(),
                created_ms: 1,
            }),
            IamWrite::PutPolicyTag("P1".into(), "Team".into(), "a".into()),
            IamWrite::PutPolicyTag("P1".into(), "team".into(), "b".into()),
            IamWrite::PutUser(UserRow {
                boundary: Some("P1".into()),
                ..user("U1", "alice")
            }),
            IamWrite::PutUserTag("U1".into(), "team".into(), "a".into()),
            IamWrite::PutGroup(GroupRow {
                id: "G1".into(),
                name: "eng".into(),
                path: "/x/".into(),
                created_ms: 2,
            }),
            IamWrite::AddMember("G1".into(), "U1".into()),
            IamWrite::AddMember("G1".into(), "U1".into()),
            IamWrite::PutInline(InlineRow {
                owner: "G1".into(),
                name: "read".into(),
                document: "{}".into(),
            }),
            IamWrite::Attach("U1".into(), "P1".into()),
            IamWrite::PutKey(key.clone()),
        ];
        system.iam_apply(&writes).unwrap();
        let rows = system.iam_rows().unwrap();
        assert_eq!(rows.meta, [("account".into(), "123456789012".into())]);
        assert_eq!(rows.users[0].boundary.as_deref(), Some("P1"));
        assert_eq!(rows.user_tags, [("U1".into(), "team".into(), "a".into())]);
        assert_eq!(rows.members, [("G1".into(), "U1".into())]);
        assert_eq!(
            rows.policy_tags.len(),
            2,
            "policy tag keys are case sensitive"
        );
        assert_eq!(rows.inline[0].owner, "G1");
        assert_eq!(rows.attached, [("U1".into(), "P1".into())]);
        assert_eq!(rows.keys, [key]);
        assert!(!format!("{:?}", rows.keys[0]).contains("secret"));
    }

    #[test]
    fn updates_keep_what_hangs_off_a_row() {
        let (_dir, mut system) = open();
        system
            .iam_apply(&[
                IamWrite::PutUser(user("U1", "alice")),
                IamWrite::PutUserTag("U1".into(), "Team".into(), "a".into()),
            ])
            .unwrap();
        system
            .iam_apply(&[
                IamWrite::PutUser(user("U1", "alicia")),
                // Tag keys compare without case; the new case wins.
                IamWrite::PutUserTag("U1".into(), "team".into(), "b".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert_eq!(rows.users[0].name, "alicia");
        assert_eq!(rows.user_tags, [("U1".into(), "team".into(), "b".into())]);
        system
            .iam_apply(&[IamWrite::DeleteUser("U1".into())])
            .unwrap();
        assert!(
            system.iam_rows().unwrap().user_tags.is_empty(),
            "tags go with the user"
        );
    }

    #[test]
    fn roles_round_trip_and_keep_their_tags_on_update() {
        let (_dir, mut system) = open();
        let role = RoleRow {
            id: "AROA1".into(),
            name: "reader".into(),
            path: "/svc/".into(),
            description: "reads".into(),
            trust: "{}".into(),
            principals: "{}".into(),
            max_session: 3600,
            created_ms: 7,
            boundary: Some("P1".into()),
        };
        system
            .iam_apply(&[
                IamWrite::PutPolicy(policy("P1")),
                IamWrite::PutRole(role.clone()),
                IamWrite::PutRoleTag("AROA1".into(), "Team".into(), "a".into()),
                IamWrite::PutInline(InlineRow {
                    owner: "AROA1".into(),
                    name: "read".into(),
                    document: "{}".into(),
                }),
                IamWrite::Attach("AROA1".into(), "P1".into()),
            ])
            .unwrap();
        let changed = RoleRow {
            description: "reads more".into(),
            trust: "{\"x\":1}".into(),
            principals: "{\"a\":\"b\"}".into(),
            max_session: 43200,
            boundary: None,
            ..role.clone()
        };
        system
            .iam_apply(&[
                IamWrite::PutRole(changed.clone()),
                IamWrite::PutRoleTag("AROA1".into(), "team".into(), "b".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert_eq!(rows.roles, [changed]);
        assert_eq!(
            rows.role_tags,
            [("AROA1".into(), "team".into(), "b".into())]
        );
        assert_eq!(rows.attached, [("AROA1".into(), "P1".into())]);
        assert!(
            system
                .iam_apply(&[IamWrite::PutRole(RoleRow {
                    id: "AROA2".into(),
                    name: "READER".into(),
                    ..role
                })])
                .is_err(),
            "role names are unique without case"
        );
        system
            .iam_apply(&[IamWrite::DeleteRole("AROA1".into())])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert!(rows.roles.is_empty() && rows.role_tags.is_empty());
    }

    #[test]
    fn oidc_providers_round_trip_and_keep_their_url() {
        let (_dir, mut system) = open();
        let provider = OidcProviderRow {
            id: "P1".into(),
            name: "idp.example.com/realms/a".into(),
            url: "https://idp.example.com/realms/a".into(),
            client_ids: r#"["app"]"#.into(),
            thumbprints: "[]".into(),
            created_ms: 7,
        };
        system
            .iam_apply(&[
                IamWrite::PutOidcProvider(provider.clone()),
                IamWrite::PutOidcProviderTag("P1".into(), "Team".into(), "a".into()),
            ])
            .unwrap();
        let changed = OidcProviderRow {
            client_ids: r#"["app","cli"]"#.into(),
            thumbprints: r#"["00"]"#.into(),
            ..provider.clone()
        };
        system
            .iam_apply(&[
                IamWrite::PutOidcProvider(OidcProviderRow {
                    // An update never moves a provider to another URL.
                    url: "https://elsewhere".into(),
                    ..changed.clone()
                }),
                IamWrite::PutOidcProviderTag("P1".into(), "team".into(), "b".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert_eq!(rows.oidc_providers, [changed]);
        assert_eq!(
            rows.oidc_provider_tags,
            [("P1".into(), "team".into(), "b".into())]
        );
        assert!(
            system
                .iam_apply(&[IamWrite::PutOidcProvider(OidcProviderRow {
                    id: "P2".into(),
                    name: "IDP.example.com/realms/a".into(),
                    ..provider
                })])
                .is_err(),
            "one provider per URL, without case"
        );
        system
            .iam_apply(&[
                IamWrite::DeleteOidcProviderTag("P1".into(), "TEAM".into()),
                IamWrite::DeleteOidcProvider("P1".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert!(rows.oidc_providers.is_empty() && rows.oidc_provider_tags.is_empty());
    }

    #[test]
    fn a_failed_change_changes_nothing() {
        let (_dir, mut system) = open();
        system
            .iam_apply(&[IamWrite::PutUser(user("U1", "alice"))])
            .unwrap();
        // Names are unique without case; the second write fails, so the first is undone.
        let err = system.iam_apply(&[
            IamWrite::PutGroup(GroupRow {
                id: "G1".into(),
                name: "g".into(),
                path: "/".into(),
                created_ms: 1,
            }),
            IamWrite::PutUser(user("U2", "ALICE")),
        ]);
        assert!(err.is_err());
        let rows = system.iam_rows().unwrap();
        assert!(rows.groups.is_empty());
        assert_eq!(rows.users.len(), 1);
        // Foreign keys back up the rules: a key needs its user, a user in use can't go.
        assert!(
            system
                .iam_apply(&[IamWrite::AddMember("G9".into(), "U1".into())])
                .is_err()
        );
        system
            .iam_apply(&[
                IamWrite::PutPolicy(policy("P1")),
                IamWrite::Attach("U1".into(), "P1".into()),
            ])
            .unwrap();
        assert!(
            system
                .iam_apply(&[IamWrite::DeletePolicy("P1".into())])
                .is_err()
        );
    }
}
