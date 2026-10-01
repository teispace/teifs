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

/// SAML providers: migration 9. Their private keys (which decrypt assertions) are
/// sealed under IAM's key.
pub(crate) const SAML_MIGRATION: &str = "
    CREATE TABLE iam_saml_providers (
        id             TEXT    PRIMARY KEY,
        name           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        uuid           TEXT    NOT NULL,
        metadata       TEXT    NOT NULL,
        encryption     TEXT    NOT NULL,
        created_ms     INTEGER NOT NULL,
        valid_until_ms INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE iam_saml_provider_keys (
        provider_id TEXT    NOT NULL REFERENCES iam_saml_providers (id) ON DELETE CASCADE,
        key_id      TEXT    NOT NULL,
        sealed      BLOB    NOT NULL,
        created_ms  INTEGER NOT NULL,
        PRIMARY KEY (provider_id, key_id)
    ) WITHOUT ROWID;
    CREATE TABLE iam_saml_provider_tags (
        provider_id TEXT NOT NULL REFERENCES iam_saml_providers (id) ON DELETE CASCADE,
        key         TEXT NOT NULL COLLATE NOCASE,
        value       TEXT NOT NULL,
        PRIMARY KEY (provider_id, key)
    ) WITHOUT ROWID;";

/// LDAP sign-in: migration 8. The managed policies mapped to directory users' and
/// groups' DNs, and a record of each directory user with live sessions.
pub(crate) const LDAP_MIGRATION: &str = "
    CREATE TABLE iam_ldap_policies (
        dn        TEXT NOT NULL,
        entity    TEXT NOT NULL,
        policy_id TEXT NOT NULL REFERENCES iam_policies (id),
        PRIMARY KEY (dn, policy_id)
    ) WITHOUT ROWID;
    CREATE TABLE iam_ldap_sessions (
        dn         TEXT    PRIMARY KEY,
        username   TEXT    NOT NULL,
        groups     TEXT    NOT NULL,
        checked_ms INTEGER NOT NULL,
        expires_ms INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        gone       INTEGER NOT NULL
    ) WITHOUT ROWID;";

/// Users and groups that are disabled, as `MinIO` has them.
pub(crate) const STATUS_MIGRATION: &str = "
    ALTER TABLE iam_users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE iam_groups ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;";

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
    /// Whether it's disabled (`MinIO`'s user status): its keys don't sign.
    pub disabled: bool,
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

/// A SAML identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlProviderRow {
    /// Its unique id.
    pub id: String,
    /// Its name, the last part of its ARN, unique without case.
    pub name: String,
    /// The identifier AWS calls its `SAMLProviderUUID`.
    pub uuid: String,
    /// Its metadata document, as given.
    pub metadata: String,
    /// Whether assertions must be encrypted (`Required`, `Allowed`, or empty if unsaid).
    pub encryption: String,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its `ValidUntil`, in milliseconds since the Unix epoch.
    pub valid_until_ms: i64,
}

/// A private key of a SAML provider, which decrypts its assertions.
#[derive(Clone, PartialEq, Eq)]
pub struct SamlKeyRow {
    /// The provider's id.
    pub provider_id: String,
    /// The key's id.
    pub key_id: String,
    /// The key (PEM), sealed.
    pub sealed: Vec<u8>,
    /// When it was added, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

impl std::fmt::Debug for SamlKeyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlKeyRow")
            .field("provider_id", &self.provider_id)
            .field("key_id", &self.key_id)
            .field("created_ms", &self.created_ms)
            .finish_non_exhaustive()
    }
}

/// A managed policy mapped to an LDAP user's or group's DN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapPolicyRow {
    /// The DN, written in one form (`teifs-iam` owns it).
    pub dn: String,
    /// `user` or `group`.
    pub entity: String,
    /// The policy's id.
    pub policy_id: String,
}

/// A directory user with live sessions, as the directory last said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapSessionRow {
    /// Its DN, written in one form.
    pub dn: String,
    /// The name it signed in with.
    pub username: String,
    /// Its groups' DNs (JSON, which `teifs-iam` owns).
    pub groups: String,
    /// When the directory last said, in milliseconds since the Unix epoch.
    pub checked_ms: i64,
    /// When its last session expires.
    pub expires_ms: i64,
    /// Sessions of an older generation are revoked.
    pub generation: u32,
    /// Whether the directory no longer has it.
    pub gone: bool,
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
    /// Whether it's disabled (`MinIO`'s group status): its policies don't count.
    pub disabled: bool,
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
    /// SAML providers.
    pub saml_providers: Vec<SamlProviderRow>,
    /// Their private keys.
    pub saml_keys: Vec<SamlKeyRow>,
    /// Their tags: (provider id, key, value).
    pub saml_provider_tags: Vec<(String, String, String)>,
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
    /// Policies mapped to LDAP DNs.
    pub ldap_policies: Vec<LdapPolicyRow>,
    /// LDAP users with live sessions.
    pub ldap_sessions: Vec<LdapSessionRow>,
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
    /// Adds or updates a SAML provider.
    PutSamlProvider(SamlProviderRow),
    /// Deletes a SAML provider (and its keys and tags).
    DeleteSamlProvider(String),
    /// Adds a SAML provider's private key.
    PutSamlKey(SamlKeyRow),
    /// Removes a SAML provider's private key: (provider id, key id).
    DeleteSamlKey(String, String),
    /// Sets a SAML provider's tag (keys compare without case; the given case is kept).
    PutSamlProviderTag(String, String, String),
    /// Removes a SAML provider's tag.
    DeleteSamlProviderTag(String, String),
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
    /// Maps a managed policy to an LDAP DN: (DN, `user` or `group`, policy id).
    PutLdapPolicy(String, String, String),
    /// Removes a mapping: (DN, policy id).
    DeleteLdapPolicy(String, String),
    /// Adds or updates an LDAP user's record.
    PutLdapSession(LdapSessionRow),
    /// Deletes an LDAP user's record.
    DeleteLdapSession(String),
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
            users: all(
                "SELECT id, name, path, created_ms, boundary, disabled FROM iam_users ORDER BY id",
            )?
            .query_map([], |r| {
                Ok(UserRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    path: r.get(2)?,
                    created_ms: r.get(3)?,
                    boundary: r.get(4)?,
                    disabled: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?,
            user_tags: tag_rows(
                conn,
                "SELECT user_id, key, value FROM iam_user_tags ORDER BY user_id, key",
            )?,
            groups: all("SELECT id, name, path, created_ms, disabled FROM iam_groups ORDER BY id")?
                .query_map([], |r| {
                    Ok(GroupRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        path: r.get(2)?,
                        created_ms: r.get(3)?,
                        disabled: r.get(4)?,
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
            saml_providers: saml_providers(conn)?,
            saml_keys: saml_keys(conn)?,
            saml_provider_tags: tag_rows(
                conn,
                "SELECT provider_id, key, value FROM iam_saml_provider_tags
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
            ldap_policies: all(
                "SELECT dn, entity, policy_id FROM iam_ldap_policies ORDER BY dn, policy_id",
            )?
            .query_map([], |r| {
                Ok(LdapPolicyRow {
                    dn: r.get(0)?,
                    entity: r.get(1)?,
                    policy_id: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?,
            ldap_sessions: all(
                "SELECT dn, username, groups, checked_ms, expires_ms, generation, gone
                 FROM iam_ldap_sessions ORDER BY dn",
            )?
            .query_map([], |r| {
                Ok(LdapSessionRow {
                    dn: r.get(0)?,
                    username: r.get(1)?,
                    groups: r.get(2)?,
                    checked_ms: r.get(3)?,
                    expires_ms: r.get(4)?,
                    generation: r.get(5)?,
                    gone: r.get(6)?,
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

fn saml_providers(conn: &rusqlite::Connection) -> Result<Vec<SamlProviderRow>> {
    Ok(conn
        .prepare(
            "SELECT id, name, uuid, metadata, encryption, created_ms, valid_until_ms
             FROM iam_saml_providers ORDER BY id",
        )?
        .query_map([], |r| {
            Ok(SamlProviderRow {
                id: r.get(0)?,
                name: r.get(1)?,
                uuid: r.get(2)?,
                metadata: r.get(3)?,
                encryption: r.get(4)?,
                created_ms: r.get(5)?,
                valid_until_ms: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
}

fn saml_keys(conn: &rusqlite::Connection) -> Result<Vec<SamlKeyRow>> {
    Ok(conn
        .prepare(
            "SELECT provider_id, key_id, sealed, created_ms FROM iam_saml_provider_keys
             ORDER BY provider_id, created_ms, key_id",
        )?
        .query_map([], |r| {
            Ok(SamlKeyRow {
                provider_id: r.get(0)?,
                key_id: r.get(1)?,
                sealed: r.get(2)?,
                created_ms: r.get(3)?,
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
            "INSERT INTO iam_users (id, name, path, created_ms, boundary, disabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, path = excluded.path,
               boundary = excluded.boundary, disabled = excluded.disabled",
            params![u.id, u.name, u.path, u.created_ms, u.boundary, u.disabled],
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
            "INSERT INTO iam_groups (id, name, path, created_ms, disabled) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, path = excluded.path,
               disabled = excluded.disabled",
            params![g.id, g.name, g.path, g.created_ms, g.disabled],
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
        IamWrite::PutSamlProvider(p) => run(
            "INSERT INTO iam_saml_providers
               (id, name, uuid, metadata, encryption, created_ms, valid_until_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (id) DO UPDATE SET metadata = excluded.metadata,
               encryption = excluded.encryption",
            params![
                p.id,
                p.name,
                p.uuid,
                p.metadata,
                p.encryption,
                p.created_ms,
                p.valid_until_ms
            ],
        ),
        IamWrite::DeleteSamlProvider(id) => {
            run("DELETE FROM iam_saml_providers WHERE id = ?1", params![id])
        }
        IamWrite::PutSamlKey(k) => run(
            "INSERT INTO iam_saml_provider_keys (provider_id, key_id, sealed, created_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![k.provider_id, k.key_id, k.sealed, k.created_ms],
        ),
        IamWrite::DeleteSamlKey(provider, key) => run(
            "DELETE FROM iam_saml_provider_keys WHERE provider_id = ?1 AND key_id = ?2",
            params![provider, key],
        ),
        IamWrite::PutSamlProviderTag(provider, key, value) => run(
            "INSERT INTO iam_saml_provider_tags (provider_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (provider_id, key) DO UPDATE SET key = excluded.key,
               value = excluded.value",
            params![provider, key, value],
        ),
        IamWrite::DeleteSamlProviderTag(provider, key) => run(
            "DELETE FROM iam_saml_provider_tags WHERE provider_id = ?1 AND key = ?2",
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
        IamWrite::PutLdapPolicy(dn, entity, policy) => run(
            "INSERT INTO iam_ldap_policies (dn, entity, policy_id) VALUES (?1, ?2, ?3)
             ON CONFLICT (dn, policy_id) DO UPDATE SET entity = excluded.entity",
            params![dn, entity, policy],
        ),
        IamWrite::DeleteLdapPolicy(dn, policy) => run(
            "DELETE FROM iam_ldap_policies WHERE dn = ?1 AND policy_id = ?2",
            params![dn, policy],
        ),
        IamWrite::PutLdapSession(s) => run(
            "INSERT INTO iam_ldap_sessions
               (dn, username, groups, checked_ms, expires_ms, generation, gone)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (dn) DO UPDATE SET username = excluded.username,
               groups = excluded.groups, checked_ms = excluded.checked_ms,
               expires_ms = excluded.expires_ms, generation = excluded.generation,
               gone = excluded.gone",
            params![s.dn, s.username, s.groups, s.checked_ms, s.expires_ms, s.generation, s.gone],
        ),
        IamWrite::DeleteLdapSession(dn) => {
            run("DELETE FROM iam_ldap_sessions WHERE dn = ?1", params![dn])
        }
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
            disabled: false,
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
                disabled: true,
                ..user("U1", "alice")
            }),
            IamWrite::PutUserTag("U1".into(), "team".into(), "a".into()),
            IamWrite::PutGroup(GroupRow {
                id: "G1".into(),
                name: "eng".into(),
                path: "/x/".into(),
                created_ms: 2,
                disabled: true,
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
    fn saml_providers_keys_and_tags_round_trip() {
        let (_dir, mut system) = open();
        let provider = SamlProviderRow {
            id: "S1".into(),
            name: "Okta".into(),
            uuid: "SAMLAAAAAAAAAAAAAAAAAAAA".into(),
            metadata: "<md/>".into(),
            encryption: String::new(),
            created_ms: 1,
            valid_until_ms: 2,
        };
        let key = |id: &str, at: i64| SamlKeyRow {
            provider_id: "S1".into(),
            key_id: id.into(),
            sealed: vec![1, 2, 3],
            created_ms: at,
        };
        system
            .iam_apply(&[
                IamWrite::PutSamlProvider(provider.clone()),
                IamWrite::PutSamlKey(key("K2", 5)),
                IamWrite::PutSamlKey(key("K1", 4)),
                IamWrite::PutSamlProviderTag("S1".into(), "Team".into(), "a".into()),
            ])
            .unwrap();
        // An update changes the metadata and encryption, never the name or dates.
        let changed = SamlProviderRow {
            metadata: "<md2/>".into(),
            encryption: "Required".into(),
            ..provider.clone()
        };
        system
            .iam_apply(&[
                IamWrite::PutSamlProvider(SamlProviderRow {
                    name: "Other".into(),
                    created_ms: 9,
                    valid_until_ms: 9,
                    ..changed.clone()
                }),
                IamWrite::PutSamlProviderTag("S1".into(), "team".into(), "b".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert_eq!(rows.saml_providers, [changed]);
        assert_eq!(rows.saml_keys, [key("K1", 4), key("K2", 5)]);
        assert!(!format!("{:?}", rows.saml_keys[0]).contains("sealed"));
        assert_eq!(
            rows.saml_provider_tags,
            [("S1".into(), "team".into(), "b".into())]
        );
        system
            .iam_apply(&[IamWrite::DeleteSamlKey("S1".into(), "K1".into())])
            .unwrap();
        assert_eq!(system.iam_rows().unwrap().saml_keys, [key("K2", 5)]);
        system
            .iam_apply(&[
                IamWrite::DeleteSamlProviderTag("S1".into(), "TEAM".into()),
                IamWrite::DeleteSamlProvider("S1".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert!(rows.saml_providers.is_empty() && rows.saml_keys.is_empty());
        assert!(rows.saml_provider_tags.is_empty());
        // Deleting a provider takes its keys and tags with it.
        system
            .iam_apply(&[
                IamWrite::PutSamlProvider(provider),
                IamWrite::PutSamlKey(key("K1", 4)),
                IamWrite::PutSamlProviderTag("S1".into(), "Team".into(), "a".into()),
                IamWrite::DeleteSamlProvider("S1".into()),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert!(rows.saml_keys.is_empty() && rows.saml_provider_tags.is_empty());
    }

    #[test]
    fn ldap_mappings_and_sessions_round_trip() {
        let (_dir, mut system) = open();
        system
            .iam_apply(&[IamWrite::PutPolicy(PolicyRow {
                id: "P1".into(),
                name: "read".into(),
                path: "/".into(),
                description: String::new(),
                default_version: 1,
                latest_version: 1,
                created_ms: 1,
                updated_ms: 1,
            })])
            .unwrap();
        let dn = "uid=a,dc=io".to_owned();
        let session = LdapSessionRow {
            dn: dn.clone(),
            username: "a".into(),
            groups: r#"["cn=g,dc=io"]"#.into(),
            checked_ms: 5,
            expires_ms: 9,
            generation: 0,
            gone: false,
        };
        system
            .iam_apply(&[
                IamWrite::PutLdapPolicy(dn.clone(), "user".into(), "P1".into()),
                IamWrite::PutLdapPolicy(dn.clone(), "user".into(), "P1".into()),
                IamWrite::PutLdapSession(session.clone()),
            ])
            .unwrap();
        let changed = LdapSessionRow {
            generation: 2,
            gone: true,
            groups: "[]".into(),
            checked_ms: 6,
            expires_ms: 10,
            username: "A".into(),
            ..session
        };
        system
            .iam_apply(&[IamWrite::PutLdapSession(changed.clone())])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert_eq!(
            rows.ldap_policies,
            [LdapPolicyRow {
                dn: dn.clone(),
                entity: "user".into(),
                policy_id: "P1".into(),
            }]
        );
        assert_eq!(rows.ldap_sessions, [changed]);
        assert!(
            system
                .iam_apply(&[IamWrite::PutLdapPolicy(
                    dn.clone(),
                    "user".into(),
                    "P9".into()
                )])
                .is_err(),
            "only policies that exist"
        );
        system
            .iam_apply(&[
                IamWrite::DeleteLdapPolicy(dn.clone(), "P1".into()),
                IamWrite::DeleteLdapSession(dn),
            ])
            .unwrap();
        let rows = system.iam_rows().unwrap();
        assert!(rows.ldap_policies.is_empty() && rows.ldap_sessions.is_empty());
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
                disabled: false,
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
