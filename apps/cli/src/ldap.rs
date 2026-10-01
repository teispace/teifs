//! The LDAP directory `teifs serve` signs users in with (`AssumeRoleWithLDAPIdentity`),
//! and that `teifs doctor` checks. The lookup account's password never comes from a
//! flag: `TEIFS_LDAP_LOOKUP_BIND_PASSWORD`.
//!
//! MinIO's `MINIO_IDENTITY_LDAP_*` variables work as well when `--ldap-server` isn't
//! given, so a MinIO deployment's environment carries over.

use std::path::PathBuf;

use teifs_client::Zeroizing;
use teifs_server::{LdapSettings, SrvRecord, Transport};

use crate::error::{Error, Kind};

/// The directory's settings.
#[derive(clap::Args, Clone, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "each field is a flag, named as clap names it"
)]
pub(crate) struct LdapArgs {
    /// Sign users in with this LDAP server (`host` or `host:port`; port 636 when none),
    /// as MinIO's `AssumeRoleWithLDAPIdentity`. Its lookup account's password comes from
    /// `TEIFS_LDAP_LOOKUP_BIND_PASSWORD`.
    #[arg(long, env = "TEIFS_LDAP_SERVER", value_name = "ADDRESS")]
    pub ldap_server: Option<String>,
    /// Find the servers in DNS SRV records instead: `on` (the address is the record's
    /// whole name), `ldap` or `ldaps` (the address is a domain).
    #[arg(long, env = "TEIFS_LDAP_SRV_RECORD", requires = "ldap_server", value_parser = ["on", "ldap", "ldaps"])]
    pub ldap_srv_record: Option<String>,
    /// Reach it with plain LDAP upgraded by `StartTLS`, not LDAP over TLS.
    #[arg(
        long,
        env = "TEIFS_LDAP_STARTTLS",
        requires = "ldap_server",
        conflicts_with = "ldap_insecure"
    )]
    pub ldap_starttls: bool,
    /// Reach it with plain, unencrypted LDAP: passwords cross the network as they are.
    #[arg(long, env = "TEIFS_LDAP_INSECURE", requires = "ldap_server")]
    pub ldap_insecure: bool,
    /// The certificate authorities (PEM) its certificate is checked against (default:
    /// the system's).
    #[arg(
        long,
        env = "TEIFS_LDAP_CA",
        requires = "ldap_server",
        value_name = "FILE"
    )]
    pub ldap_ca: Option<PathBuf>,
    /// Accept any certificate from it: for a test directory only.
    #[arg(long, env = "TEIFS_LDAP_TLS_SKIP_VERIFY", requires = "ldap_server")]
    pub ldap_tls_skip_verify: bool,
    /// The DN of the account users are looked up with.
    #[arg(
        long,
        env = "TEIFS_LDAP_LOOKUP_BIND_DN",
        requires = "ldap_server",
        value_name = "DN"
    )]
    pub ldap_lookup_bind_dn: Option<String>,
    /// Where users are searched for (repeatable, or separated by `;`).
    #[arg(
        long,
        env = "TEIFS_LDAP_USER_BASE_DN",
        requires = "ldap_server",
        value_name = "DN",
        value_delimiter = ';'
    )]
    pub ldap_user_base_dn: Vec<String>,
    /// The filter that finds a user: `%s` is the name it signs in with, like `(uid=%s)`.
    #[arg(
        long,
        env = "TEIFS_LDAP_USER_FILTER",
        requires = "ldap_server",
        value_name = "FILTER"
    )]
    pub ldap_user_filter: Option<String>,
    /// The user's attributes its sessions carry, comma-separated.
    #[arg(
        long,
        env = "TEIFS_LDAP_USER_ATTRIBUTES",
        requires = "ldap_server",
        value_name = "NAMES",
        value_delimiter = ','
    )]
    pub ldap_user_attributes: Vec<String>,
    /// Where groups are searched for (repeatable, or separated by `;`).
    #[arg(
        long,
        env = "TEIFS_LDAP_GROUP_BASE_DN",
        requires = "ldap_server",
        value_name = "DN",
        value_delimiter = ';'
    )]
    pub ldap_group_base_dn: Vec<String>,
    /// The filter that finds a user's groups: `%d` is its DN and `%s` the name it signs
    /// in with, like `(&(objectclass=groupOfNames)(member=%d))`.
    #[arg(
        long,
        env = "TEIFS_LDAP_GROUP_FILTER",
        requires = "ldap_server",
        value_name = "FILTER"
    )]
    pub ldap_group_filter: Option<String>,
}

/// The lookup account's password.
const PASSWORD: &str = "TEIFS_LDAP_LOOKUP_BIND_PASSWORD";
/// MinIO's variables.
const MINIO: &str = "MINIO_IDENTITY_LDAP_";

impl LdapArgs {
    /// The directory these settings (or MinIO's variables) name, if any.
    pub(crate) fn settings(&self) -> Result<Option<LdapSettings>, Error> {
        self.settings_with(&|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
    }

    fn settings_with(
        &self,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<LdapSettings>, Error> {
        let given = match &self.ldap_server {
            Some(server) => self.clone_with(server),
            None => match Self::from_minio(env)? {
                Some(args) => args,
                None => return Ok(None),
            },
        };
        let ca_pem = match &given.ldap_ca {
            Some(path) => Some(std::fs::read(path).map_err(|e| {
                Error::new(
                    Kind::NotFound,
                    format!("can't read the LDAP CA file {}: {e}", path.display()),
                )
            })?),
            None => None,
        };
        let transport = if given.ldap_insecure {
            Transport::Plain
        } else if given.ldap_starttls {
            Transport::StartTls
        } else {
            Transport::Tls
        };
        let lookup_password = env(PASSWORD)
            .or_else(|| env(&format!("{MINIO}LOOKUP_BIND_PASSWORD")))
            .map(Zeroizing::new);
        let list = |values: &[String]| -> Vec<String> {
            values
                .iter()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .collect()
        };
        Ok(Some(LdapSettings {
            server: given.ldap_server.clone().unwrap_or_default(),
            srv: given.ldap_srv_record.as_deref().and_then(SrvRecord::parse),
            transport,
            ca_pem,
            skip_verify: given.ldap_tls_skip_verify,
            lookup_dn: given.ldap_lookup_bind_dn.clone().unwrap_or_default(),
            lookup_password,
            user_bases: list(&given.ldap_user_base_dn),
            user_filter: given.ldap_user_filter.clone().unwrap_or_default(),
            user_attributes: list(&given.ldap_user_attributes),
            group_bases: list(&given.ldap_group_base_dn),
            group_filter: given
                .ldap_group_filter
                .clone()
                .filter(|f| !f.trim().is_empty()),
        }))
    }

    fn clone_with(&self, server: &str) -> Self {
        Self {
            ldap_server: Some(server.to_owned()),
            ..self.clone()
        }
    }

    /// The settings MinIO's `MINIO_IDENTITY_LDAP_*` variables give, if they name a
    /// server.
    fn from_minio(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, Error> {
        let var = |name: &str| env(&format!("{MINIO}{name}"));
        let Some(server) = var("SERVER_ADDR") else {
            return Ok(None);
        };
        if var("ENABLE").is_some_and(|v| matches!(flag(&v), Ok(false))) {
            return Ok(None);
        }
        let on = |name: &str| -> Result<bool, Error> {
            var(name).map_or(Ok(false), |v| {
                flag(&v)
                    .map_err(|()| Error::usage(format!("{MINIO}{name} is `{v}`: give on or off")))
            })
        };
        let split = |name: &str, by: char| -> Vec<String> {
            var(name)
                .map(|v| v.split(by).map(str::to_owned).collect())
                .unwrap_or_default()
        };
        let srv = var("SRV_RECORD_NAME");
        if let Some(srv) = &srv
            && SrvRecord::parse(srv).is_none()
        {
            return Err(Error::usage(format!(
                "{MINIO}SRV_RECORD_NAME is `{srv}`: give on, ldap or ldaps"
            )));
        }
        Ok(Some(Self {
            ldap_server: Some(server),
            ldap_srv_record: srv,
            ldap_starttls: on("SERVER_STARTTLS")?,
            ldap_insecure: on("SERVER_INSECURE")?,
            ldap_ca: None,
            ldap_tls_skip_verify: on("TLS_SKIP_VERIFY")?,
            ldap_lookup_bind_dn: var("LOOKUP_BIND_DN"),
            ldap_user_base_dn: split("USER_DN_SEARCH_BASE_DN", ';'),
            ldap_user_filter: var("USER_DN_SEARCH_FILTER"),
            ldap_user_attributes: split("USER_DN_ATTRIBUTES", ','),
            ldap_group_base_dn: split("GROUP_SEARCH_BASE_DN", ';'),
            ldap_group_filter: var("GROUP_SEARCH_FILTER"),
        }))
    }
}

/// MinIO's booleans: `on`/`off`, and the usual spellings.
fn flag(value: &str) -> Result<bool, ()> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" | "enable" | "enabled" => Ok(true),
        "off" | "false" | "no" | "0" | "disable" | "disabled" => Ok(false),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const MINIO_ENV: [(&str, &str); 10] = [
        ("MINIO_IDENTITY_LDAP_SERVER_ADDR", "ldap.min.io:389"),
        ("MINIO_IDENTITY_LDAP_SERVER_INSECURE", "on"),
        (
            "MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN",
            "cn=admin,dc=min,dc=io",
        ),
        ("MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD", "admin"),
        (
            "MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN",
            "ou=a,dc=min,dc=io; ou=b,dc=min,dc=io",
        ),
        ("MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER", "(uid=%s)"),
        (
            "MINIO_IDENTITY_LDAP_USER_DN_ATTRIBUTES",
            "mail, sshPublicKey",
        ),
        (
            "MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN",
            "ou=groups,dc=min,dc=io",
        ),
        ("MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER", "(member=%d)"),
        ("MINIO_IDENTITY_LDAP_SRV_RECORD_NAME", "ldap"),
    ];

    #[test]
    fn no_server_is_no_directory() {
        assert!(
            LdapArgs::default()
                .settings_with(&env(&[]))
                .unwrap()
                .is_none()
        );
        let off = [MINIO_ENV[0], ("MINIO_IDENTITY_LDAP_ENABLE", "off")];
        assert!(
            LdapArgs::default()
                .settings_with(&env(&off))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn minios_variables_carry_over() {
        let s = LdapArgs::default()
            .settings_with(&env(&MINIO_ENV))
            .unwrap()
            .unwrap();
        assert_eq!(s.server, "ldap.min.io:389");
        assert_eq!(s.transport, Transport::Plain);
        assert_eq!(s.srv, Some(SrvRecord::Ldap));
        assert_eq!(s.lookup_dn, "cn=admin,dc=min,dc=io");
        assert_eq!(
            s.lookup_password.as_deref().map(String::as_str),
            Some("admin")
        );
        assert_eq!(s.user_bases, ["ou=a,dc=min,dc=io", "ou=b,dc=min,dc=io"]);
        assert_eq!(s.user_filter, "(uid=%s)");
        assert_eq!(s.user_attributes, ["mail", "sshPublicKey"]);
        assert_eq!(s.group_bases, ["ou=groups,dc=min,dc=io"]);
        assert_eq!(s.group_filter.as_deref(), Some("(member=%d)"));
        let bad = [
            MINIO_ENV[0],
            ("MINIO_IDENTITY_LDAP_SERVER_STARTTLS", "maybe"),
        ];
        assert!(LdapArgs::default().settings_with(&env(&bad)).is_err());
        let bad = [MINIO_ENV[0], ("MINIO_IDENTITY_LDAP_SRV_RECORD_NAME", "dns")];
        assert!(LdapArgs::default().settings_with(&env(&bad)).is_err());
        let starttls = [
            MINIO_ENV[0],
            ("MINIO_IDENTITY_LDAP_SERVER_STARTTLS", "true"),
        ];
        let s = LdapArgs::default()
            .settings_with(&env(&starttls))
            .unwrap()
            .unwrap();
        assert_eq!(s.transport, Transport::StartTls);
        assert!(s.lookup_password.is_none());
    }

    #[test]
    fn flags_win_over_minios_variables() {
        let args = LdapArgs {
            ldap_server: Some("ldaps.example.com".into()),
            ldap_lookup_bind_dn: Some("cn=lookup,dc=example,dc=com".into()),
            ldap_user_base_dn: vec!["dc=example,dc=com".into(), " ".into()],
            ldap_user_filter: Some("(sAMAccountName=%s)".into()),
            ldap_group_filter: Some(" ".into()),
            ldap_tls_skip_verify: true,
            ..LdapArgs::default()
        };
        let pass = [(PASSWORD, "secret"), MINIO_ENV[3]];
        let s = args.settings_with(&env(&pass)).unwrap().unwrap();
        assert_eq!(s.server, "ldaps.example.com");
        assert_eq!(s.transport, Transport::Tls);
        assert!(s.skip_verify);
        assert_eq!(s.user_bases, ["dc=example,dc=com"]);
        assert_eq!(s.group_filter, None);
        assert_eq!(
            s.lookup_password.as_deref().map(String::as_str),
            Some("secret")
        );
        let starttls = LdapArgs {
            ldap_starttls: true,
            ..args.clone()
        };
        assert_eq!(
            starttls
                .settings_with(&env(&[]))
                .unwrap()
                .unwrap()
                .transport,
            Transport::StartTls
        );
        let missing_ca = LdapArgs {
            ldap_ca: Some("/no/such/ca.pem".into()),
            ..args
        };
        assert!(missing_ca.settings_with(&env(&[])).is_err());
    }
}
