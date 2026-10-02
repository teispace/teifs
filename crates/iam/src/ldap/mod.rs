//! Sign-in with an LDAP directory (Active Directory, `OpenLDAP`…), as MinIO has it:
//! `AssumeRoleWithLDAPIdentity` takes a directory user's name and password and gives
//! temporary credentials whose permissions are the managed policies mapped to the user's
//! DN and to the DNs of its groups.
//!
//! TeiFS binds as a lookup account, finds the user's DN with the user search filter,
//! binds as that DN with the password, then finds its groups with the group search
//! filter. Mappings are kept by DN, written in one form ([`dn`]), so a DN in any spelling
//! finds them.

pub(crate) mod client;
pub(crate) mod dn;
#[cfg(any(test, feature = "fake-ldap"))]
pub mod fake;
mod tls;

#[cfg(test)]
mod directory_tests;
#[cfg(test)]
mod sign_in_tests;

use std::{sync::Arc, time::Duration};

use zeroize::Zeroizing;

pub use client::{Directory, LdapError, SignedIn};
use dn::Dn;
pub use dn::normalize;

/// Whether a name is written as a DN (`uid=ann,ou=people,…`) rather than a user name.
#[must_use]
pub fn is_dn(name: &str) -> bool {
    name.contains('=') && normalize(name).is_ok()
}

/// How long to wait to connect to the directory, and for each operation (MinIO waits
/// 30 seconds for each).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// The port LDAP over TLS listens on when the address names none.
const LDAPS_PORT: u16 = 636;

/// How the directory is reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Transport {
    /// LDAP over TLS (`ldaps://`).
    #[default]
    Tls,
    /// Plain LDAP upgraded with `StartTLS`.
    StartTls,
    /// Plain LDAP, unencrypted: passwords cross the network as they are.
    Plain,
}

impl Transport {
    /// `tls`, `starttls` or `plain`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::StartTls => "starttls",
            Self::Plain => "plain",
        }
    }
}

/// Where the directory's servers are listed in DNS SRV records, instead of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvRecord {
    /// The address is the SRV record's whole name (`_ldap._tcp.example.com`).
    On,
    /// `_ldap._tcp.` before the address (a domain).
    Ldap,
    /// `_ldaps._tcp.` before the address.
    Ldaps,
}

impl SrvRecord {
    /// MinIO's names: `on`, `ldap`, `ldaps`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "on" => Some(Self::On),
            "ldap" => Some(Self::Ldap),
            "ldaps" => Some(Self::Ldaps),
            _ => None,
        }
    }
}

/// The directory's settings, as `teifs serve` takes them (and MinIO's
/// `MINIO_IDENTITY_LDAP_*`).
#[derive(Clone, Default)]
pub struct LdapSettings {
    /// The server's address (`host` or `host:port`; 636 when none), or the name an SRV
    /// lookup starts from.
    pub server: String,
    /// Whether the address names SRV records.
    pub srv: Option<SrvRecord>,
    /// How the server is reached.
    pub transport: Transport,
    /// The certificate authorities (PEM) the server's certificate is checked against,
    /// instead of the system's.
    pub ca_pem: Option<Vec<u8>>,
    /// Accept any certificate from the server (MinIO's `tls_skip_verify`).
    pub skip_verify: bool,
    /// The lookup account's DN.
    pub lookup_dn: String,
    /// The lookup account's password (none: an unauthenticated bind).
    pub lookup_password: Option<Zeroizing<String>>,
    /// Where users are searched for (MinIO separates DNs with `;`).
    pub user_bases: Vec<String>,
    /// The filter that finds a user: `%s` is the name signed in with.
    pub user_filter: String,
    /// The user's attributes its sessions' claims carry.
    pub user_attributes: Vec<String>,
    /// Where groups are searched for.
    pub group_bases: Vec<String>,
    /// The filter that finds a user's groups: `%s` is the name signed in with, `%d` the
    /// user's DN. None: users' groups aren't looked up.
    pub group_filter: Option<String>,
}

impl std::fmt::Debug for LdapSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapSettings")
            .field("server", &self.server)
            .field("srv", &self.srv)
            .field("transport", &self.transport)
            .field("lookup_dn", &self.lookup_dn)
            .field("user_bases", &self.user_bases)
            .field("user_filter", &self.user_filter)
            .field("group_bases", &self.group_bases)
            .field("group_filter", &self.group_filter)
            .finish_non_exhaustive()
    }
}

/// Settings checked before any connection: what a directory can't fix.
pub(crate) struct Checked {
    pub(crate) settings: LdapSettings,
    pub(crate) user_bases: Vec<Dn>,
    pub(crate) group_bases: Vec<Dn>,
    pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
}

impl LdapSettings {
    /// Checks what can be checked without the directory, as MinIO does: an address, a
    /// lookup account, base DNs that parse and don't overlap, filters that parse with
    /// their placeholders, attribute names.
    pub(crate) fn check(self) -> Result<Checked, String> {
        if self.server.trim().is_empty() {
            return Err("give the LDAP server's address".to_owned());
        }
        if self.lookup_dn.trim().is_empty() {
            return Err(
                "give the DN of the account TeiFS looks users up with (the lookup bind DN)"
                    .to_owned(),
            );
        }
        dn::normalize(&self.lookup_dn).map_err(|e| format!("the lookup bind DN: {e}"))?;
        let user_bases = bases(&self.user_bases, "user")?;
        if user_bases.is_empty() {
            return Err("give the base DN users are searched under".to_owned());
        }
        if !self.user_filter.contains("%s") {
            return Err(format!(
                "the user search filter `{}` must contain %s, which becomes the name a user \
                 signs in with, like (uid=%s)",
                self.user_filter
            ));
        }
        if self.user_filter.contains("%d") {
            return Err(format!(
                "the user search filter `{}` can't contain %d: only %s, the name a user signs \
                 in with",
                self.user_filter
            ));
        }
        filter(&self.user_filter, "user")?;
        if let Some(bad) = self.user_attributes.iter().find(|a| !is_attribute_name(a)) {
            return Err(format!("`{bad}` isn't an attribute name"));
        }
        let group_bases = bases(&self.group_bases, "group")?;
        if let Some(group_filter) = &self.group_filter {
            if !group_filter.contains("%s") && !group_filter.contains("%d") {
                return Err(format!(
                    "the group search filter `{group_filter}` must contain %s (the name a user \
                     signs in with) or %d (the user's DN), like \
                     (&(objectclass=groupOfNames)(member=%d))"
                ));
            }
            filter(group_filter, "group")?;
            if group_bases.is_empty() {
                return Err("give the base DN groups are searched under".to_owned());
            }
        }
        let tls = match self.transport {
            Transport::Plain => None,
            Transport::Tls | Transport::StartTls => {
                Some(tls::config(self.ca_pem.as_deref(), self.skip_verify)?)
            }
        };
        Ok(Checked {
            settings: self,
            user_bases,
            group_bases,
            tls,
        })
    }

    /// The URL of the server at `address` (`host` or `host:port`).
    pub(crate) fn url(&self, address: &str) -> String {
        let scheme = match self.transport {
            Transport::Tls => "ldaps",
            Transport::StartTls | Transport::Plain => "ldap",
        };
        if has_port(address) {
            format!("{scheme}://{address}")
        } else {
            format!("{scheme}://{address}:{LDAPS_PORT}")
        }
    }
}

/// Whether `address` names a port: `host:port` or `[v6]:port`.
fn has_port(address: &str) -> bool {
    match address.rsplit_once(':') {
        Some((host, port)) => {
            port.parse::<u16>().is_ok()
                && (!host.contains(':') || (host.starts_with('[') && host.ends_with(']')))
        }
        None => false,
    }
}

/// Base DNs, parsed, none of them below another.
fn bases(given: &[String], what: &str) -> Result<Vec<Dn>, String> {
    let mut parsed: Vec<(Dn, &str)> = Vec::new();
    for text in given.iter().map(|b| b.trim()).filter(|b| !b.is_empty()) {
        let base = Dn::parse(text).map_err(|e| format!("the {what} search base DN: {e}"))?;
        if let Some((_, other)) = parsed
            .iter()
            .find(|(p, _)| p.is_ancestor_of(&base) || base.is_ancestor_of(p) || p.same(&base))
        {
            return Err(format!(
                "the {what} search base DNs `{other}` and `{text}` overlap: give each subtree once"
            ));
        }
        parsed.push((base, text));
    }
    Ok(parsed.into_iter().map(|(dn, _)| dn).collect())
}

/// Checks a search filter parses once its placeholders are filled, as MinIO does.
fn filter(text: &str, what: &str) -> Result<(), String> {
    let filled = text.replace("%s", "a").replace("%d", "uid=a,dc=min,dc=io");
    ldap3::parse_filter(&filled)
        .map(drop)
        .map_err(|()| format!("the {what} search filter `{text}` isn't an LDAP filter"))
}

/// MinIO's attribute names: a letter, then letters, digits and `-`.
fn is_attribute_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A search filter with its placeholders filled, each value escaped (RFC 4515).
pub(crate) fn fill(filter: &str, username: &str, dn: &str) -> String {
    filter
        .replace("%s", &ldap3::ldap_escape(username))
        .replace("%d", &ldap3::ldap_escape(dn))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> LdapSettings {
        LdapSettings {
            server: "ldap.example.com".into(),
            lookup_dn: "cn=admin,dc=min,dc=io".into(),
            user_bases: vec!["ou=people,dc=min,dc=io".into()],
            user_filter: "(uid=%s)".into(),
            user_attributes: vec!["sshPublicKey".into()],
            group_bases: vec!["ou=groups,dc=min,dc=io".into()],
            group_filter: Some("(&(objectclass=groupOfNames)(member=%d))".into()),
            transport: Transport::Plain,
            ..LdapSettings::default()
        }
    }

    #[test]
    fn good_settings_pass() {
        let checked = settings().check().unwrap();
        assert_eq!(checked.user_bases.len(), 1);
        assert_eq!(checked.group_bases.len(), 1);
        assert!(checked.tls.is_none());
        let tls = LdapSettings {
            transport: Transport::Tls,
            group_filter: None,
            group_bases: vec![],
            ..settings()
        };
        assert!(tls.check().unwrap().tls.is_some());
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "a table of cases")]
    fn bad_settings_say_what_to_fix() {
        let cases: Vec<(LdapSettings, &str)> = vec![
            (
                LdapSettings {
                    server: " ".into(),
                    ..settings()
                },
                "address",
            ),
            (
                LdapSettings {
                    lookup_dn: String::new(),
                    ..settings()
                },
                "lookup",
            ),
            (
                LdapSettings {
                    lookup_dn: "admin".into(),
                    ..settings()
                },
                "lookup bind DN",
            ),
            (
                LdapSettings {
                    user_bases: vec![" ".into()],
                    ..settings()
                },
                "base DN users",
            ),
            (
                LdapSettings {
                    user_bases: vec!["people".into()],
                    ..settings()
                },
                "user search base",
            ),
            (
                LdapSettings {
                    user_bases: vec!["dc=min,dc=io".into(), "ou=people,DC=min,dc=io".into()],
                    ..settings()
                },
                "overlap",
            ),
            (
                LdapSettings {
                    group_bases: vec!["ou=g,dc=io".into(), "OU=g,dc=io".into()],
                    ..settings()
                },
                "overlap",
            ),
            (
                LdapSettings {
                    user_filter: "(uid=x)".into(),
                    ..settings()
                },
                "must contain %s",
            ),
            (
                LdapSettings {
                    user_filter: "(&(uid=%s)(x=%d))".into(),
                    ..settings()
                },
                "can't contain %d",
            ),
            (
                LdapSettings {
                    user_filter: "(uid=%s".into(),
                    ..settings()
                },
                "isn't an LDAP filter",
            ),
            (
                LdapSettings {
                    user_attributes: vec!["1x".into()],
                    ..settings()
                },
                "attribute",
            ),
            (
                LdapSettings {
                    group_filter: Some("(member=x)".into()),
                    ..settings()
                },
                "%s",
            ),
            (
                LdapSettings {
                    group_filter: Some("member=%d)".into()),
                    ..settings()
                },
                "isn't an LDAP filter",
            ),
            (
                LdapSettings {
                    group_bases: vec![],
                    ..settings()
                },
                "groups are searched",
            ),
            (
                LdapSettings {
                    transport: Transport::Tls,
                    ca_pem: Some(b"nothing".to_vec()),
                    ..settings()
                },
                "certificate",
            ),
        ];
        for (settings, says) in cases {
            let err = settings
                .clone()
                .check()
                .err()
                .unwrap_or_else(|| panic!("{settings:?}"));
            assert!(err.contains(says), "{err} / {says}");
        }
    }

    #[test]
    fn addresses_get_a_scheme_and_port() {
        let tls = LdapSettings {
            transport: Transport::Tls,
            ..settings()
        };
        assert_eq!(tls.url("ldap.example.com"), "ldaps://ldap.example.com:636");
        assert_eq!(
            tls.url("ldap.example.com:1636"),
            "ldaps://ldap.example.com:1636"
        );
        assert_eq!(tls.url("[::1]:389"), "ldaps://[::1]:389");
        assert_eq!(tls.url("[::1]"), "ldaps://[::1]:636");
        let plain = settings();
        assert_eq!(plain.url("127.0.0.1:389"), "ldap://127.0.0.1:389");
        let starttls = LdapSettings {
            transport: Transport::StartTls,
            ..settings()
        };
        assert_eq!(starttls.url("h"), "ldap://h:636");
        assert_eq!(SrvRecord::parse("ldaps"), Some(SrvRecord::Ldaps));
        assert_eq!(SrvRecord::parse("on"), Some(SrvRecord::On));
        assert_eq!(SrvRecord::parse("ldap"), Some(SrvRecord::Ldap));
        assert_eq!(SrvRecord::parse("off"), None);
    }

    #[test]
    fn placeholders_are_escaped() {
        assert_eq!(
            fill("(&(uid=%s)(member=%d))", "a*)(uid=b", "cn=x(y),dc=io"),
            "(&(uid=a\\2a\\29\\28uid=b)(member=cn=x\\28y\\29,dc=io))"
        );
    }
}
