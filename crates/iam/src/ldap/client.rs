//! The directory's operations: sign a user in, look up a DN, refresh a user's groups.
//! Each opens its own connection and binds as the lookup account, as MinIO does, so no
//! connection outlives a request or carries a user's bind.

use std::{collections::BTreeMap, sync::Arc};

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError as Ldap3Error, ResultEntry, Scope};
use zeroize::Zeroizing;

use super::{
    CONNECT_TIMEOUT, Checked, LdapSettings, OPERATION_TIMEOUT, SrvRecord, Transport, dn, fill,
};
use dn::Dn;

/// LDAP's result codes TeiFS tells apart (RFC 4511, appendix A).
const NO_SUCH_OBJECT: u32 = 32;
const INVALID_CREDENTIALS: u32 = 49;

/// Asking for no attributes (RFC 4511, 4.5.1.8).
const NO_ATTRIBUTES: &[&str] = &["1.1"];

/// Why the directory didn't answer as hoped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LdapError {
    /// The server has no directory to sign users in with.
    #[error("LDAP isn't set up on this server")]
    NotSetUp,
    /// No server could be reached.
    #[error("can't reach the LDAP server: {0}")]
    Unreachable(String),
    /// The lookup account couldn't bind.
    #[error("the LDAP lookup account can't sign in: {0}")]
    LookupBind(String),
    /// No such user, or the password is wrong (told apart only in the server's log).
    #[error("the LDAP user name or password is wrong")]
    Refused,
    /// The user search found more than one user.
    #[error("more than one LDAP user is named {0}: fix the user search filter")]
    Ambiguous(String),
    /// The directory failed otherwise.
    #[error("the LDAP server failed: {0}")]
    Failed(String),
}

/// A user the directory vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    /// The user's DN, written in one form: what its mappings are kept by.
    pub dn: String,
    /// The DN as the directory spells it.
    pub actual_dn: String,
    /// The name it signed in with.
    pub username: String,
    /// Its groups' DNs, written in one form.
    pub groups: Vec<String>,
    /// The attributes the settings ask for, by name.
    pub attributes: BTreeMap<String, Vec<String>>,
}

/// An LDAP directory TeiFS signs users in with.
pub struct Directory {
    checked: Checked,
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("settings", &self.checked.settings)
            .finish_non_exhaustive()
    }
}

/// What a lookup of a DN found: the DN as the directory spells it, written in one form,
/// and whether it sits under one of the settings' base DNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Found {
    pub(crate) dn: String,
    pub(crate) under_base: bool,
}

/// Users or groups: which base DNs a DN must sit under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    User,
    Group,
}

impl Directory {
    /// A directory with these settings, checked as far as they can be without it.
    ///
    /// # Errors
    ///
    /// What's wrong with the settings, in a sentence that says how to fix it.
    pub fn new(settings: LdapSettings) -> Result<Self, String> {
        Ok(Self {
            checked: settings.check()?,
        })
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &LdapSettings {
        &self.checked.settings
    }

    /// Signs `username` in with `password`: finds its DN with the lookup account, binds
    /// as it, and finds its groups.
    ///
    /// # Errors
    ///
    /// [`LdapError::Refused`] for an unknown user or a wrong password (or an empty one,
    /// which LDAP would take as an unauthenticated bind); otherwise the directory's
    /// failure.
    pub async fn sign_in(&self, username: &str, password: &str) -> Result<SignedIn, LdapError> {
        if username.is_empty() || password.is_empty() {
            return Err(LdapError::Refused);
        }
        let mut ldap = self.lookup_session().await?;
        let found = self.find_user(&mut ldap, username).await;
        let (actual_dn, attributes) = match found {
            Ok(Some(found)) => found,
            Ok(None) => {
                close(ldap).await;
                tracing::info!(username, "LDAP sign-in refused: no such user");
                return Err(LdapError::Refused);
            }
            Err(e) => {
                close(ldap).await;
                return Err(e);
            }
        };
        let bound = ldap
            .with_timeout(OPERATION_TIMEOUT)
            .simple_bind(&actual_dn, password)
            .await
            .and_then(ldap3::LdapResult::success);
        if let Err(e) = bound {
            close(ldap).await;
            return Err(match code(&e) {
                Some(INVALID_CREDENTIALS) => {
                    tracing::info!(dn = %actual_dn, "LDAP sign-in refused: wrong password");
                    LdapError::Refused
                }
                _ => failed(&e),
            });
        }
        let groups = self.groups_again(&mut ldap, username, &actual_dn).await;
        close(ldap).await;
        Ok(SignedIn {
            dn: dn::normalize(&actual_dn).map_err(LdapError::Failed)?,
            actual_dn,
            username: username.to_owned(),
            groups: groups?,
            attributes,
        })
    }

    /// The user who signs in as `username`, as the directory has it now, found without
    /// its password: none when the user search filter finds none.
    ///
    /// # Errors
    ///
    /// [`LdapError::Ambiguous`] when the filter finds more than one; otherwise the
    /// directory's failure.
    pub async fn user(&self, username: &str) -> Result<Option<SignedIn>, LdapError> {
        if username.is_empty() {
            return Ok(None);
        }
        let mut ldap = self.lookup_session().await?;
        let found = match self.find_user(&mut ldap, username).await {
            Ok(Some((actual_dn, attributes))) => self
                .groups(&mut ldap, username, &actual_dn)
                .await
                .and_then(|groups| {
                    Ok(Some(SignedIn {
                        dn: dn::normalize(&actual_dn).map_err(LdapError::Failed)?,
                        actual_dn,
                        username: username.to_owned(),
                        groups,
                        attributes,
                    }))
                }),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        };
        close(ldap).await;
        found
    }

    /// The user `dn` (signed in as `username`) as the directory has it now: its groups,
    /// or none when it's gone or no longer under the user base DNs.
    pub(crate) async fn refresh(
        &self,
        dn: &str,
        username: &str,
    ) -> Result<Option<Vec<String>>, LdapError> {
        let mut ldap = self.lookup_session().await?;
        let found = self.look_up(&mut ldap, dn, Kind::User).await;
        let result = match found {
            Ok(Some(Found {
                under_base: true,
                dn: _,
            })) => self.groups(&mut ldap, username, dn).await.map(Some),
            Ok(_) => Ok(None),
            Err(e) => Err(e),
        };
        close(ldap).await;
        result
    }

    /// Looks up a user's or group's DN, given in any spelling.
    pub(crate) async fn find(&self, dn: &str, kind: Kind) -> Result<Option<Found>, LdapError> {
        let mut ldap = self.lookup_session().await?;
        let found = self.look_up(&mut ldap, dn, kind).await;
        close(ldap).await;
        found
    }

    /// Checks the directory can be used: it's reached, the lookup account binds, and
    /// each base DN exists.
    ///
    /// # Errors
    ///
    /// The first thing that's wrong.
    pub async fn check(&self) -> Result<(), LdapError> {
        let mut ldap = self.lookup_session().await?;
        let mut result = Ok(());
        let bases = self
            .settings()
            .user_bases
            .iter()
            .chain(&self.settings().group_bases);
        for base in bases.filter(|b| !b.trim().is_empty()) {
            match exists(&mut ldap, base).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    result = Err(LdapError::Failed(format!(
                        "the base DN {base} isn't in the directory"
                    )));
                    break;
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        close(ldap).await;
        result
    }

    /// A connection bound as the lookup account.
    async fn lookup_session(&self) -> Result<Ldap, LdapError> {
        let mut ldap = self.connect().await?;
        let settings = self.settings();
        let password = settings
            .lookup_password
            .clone()
            .unwrap_or_else(|| Zeroizing::new(String::new()));
        let bound = ldap
            .with_timeout(OPERATION_TIMEOUT)
            .simple_bind(&settings.lookup_dn, &password)
            .await
            .and_then(ldap3::LdapResult::success);
        match bound {
            Ok(_) => Ok(ldap),
            Err(e) => {
                close(ldap).await;
                Err(LdapError::LookupBind(describe(&e)))
            }
        }
    }

    /// Binds as the lookup account again (the connection is bound as the user), then
    /// finds the user's groups.
    async fn groups_again(
        &self,
        ldap: &mut Ldap,
        username: &str,
        user_dn: &str,
    ) -> Result<Vec<String>, LdapError> {
        if self.settings().group_filter.is_none() {
            return Ok(Vec::new());
        }
        let settings = self.settings();
        let password = settings
            .lookup_password
            .clone()
            .unwrap_or_else(|| Zeroizing::new(String::new()));
        ldap.with_timeout(OPERATION_TIMEOUT)
            .simple_bind(&settings.lookup_dn, &password)
            .await
            .and_then(ldap3::LdapResult::success)
            .map_err(|e| LdapError::LookupBind(describe(&e)))?;
        self.groups(ldap, username, user_dn).await
    }

    /// The DN and attributes of the one user the user search filter finds for
    /// `username`, if it finds one.
    async fn find_user(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<Option<(String, BTreeMap<String, Vec<String>>)>, LdapError> {
        let settings = self.settings();
        let filter = fill(&settings.user_filter, username, "");
        let attributes: Vec<&str> = if settings.user_attributes.is_empty() {
            NO_ATTRIBUTES.to_vec()
        } else {
            settings
                .user_attributes
                .iter()
                .map(String::as_str)
                .collect()
        };
        let mut found = Vec::new();
        for base in &settings.user_bases {
            found.extend(search(ldap, base, Scope::Subtree, &filter, &attributes).await?);
            if found.len() > 1 {
                break;
            }
        }
        match found.len() {
            0 => Ok(None),
            1 => Ok(Some(found.remove(0))),
            _ => Err(LdapError::Ambiguous(username.to_owned())),
        }
    }

    /// The DNs of the groups the group search filter finds for the user.
    async fn groups(
        &self,
        ldap: &mut Ldap,
        username: &str,
        user_dn: &str,
    ) -> Result<Vec<String>, LdapError> {
        let settings = self.settings();
        let Some(filter) = &settings.group_filter else {
            return Ok(Vec::new());
        };
        let filter = fill(filter, username, user_dn);
        let mut groups = Vec::new();
        for base in &settings.group_bases {
            for (dn, _) in search(ldap, base, Scope::Subtree, &filter, NO_ATTRIBUTES).await? {
                let dn = dn::normalize(&dn).map_err(LdapError::Failed)?;
                if !groups.contains(&dn) {
                    groups.push(dn);
                }
            }
        }
        Ok(groups)
    }

    /// Looks `dn` up, and checks it sits under the base DNs of `kind`.
    async fn look_up(
        &self,
        ldap: &mut Ldap,
        dn: &str,
        kind: Kind,
    ) -> Result<Option<Found>, LdapError> {
        let Some(actual) = exists(ldap, dn).await? else {
            return Ok(None);
        };
        let parsed = Dn::parse(&actual).map_err(LdapError::Failed)?;
        let bases = match kind {
            Kind::User => &self.checked.user_bases,
            Kind::Group => &self.checked.group_bases,
        };
        Ok(Some(Found {
            dn: parsed.to_string(),
            under_base: bases.iter().any(|b| b.is_ancestor_of(&parsed)),
        }))
    }

    /// A connection to the first server that answers.
    async fn connect(&self) -> Result<Ldap, LdapError> {
        let settings = self.settings();
        let addresses = match settings.srv {
            None => vec![settings.server.clone()],
            Some(srv) => srv_addresses(srv, &settings.server).await?,
        };
        let mut errors = Vec::new();
        for address in &addresses {
            let mut ldap_settings = LdapConnSettings::new()
                .set_conn_timeout(CONNECT_TIMEOUT)
                .set_starttls(settings.transport == Transport::StartTls);
            if let Some(tls) = &self.checked.tls {
                ldap_settings = ldap_settings.set_config(Arc::clone(tls));
            }
            if settings.skip_verify {
                ldap_settings = ldap_settings.set_no_tls_verify(true);
            }
            let url = settings.url(address);
            let connected = tokio::time::timeout(
                CONNECT_TIMEOUT * 2,
                LdapConnAsync::with_settings(ldap_settings, &url),
            )
            .await;
            match connected {
                Ok(Ok((conn, ldap))) => {
                    tokio::spawn(async move {
                        if let Err(e) = conn.drive().await {
                            tracing::debug!(error = %e, "an LDAP connection ended");
                        }
                    });
                    return Ok(ldap);
                }
                Ok(Err(e)) => errors.push(format!("{address}: {}", describe(&e))),
                Err(_) => errors.push(format!("{address}: no answer")),
            }
        }
        Err(LdapError::Unreachable(errors.join("; ")))
    }
}

/// An SRV record's server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Srv {
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) target: String,
    pub(crate) port: u16,
}

/// The servers' addresses, lowest priority first, then heaviest first (RFC 2782 says to
/// pick by weight at random; trying the heaviest first is what that favours).
pub(crate) fn in_order(mut records: Vec<Srv>) -> Vec<String> {
    records.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));
    records
        .iter()
        .map(|srv| format!("{}:{}", srv.target.trim_end_matches('.'), srv.port))
        .collect()
}

/// The directory's servers an SRV lookup lists, in the order they should be tried.
async fn srv_addresses(srv: SrvRecord, server: &str) -> Result<Vec<String>, LdapError> {
    let name = match srv {
        SrvRecord::On => server.to_owned(),
        SrvRecord::Ldap => format!("_ldap._tcp.{server}"),
        SrvRecord::Ldaps => format!("_ldaps._tcp.{server}"),
    };
    let unreachable = |e: &dyn std::fmt::Display| {
        LdapError::Unreachable(format!("the DNS SRV lookup of {name} failed: {e}"))
    };
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .map_err(|e| unreachable(&e))?
        .build()
        .map_err(|e| unreachable(&e))?;
    let lookup = resolver
        .srv_lookup(name.as_str())
        .await
        .map_err(|e| unreachable(&e))?;
    let addresses = in_order(
        lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::SRV(srv) => Some(Srv {
                    priority: srv.priority,
                    weight: srv.weight,
                    target: srv.target.to_utf8(),
                    port: srv.port,
                }),
                _ => None,
            })
            .collect(),
    );
    if addresses.is_empty() {
        return Err(LdapError::Unreachable(format!("{name} lists no server")));
    }
    Ok(addresses)
}

/// The entry at `dn` as the directory spells its DN; none when there's none.
async fn exists(ldap: &mut Ldap, dn: &str) -> Result<Option<String>, LdapError> {
    let mut found = search(ldap, dn, Scope::Base, "(objectClass=*)", NO_ATTRIBUTES).await?;
    Ok((found.len() == 1).then(|| found.remove(0).0))
}

/// The entries a search finds: each one's DN and attributes. A base that doesn't exist
/// finds nothing.
async fn search(
    ldap: &mut Ldap,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<(String, BTreeMap<String, Vec<String>>)>, LdapError> {
    let result = ldap
        .with_timeout(OPERATION_TIMEOUT)
        .search(base, scope, filter, attributes.to_vec())
        .await
        .and_then(ldap3::SearchResult::success);
    match result {
        Ok((entries, _)) => Ok(entries.into_iter().filter_map(entry).collect()),
        Err(e) if code(&e) == Some(NO_SUCH_OBJECT) && scope == Scope::Base => Ok(Vec::new()),
        Err(e) if code(&e) == Some(NO_SUCH_OBJECT) => Err(LdapError::Failed(format!(
            "the base DN {base} isn't in the directory"
        ))),
        Err(e) => Err(failed(&e)),
    }
}

/// A search result entry's DN and text attributes; none for a referral or an entry
/// that can't be read.
fn entry(entry: ResultEntry) -> Option<(String, BTreeMap<String, Vec<String>>)> {
    let mut parts = entry.0.match_id(4)?.expect_constructed()?.into_iter();
    let dn = String::from_utf8(parts.next()?.expect_primitive()?).ok()?;
    let mut attributes = BTreeMap::new();
    for attribute in parts.next()?.expect_constructed()? {
        let mut attribute = attribute.expect_constructed()?.into_iter();
        let name = String::from_utf8(attribute.next()?.expect_primitive()?).ok()?;
        let values: Vec<String> = attribute
            .next()?
            .expect_constructed()?
            .into_iter()
            .filter_map(|v| String::from_utf8(v.expect_primitive()?).ok())
            .collect();
        attributes.insert(name, values);
    }
    Some((dn, attributes))
}

async fn close(mut ldap: Ldap) {
    let _ = ldap.unbind().await;
}

fn code(e: &Ldap3Error) -> Option<u32> {
    match e {
        Ldap3Error::LdapResult { result } => Some(result.rc),
        _ => None,
    }
}

fn describe(e: &Ldap3Error) -> String {
    match e {
        Ldap3Error::LdapResult { result } if result.text.is_empty() => {
            format!("LDAP result code {}", result.rc)
        }
        Ldap3Error::LdapResult { result } => {
            format!("{} (LDAP result code {})", result.text, result.rc)
        }
        e => e.to_string(),
    }
}

fn failed(e: &Ldap3Error) -> LdapError {
    LdapError::Failed(describe(e))
}
