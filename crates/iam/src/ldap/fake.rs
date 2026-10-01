//! A fake LDAP server for tests: an in-memory tree under `dc=min,dc=io`, simple binds,
//! and searches with the filters TeiFS sends. It takes an empty password as an
//! unauthenticated bind, as real servers do, so tests show TeiFS refuses those itself.

#![allow(
    clippy::unwrap_used,
    reason = "a test double: anything unexpected fails the test that uses it"
)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use futures::{SinkExt, StreamExt};
use ldap3_proto::{
    LdapCodec, LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
    LdapSearchScope,
    simple::{SearchRequest, ServerOps},
};
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite};
use zeroize::Zeroizing;

use super::{Directory, LdapSettings, Transport, dn::Dn};

/// An entry: its DN, attributes and password.
#[derive(Debug, Clone)]
pub struct Entry {
    dn: String,
    attributes: Vec<(String, Vec<String>)>,
    password: Option<String>,
}

/// A person `uid` under `ou=OU,dc=min,dc=io`, whose password is `UID-password`.
#[must_use]
pub fn person(uid: &str, ou: &str) -> Entry {
    Entry {
        dn: format!("uid={},ou={ou},dc=min,dc=io", ldap3::dn_escape(uid)),
        attributes: vec![
            ("objectClass".into(), vec!["inetOrgPerson".into()]),
            ("uid".into(), vec![uid.into()]),
            ("mail".into(), vec![format!("{uid}@min.io")]),
        ],
        password: Some(format!("{uid}-password")),
    }
}

/// A group `cn` under `ou=groups,dc=min,dc=io`, with these people of `ou=people` as
/// members (`member` holds their DNs, `memberUid` their names).
#[must_use]
pub fn group(cn: &str, members: &[&str]) -> Entry {
    Entry {
        dn: format!("cn={cn},ou=groups,dc=min,dc=io"),
        attributes: vec![
            ("objectClass".into(), vec!["groupOfNames".into()]),
            ("cn".into(), vec![cn.into()]),
            (
                "member".into(),
                members
                    .iter()
                    .map(|m| format!("uid={m},ou=people,dc=min,dc=io"))
                    .collect(),
            ),
            (
                "memberUid".into(),
                members.iter().map(|m| (*m).to_owned()).collect(),
            ),
        ],
        password: None,
    }
}

fn container(dn: &str) -> Entry {
    Entry {
        dn: dn.into(),
        attributes: vec![("objectClass".into(), vec!["organizationalUnit".into()])],
        password: None,
    }
}

/// A fake directory: `dc=min,dc=io` with people, groups and a lookup account
/// (`cn=admin,dc=min,dc=io`, password `lookup-password`).
#[derive(Debug, Clone)]
pub struct FakeLdap {
    /// Where it listens.
    pub address: SocketAddr,
    entries: Arc<Mutex<Vec<Entry>>>,
}

impl FakeLdap {
    /// Starts the server on a free local port.
    pub async fn start() -> Self {
        let mut admin = container("cn=admin,dc=min,dc=io");
        admin.password = Some("lookup-password".into());
        let entries = vec![
            container("dc=min,dc=io"),
            admin,
            container("ou=people,dc=min,dc=io"),
            container("ou=groups,dc=min,dc=io"),
            container("ou=others,dc=min,dc=io"),
            person("dillon", "people"),
            person("liza", "people"),
            person("Smith, John", "people"),
            person("outsider", "others"),
            group("projecta", &["dillon"]),
            group("projectb", &["dillon", "liza"]),
        ];
        let entries = Arc::new(Mutex::new(entries));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tree = Arc::clone(&entries);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(serve(socket, Arc::clone(&tree)));
            }
        });
        Self { address, entries }
    }

    /// Adds an entry.
    pub fn add(&self, entry: Entry) {
        self.entries.lock().unwrap().push(entry);
    }

    /// Removes the entry at `dn`.
    pub fn remove(&self, dn: &str) {
        self.entries.lock().unwrap().retain(|e| e.dn != dn);
    }

    /// Settings for it: plain LDAP, users under `ou=people`, groups by `member`.
    #[must_use]
    pub fn settings(&self) -> LdapSettings {
        LdapSettings {
            server: self.address.to_string(),
            transport: Transport::Plain,
            lookup_dn: "cn=admin,dc=min,dc=io".into(),
            lookup_password: Some(Zeroizing::new("lookup-password".into())),
            user_bases: vec!["ou=people,dc=min,dc=io".into()],
            user_filter: "(uid=%s)".into(),
            user_attributes: vec!["mail".into()],
            group_bases: vec!["ou=groups,dc=min,dc=io".into()],
            group_filter: Some("(&(objectClass=groupOfNames)(member=%d))".into()),
            ..LdapSettings::default()
        }
    }

    /// A directory with [`Self::settings`].
    #[must_use]
    pub fn directory(&self) -> Directory {
        Directory::new(self.settings()).unwrap()
    }
}

async fn serve(socket: tokio::net::TcpStream, entries: Arc<Mutex<Vec<Entry>>>) {
    let (r, w) = tokio::io::split(socket);
    let mut requests = FramedRead::new(r, LdapCodec::default());
    let mut answers = FramedWrite::new(w, LdapCodec::default());
    while let Some(Ok(message)) = requests.next().await {
        let Ok(op) = ServerOps::try_from(message) else {
            return;
        };
        let replies = match op {
            ServerOps::SimpleBind(bind) => {
                let entries = entries.lock().unwrap();
                let ok = bind.pw.is_empty()
                    || entries
                        .iter()
                        .any(|e| same(&e.dn, &bind.dn) && e.password.as_deref() == Some(&bind.pw));
                vec![if ok {
                    bind.gen_success()
                } else {
                    bind.gen_invalid_cred()
                }]
            }
            ServerOps::Search(search) => answer(&search, &entries.lock().unwrap()),
            _ => return,
        };
        for reply in replies {
            if answers.send(reply).await.is_err() {
                return;
            }
        }
    }
}

fn same(a: &str, b: &str) -> bool {
    match (Dn::parse(a), Dn::parse(b)) {
        (Ok(a), Ok(b)) => a.same(&b),
        _ => false,
    }
}

fn answer(search: &SearchRequest, entries: &[Entry]) -> Vec<ldap3_proto::LdapMsg> {
    let Ok(base) = Dn::parse(&search.base) else {
        return vec![search.gen_error(LdapResultCode::InvalidDNSyntax, "bad DN".into())];
    };
    if !entries.iter().any(|e| same(&e.dn, &search.base)) {
        return vec![search.gen_error(LdapResultCode::NoSuchObject, String::new())];
    }
    let mut replies: Vec<_> = entries
        .iter()
        .filter(|e| {
            let dn = Dn::parse(&e.dn).unwrap();
            match search.scope {
                LdapSearchScope::Base => base.same(&dn),
                _ => base.same(&dn) || base.is_ancestor_of(&dn),
            }
        })
        .filter(|e| matches(&search.filter, e))
        .map(|e| {
            let wanted = |name: &str| search.attrs.iter().any(|a| a.eq_ignore_ascii_case(name));
            search.gen_result_entry(LdapSearchResultEntry {
                dn: e.dn.clone(),
                attributes: e
                    .attributes
                    .iter()
                    .filter(|(name, _)| wanted(name))
                    .map(|(name, values)| LdapPartialAttribute {
                        atype: name.clone(),
                        vals: values.iter().map(|v| v.as_bytes().to_vec()).collect(),
                    })
                    .collect(),
            })
        })
        .collect();
    replies.push(search.gen_success());
    replies
}

/// An entry's values of the attribute `name`.
fn values<'a>(entry: &'a Entry, name: &'a str) -> impl Iterator<Item = &'a String> {
    entry
        .attributes
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.iter())
}

fn matches(filter: &LdapFilter, entry: &Entry) -> bool {
    let values = |name| values(entry, name);
    match filter {
        LdapFilter::And(all) => all.iter().all(|f| matches(f, entry)),
        LdapFilter::Or(any) => any.iter().any(|f| matches(f, entry)),
        LdapFilter::Not(f) => !matches(f, entry),
        LdapFilter::Present(name) => values(name).next().is_some(),
        LdapFilter::Equality(name, value) => {
            values(name).any(|v| v.eq_ignore_ascii_case(value) || same(v, value))
        }
        _ => false,
    }
}
