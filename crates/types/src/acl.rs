//! Access control lists: S3's older grants on a bucket or an object, kept for buckets
//! whose Object Ownership setting enables them.
//!
//! A drive is one account, so the only canonical user a grant can name is the drive's
//! own ([`OWNER_ID`]); what else a grant can name are S3's predefined groups. The groups
//! of everyone ([`Grantee::AllUsers`]) and of every signed request
//! ([`Grantee::AuthenticatedUsers`]) change who may do what; the owner may do everything
//! anyway.

use serde::{Deserialize, Serialize};

/// The canonical user id of the drive's account: the owner of every bucket and object.
pub const OWNER_ID: &str = "teifs";

/// An access control list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acl {
    /// The grants, in the order they were given.
    pub grants: Vec<AclGrant>,
}

/// One grant: a permission for a grantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclGrant {
    /// Who.
    pub grantee: Grantee,
    /// What.
    pub permission: Permission,
}

/// Who a grant is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Grantee {
    /// The drive's account (canonical user [`OWNER_ID`]).
    Owner,
    /// Everyone, anonymous requests included (`…/groups/global/AllUsers`).
    AllUsers,
    /// Every AWS account (`…/groups/global/AuthenticatedUsers`).
    AuthenticatedUsers,
    /// S3's log delivery (`…/groups/s3/LogDelivery`).
    LogDelivery,
}

/// Who a request is from, as far as an ACL's groups tell callers apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclCaller {
    /// An unsigned request.
    Anonymous,
    /// A signed request.
    Signed,
    /// S3's log delivery writing access logs (an authenticated caller too).
    LogDelivery,
}

/// What a grant allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    /// Read the object, or list the bucket.
    Read,
    /// Write and delete the bucket's objects.
    Write,
    /// Read the ACL.
    ReadAcp,
    /// Change the ACL.
    WriteAcp,
    /// All of them.
    FullControl,
}

impl Grantee {
    /// The group's URI, for a group.
    #[must_use]
    pub const fn uri(self) -> Option<&'static str> {
        match self {
            Self::Owner => None,
            Self::AllUsers => Some("http://acs.amazonaws.com/groups/global/AllUsers"),
            Self::AuthenticatedUsers => {
                Some("http://acs.amazonaws.com/groups/global/AuthenticatedUsers")
            }
            Self::LogDelivery => Some("http://acs.amazonaws.com/groups/s3/LogDelivery"),
        }
    }

    /// The group a URI names.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        [Self::AllUsers, Self::AuthenticatedUsers, Self::LogDelivery]
            .into_iter()
            .find(|group| group.uri() == Some(uri))
    }
}

impl Permission {
    /// Every permission, as S3 names them.
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::ReadAcp,
        Self::WriteAcp,
        Self::FullControl,
    ];

    /// S3's name: `READ`, `WRITE`, `READ_ACP`, `WRITE_ACP`, `FULL_CONTROL`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::ReadAcp => "READ_ACP",
            Self::WriteAcp => "WRITE_ACP",
            Self::FullControl => "FULL_CONTROL",
        }
    }

    /// The permission S3 names so.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }
}

impl Acl {
    /// Only the owner, with full control: an object or bucket without an ACL of its own,
    /// and what reading an ACL answers while ACLs are disabled.
    #[must_use]
    pub fn private() -> Self {
        Self {
            grants: vec![AclGrant {
                grantee: Grantee::Owner,
                permission: Permission::FullControl,
            }],
        }
    }

    /// Whether it grants anything to everyone or to every AWS account: what S3's Block
    /// Public Access counts as public.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.grants
            .iter()
            .any(|g| matches!(g.grantee, Grantee::AllUsers | Grantee::AuthenticatedUsers))
    }

    /// Whether it grants only the owner: what a bucket needs to disable ACLs.
    #[must_use]
    pub fn owner_only(&self) -> bool {
        self.grants.iter().all(|g| g.grantee == Grantee::Owner)
    }

    /// Whether it gives `permission` (itself or by full control) to a caller other than
    /// the owner: to everyone, to every authenticated caller, or to S3's log delivery.
    /// Without `public`, grants to everyone and to every authenticated caller count for
    /// nothing (Block Public Access's `IgnorePublicAcls`).
    #[must_use]
    pub fn grants(&self, permission: Permission, caller: AclCaller, public: bool) -> bool {
        self.grants.iter().any(|g| {
            let to_caller = match g.grantee {
                Grantee::AllUsers => public,
                Grantee::AuthenticatedUsers => public && caller != AclCaller::Anonymous,
                Grantee::LogDelivery => caller == AclCaller::LogDelivery,
                Grantee::Owner => false,
            };
            to_caller && (g.permission == permission || g.permission == Permission::FullControl)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(grants: &[(Grantee, Permission)]) -> Acl {
        Acl {
            grants: grants
                .iter()
                .map(|&(grantee, permission)| AclGrant {
                    grantee,
                    permission,
                })
                .collect(),
        }
    }

    #[test]
    fn public_means_a_group_of_everyone() {
        use Grantee::{AllUsers, AuthenticatedUsers, LogDelivery, Owner};
        use Permission::{FullControl, Read, ReadAcp, Write};

        use AclCaller::{Anonymous, LogDelivery as Delivery, Signed};
        assert!(!Acl::private().is_public() && Acl::private().owner_only());
        assert!(acl(&[(Owner, FullControl), (AllUsers, Read)]).is_public());
        assert!(acl(&[(AuthenticatedUsers, Read)]).is_public());
        let logs = acl(&[(Owner, FullControl), (LogDelivery, Write)]);
        assert!(!logs.is_public() && !logs.owner_only());

        let read = acl(&[(AllUsers, Read)]);
        assert!([Anonymous, Signed, Delivery].iter().all(|&caller| {
            read.grants(Read, caller, true)
                && !read.grants(Write, caller, true)
                && !read.grants(Read, caller, false)
        }));
        let all = acl(&[(AllUsers, FullControl)]);
        assert!(
            Permission::ALL
                .iter()
                .all(|p| all.grants(*p, Anonymous, true))
        );
        let signed = acl(&[(AuthenticatedUsers, FullControl)]);
        assert!(signed.grants(Read, Signed, true) && signed.grants(Write, Delivery, true));
        assert!(!signed.grants(Read, Anonymous, true) && !signed.grants(Read, Signed, false));
        // The log delivery group isn't public: ignoring public grants leaves it.
        assert!(logs.grants(Write, Delivery, true) && logs.grants(Write, Delivery, false));
        assert!(!logs.grants(ReadAcp, Delivery, true));
        assert!(!logs.grants(Write, Signed, true) && !logs.grants(Write, Anonymous, true));
        let private = Acl::private();
        assert!(!private.grants(Read, Signed, true) && !private.grants(Read, Delivery, true));
    }

    #[test]
    fn names_round_trip() {
        for permission in Permission::ALL {
            assert_eq!(Permission::parse(permission.name()), Some(permission));
        }
        assert_eq!(Permission::parse("read"), None);
        for group in [
            Grantee::AllUsers,
            Grantee::AuthenticatedUsers,
            Grantee::LogDelivery,
        ] {
            assert_eq!(Grantee::from_uri(group.uri().unwrap()), Some(group));
        }
        assert_eq!(Grantee::Owner.uri(), None);
        assert_eq!(Grantee::from_uri("http://example.com/AllUsers"), None);
        let json = serde_json::to_string(&Acl::private()).unwrap();
        assert_eq!(
            json,
            r#"{"grants":[{"grantee":"owner","permission":"FULL_CONTROL"}]}"#
        );
        assert_eq!(serde_json::from_str::<Acl>(&json).unwrap(), Acl::private());
    }
}
