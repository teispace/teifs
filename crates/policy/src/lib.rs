//! The IAM policy language, as AWS defines it: parsing, conditions, policy variables and
//! evaluation, plus the table of which S3 actions each S3 operation needs.
//!
//! Pure: no I/O, no clock, no network. What a request is (who makes it, from where,
//! with which headers) comes only from a typed [`Context`] the caller builds, so a
//! policy can't read anything the server didn't deliberately put there.
//!
//! ```
//! use teifs_policy::{evaluate, Context, Date, Decision, Kind, Policies, Policy, Principal, Request};
//!
//! let policy = Policy::parse(
//!     r#"{"Version": "2012-10-17", "Statement": [{
//!         "Effect": "Allow",
//!         "Action": "s3:GetObject",
//!         "Resource": "arn:aws:s3:::photos/${aws:username}/*"
//!     }]}"#,
//!     Kind::Identity,
//! )?;
//! let alice = Principal::user("123456789012", "/", "alice", "AIDAALICE");
//! let context = Context::new(alice, Date::from_unix_seconds(1_800_000_000));
//! let request = |resource| Request { action: "s3:GetObject", resource, context: &context };
//! let policies = Policies { identity: &[&policy], ..Policies::default() };
//! assert_eq!(evaluate(&policies, &request("arn:aws:s3:::photos/alice/cat.jpg")), Decision::Allow);
//! assert_eq!(evaluate(&policies, &request("arn:aws:s3:::photos/bob/cat.jpg")), Decision::ImplicitDeny);
//! # Ok::<(), teifs_policy::Error>(())
//! ```

mod actions;
mod arn;
mod condition;
mod context;
mod evaluate;
mod json;
mod key;
mod pattern;
mod policy;
mod template;
mod value;

pub use actions::{
    ACTIONS, Authorization, Authorizations, Facts, MINIO_ACTIONS, Target, authorizations,
};
pub use arn::{S3_ACCOUNT_RESOURCE, bucket_arn, object_arn};
pub use context::{Context, Principal, PrincipalKind, Value};
pub use evaluate::{Decision, Policies, Request, evaluate};
pub use json::Json;
pub use key::{GlobalKey, IamKey, S3Key, StsKey, TagKind};
pub use policy::{Kind, Policy, Version};
pub use value::{Cidr, Date, Number};

/// A policy that isn't valid, and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The same error, said of `place` (a statement, an element).
    pub(crate) fn within(self, place: impl std::fmt::Display) -> Self {
        Self(format!("{place}: {}", self.0))
    }
}
