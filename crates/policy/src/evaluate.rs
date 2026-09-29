//! The decision, in AWS's order for requests within one account:
//!
//! 1. An explicit `Deny` in any policy that applies (identity, resource, permissions
//!    boundary, session) denies. Nothing overrides it.
//! 2. The account's root user is allowed everything else.
//! 3. A resource policy that allows the user or session **by name** allows. One that
//!    allows everyone (`"*"`) or a session's role allows if the permissions boundary and
//!    session policies (when there are any) also allow. One that names only the
//!    account allows nothing by itself.
//! 4. Otherwise an identity policy must allow, and the permissions boundary and
//!    session policies (when there are any) must too.
//! 5. Otherwise the request is implicitly denied.
//!
//! A role's trust policy is the exception AWS makes: it must allow the principal
//! itself. One that names the account allows if an identity policy allows too (as step
//! 4), but an identity policy alone never lets anyone assume a role the trust policy
//! doesn't name them or their account for.

use crate::{Kind, Policy, context::Context, policy::Grant};

/// A request to decide.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The action, `s3:GetObject` (from [`crate::authorizations`]).
    pub action: &'a str,
    /// The resource's ARN, `arn:aws:s3:::bucket/key` (see [`crate::object_arn`]).
    pub resource: &'a str,
    /// Who asks, and everything else a condition may test.
    pub context: &'a Context,
}

/// The policies that bear on a request.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policies<'a> {
    /// The principal's own policies: inline, attached, and its groups'. None for the
    /// root user and anonymous requests.
    pub identity: &'a [&'a Policy],
    /// The resource's policy (the bucket policy), if it has one.
    pub resource: Option<&'a Policy>,
    /// The principal's permissions boundary, if it has one.
    pub boundary: Option<&'a Policy>,
    /// A session's policies (or a service account's): `Some` limits the session to
    /// what one of them allows, even when that's an empty list.
    pub session: Option<&'a [&'a Policy]>,
}

/// What was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allowed.
    Allow,
    /// A policy's `Deny` applies.
    ExplicitDeny,
    /// Nothing allows it.
    ImplicitDeny,
}

impl Decision {
    /// Whether the request may go ahead.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Decides a request.
#[must_use]
pub fn evaluate(policies: &Policies<'_>, request: &Request<'_>) -> Decision {
    let denied = policies
        .identity
        .iter()
        .copied()
        .chain(policies.resource)
        .chain(policies.boundary)
        .chain(policies.session.unwrap_or_default().iter().copied())
        .any(|policy| policy.denies(request));
    if denied {
        return Decision::ExplicitDeny;
    }
    if request.context.principal().kind() == crate::PrincipalKind::Account {
        return Decision::Allow;
    }
    let limits_allow = || {
        policies
            .boundary
            .is_none_or(|boundary| boundary.allows(request))
            && policies
                .session
                .is_none_or(|session| session.iter().any(|policy| policy.allows(request)))
    };
    let identity_allows = || {
        policies
            .identity
            .iter()
            .any(|policy| policy.allows(request))
            && limits_allow()
    };
    let trust = policies
        .resource
        .is_some_and(|policy| policy.kind() == Kind::Trust);
    let allowed = match policies.resource.and_then(|policy| policy.grant(request)) {
        Some(Grant::Named) => true,
        Some(Grant::Limited) => limits_allow(),
        Some(Grant::Account) if trust => identity_allows(),
        Some(Grant::Account) | None => !trust && identity_allows(),
    };
    if allowed {
        Decision::Allow
    } else {
        Decision::ImplicitDeny
    }
}
