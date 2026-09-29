//! What authentication and authorization read on every request: access key → secret and
//! identity, built once per IAM change so requests never touch the database.

use std::{collections::HashMap, sync::Arc};

use teifs_policy::{Context, Decision, Policies, Policy, Principal, Request, evaluate};
use zeroize::Zeroizing;

use crate::state::State;

/// Who signed a request, and the policies that decide what they may do.
#[derive(Debug)]
pub struct Identity {
    principal: Principal,
    root: bool,
    tags: Box<[(String, String)]>,
    policies: Box<[Arc<Policy>]>,
    boundary: Option<Arc<Policy>>,
}

impl Identity {
    /// The principal, for the request's context.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Whether this is the account's root user, whom no policy restricts.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.root
    }

    /// The user's tags (`aws:PrincipalTag/…`).
    #[must_use]
    pub fn tags(&self) -> &[(String, String)] {
        &self.tags
    }

    /// The identity policies: the user's inline and attached policies and those of its
    /// groups.
    #[must_use]
    pub fn policies(&self) -> &[Arc<Policy>] {
        &self.policies
    }

    /// The permissions boundary, if the user has one.
    #[must_use]
    pub fn boundary(&self) -> Option<&Policy> {
        self.boundary.as_deref()
    }

    /// Whoever sends a request without signing it: no policies of its own, so only a
    /// resource policy that allows everyone lets it do anything.
    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            principal: Principal::anonymous(),
            root: false,
            tags: Box::default(),
            policies: Box::default(),
            boundary: None,
        }
    }

    /// Whether this identity may do `action` on `resource` in `context`: always for the
    /// root user, else as its policies and boundary decide.
    #[must_use]
    pub fn allows(&self, context: &Context, action: &str, resource: &str) -> bool {
        self.allows_with(context, action, resource, None)
    }

    /// [`Self::allows`], with the resource's own policy (a bucket policy) too: its
    /// `Deny` binds even the root user; its `Allow` grants as AWS's evaluation says.
    #[must_use]
    pub fn allows_with(
        &self,
        context: &Context,
        action: &str,
        resource: &str,
        resource_policy: Option<&Policy>,
    ) -> bool {
        self.decide(context, action, resource, resource_policy)
            .is_allowed()
    }

    /// The decision [`Self::allows_with`] makes, which tells an explicit `Deny` from
    /// nothing allowing the request (which an ACL may still allow).
    #[must_use]
    pub fn decide(
        &self,
        context: &Context,
        action: &str,
        resource: &str,
        resource_policy: Option<&Policy>,
    ) -> Decision {
        if self.root && resource_policy.is_none() {
            return Decision::Allow;
        }
        let policies: Vec<&Policy> = self.policies.iter().map(Arc::as_ref).collect();
        evaluate(
            &Policies {
                identity: &policies,
                resource: resource_policy,
                boundary: self.boundary(),
                session: None,
            },
            &Request {
                action,
                resource,
                context,
            },
        )
    }

    /// Whether the permissions boundary, if there is one, allows the request: what a
    /// grant to everyone (a public ACL) still needs, as a `"Principal": "*"` grant does.
    #[must_use]
    pub fn within_boundary(&self, context: &Context, action: &str, resource: &str) -> bool {
        self.boundary().is_none_or(|boundary| {
            evaluate(
                &Policies {
                    identity: &[boundary],
                    ..Policies::default()
                },
                &Request {
                    action,
                    resource,
                    context,
                },
            )
            .is_allowed()
        })
    }
}

/// An active access key's secret and whose it is.
#[derive(Clone)]
pub struct Credential {
    /// The secret key, to check the signature with.
    pub secret: Arc<Zeroizing<String>>,
    /// Who it belongs to.
    pub identity: Arc<Identity>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// The account's root access key.
pub struct RootKey {
    /// The access key id.
    pub access_key: String,
    /// The secret key.
    pub secret: Zeroizing<String>,
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootKey")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// Every active access key.
#[derive(Debug, Default)]
pub(crate) struct Snapshot {
    keys: HashMap<Box<str>, Credential>,
}

impl Snapshot {
    pub(crate) fn build(state: &State, root: Option<&RootKey>) -> Self {
        let mut keys = HashMap::with_capacity(state.keys.len() + 1);
        if let Some(root) = root {
            keys.insert(
                root.access_key.as_str().into(),
                Credential {
                    secret: Arc::new(root.secret.clone()),
                    identity: Arc::new(Identity {
                        principal: Principal::root(&state.account),
                        root: true,
                        tags: Box::default(),
                        policies: Box::default(),
                        boundary: None,
                    }),
                },
            );
        }
        let mut identities: HashMap<&str, Arc<Identity>> = HashMap::new();
        for key in state.keys.values().filter(|k| k.active) {
            if root.is_some_and(|r| r.access_key == key.id) {
                continue;
            }
            let identity = identities
                .entry(key.user.as_str())
                .or_insert_with(|| Arc::new(identity(state, &key.user)))
                .clone();
            keys.insert(
                key.id.as_str().into(),
                Credential {
                    secret: key.secret.clone(),
                    identity,
                },
            );
        }
        Self { keys }
    }

    pub(crate) fn credential(&self, access_key: &str) -> Option<Credential> {
        self.keys.get(access_key).cloned()
    }
}

fn identity(state: &State, user_id: &str) -> Identity {
    let user = &state.users[user_id];
    let managed = |ids: &std::collections::BTreeSet<String>| {
        ids.iter()
            .filter_map(|id| state.policies.get(id))
            .map(|p| p.default_document().policy.clone())
            .collect::<Vec<_>>()
    };
    let mut policies: Vec<Arc<Policy>> = user.inline.values().map(|d| d.policy.clone()).collect();
    policies.extend(managed(&user.attached));
    for group in state.groups_of(&user.id) {
        policies.extend(group.inline.values().map(|d| d.policy.clone()));
        policies.extend(managed(&group.attached));
    }
    Identity {
        principal: Principal::user(&state.account, &user.path, &user.name, &user.id),
        root: false,
        tags: user.tags.clone().into_boxed_slice(),
        policies: policies.into_boxed_slice(),
        boundary: user
            .boundary
            .as_ref()
            .and_then(|id| state.policies.get(id))
            .map(|p| p.default_document().policy.clone()),
    }
}
