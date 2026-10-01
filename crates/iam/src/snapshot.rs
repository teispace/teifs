//! What authentication and authorization read on every request: access key → secret and
//! identity, and what a session's token is turned into an identity with, built once per
//! IAM change so requests never touch the database.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, RwLock},
};

use teifs_policy::{
    Context, Date, Decision, Kind as PolicyKind, Policies, Policy, Principal, Request, TagKind,
    evaluate,
};
use zeroize::Zeroizing;

use crate::{
    sessions::{Claims, WebClaims, Who},
    state::{LdapSeen, State},
};

/// Who signed a request, and the policies that decide what they may do.
#[derive(Debug, Clone)]
pub struct Identity {
    principal: Principal,
    root: bool,
    tags: Box<[(String, String)]>,
    policies: Box<[Arc<Policy>]>,
    boundary: Option<Arc<Policy>>,
    /// The IAM user or role it acts as (ARN, unique id): what a trust policy's bindings
    /// are checked against.
    entity: Option<(Box<str>, Box<str>)>,
    session: Option<Session>,
}

/// What temporary credentials add to an identity.
#[derive(Debug, Clone)]
pub struct Session {
    kind: SessionKind,
    /// `Some` limits the session to what one of these allows, even when there are none.
    policies: Option<Box<[Arc<Policy>]>>,
    issued: i64,
    expires: i64,
    source_identity: Option<Box<str>>,
    /// The session tags that pass on to the sessions it starts.
    transitive: Box<[(String, String)]>,
    /// The web identity that started it, whose provider's keys its requests have.
    web: Option<Box<WebClaims>>,
    /// The directory user it acts for, whose `ldap:` keys its requests have.
    ldap: Option<Box<LdapClaims>>,
}

/// What an LDAP session's requests know of its user: MinIO's `ldap:user` (the DN),
/// `ldap:username` and `ldap:groups`.
#[derive(Debug, Clone)]
struct LdapClaims {
    dn: String,
    username: String,
    groups: Vec<String>,
}

/// How a session was made, which decides the APIs it may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// `AssumeRole`; `chained` when another role's session assumed it.
    Role {
        /// Started by a role's session.
        chained: bool,
    },
    /// `GetSessionToken`: without MFA, no IAM API and, of STS, only `AssumeRole` and
    /// `GetCallerIdentity`.
    SessionToken,
    /// `GetFederationToken`: no IAM API and, of STS, only `GetCallerIdentity`.
    Federated,
    /// MinIO's `AssumeRole` without a role: the user's own permissions, narrowed by the
    /// session policy if there is one.
    User,
    /// MinIO's `AssumeRoleWithWebIdentity` without a role: the managed policies a web
    /// identity token's policy claim names, narrowed by the session policy if there is
    /// one.
    Web,
    /// MinIO's `AssumeRoleWithLDAPIdentity`: the managed policies mapped to the
    /// directory user and its groups, narrowed by the session policy if there is one.
    Ldap,
}

impl Session {
    /// How it was made.
    #[must_use]
    pub const fn kind(&self) -> SessionKind {
        self.kind
    }

    /// When its credentials were issued (`aws:TokenIssueTime`).
    #[must_use]
    pub fn issued(&self) -> Date {
        Date::from_unix_seconds(self.issued)
    }

    /// When its credentials expire, in seconds since the Unix epoch.
    #[must_use]
    pub const fn expires(&self) -> i64 {
        self.expires
    }

    /// Who it says started it (`aws:SourceIdentity`), which sessions it starts keep.
    #[must_use]
    pub fn source_identity(&self) -> Option<&str> {
        self.source_identity.as_deref()
    }

    /// The session tags that pass on to the sessions it starts.
    #[must_use]
    pub fn transitive_tags(&self) -> &[(String, String)] {
        &self.transitive
    }

    /// Whether it may call the IAM API (and TeiFS's admin API): not without MFA, which
    /// TeiFS doesn't have, so only role sessions (and MinIO's) may.
    #[must_use]
    pub const fn may_manage(&self) -> bool {
        matches!(
            self.kind,
            SessionKind::Role { .. } | SessionKind::User | SessionKind::Web | SessionKind::Ldap
        )
    }
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

    /// The principal's tags (`aws:PrincipalTag/…`): a user's, or a role's with the
    /// session's over them.
    #[must_use]
    pub fn tags(&self) -> &[(String, String)] {
        &self.tags
    }

    /// The identity policies: the user's inline and attached policies and those of its
    /// groups, or the role's.
    #[must_use]
    pub fn policies(&self) -> &[Arc<Policy>] {
        &self.policies
    }

    /// The permissions boundary, if the user or role has one.
    #[must_use]
    pub fn boundary(&self) -> Option<&Policy> {
        self.boundary.as_deref()
    }

    /// The session, for temporary credentials.
    #[must_use]
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// The IAM user or role it acts as: its ARN and unique id.
    pub(crate) fn entity(&self) -> Option<(&str, &str)> {
        self.entity.as_ref().map(|(arn, id)| (&**arn, &**id))
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
            entity: None,
            session: None,
        }
    }

    /// An AWS service acting for the account (S3's log delivery, `logging.s3.amazonaws.com`):
    /// no policies of its own, so only a resource policy naming it, or an ACL granting its
    /// group, lets it do anything.
    #[must_use]
    pub fn service(name: &str) -> Self {
        Self {
            principal: Principal::service(name),
            ..Self::anonymous()
        }
    }

    /// What a condition may test about any request of this identity's at `now`: the
    /// principal, its tags, and a session's issue time and source identity. The caller
    /// adds the connection and the request.
    #[must_use]
    pub fn context(&self, now: Date) -> Context {
        let mut context = Context::new(self.principal.clone(), now);
        for (key, value) in self.tags() {
            context = context.with_tag(TagKind::Principal, key, value);
        }
        if let Some(session) = &self.session {
            context = context.with_token_issue_time(session.issued());
            if let Some(source) = session.source_identity() {
                context = context.with_source_identity(source);
            }
            if let Some(web) = &session.web {
                let key = |name: &str| format!("{}:{name}", web.prefix());
                context = context
                    .with_claim(&key("aud"), web.aud.as_str())
                    .with_claim(&key("sub"), web.sub.as_str());
                if !web.amr.is_empty() {
                    context = context.with_claim(&key("amr"), web.amr.clone());
                }
            }
            if let Some(ldap) = &session.ldap {
                context = context
                    .with_claim("ldap:user", ldap.dn.as_str())
                    .with_claim("ldap:username", ldap.username.as_str())
                    .with_claim("ldap:groups", ldap.groups.clone());
            }
        }
        context
    }

    /// Whether this identity may do `action` on `resource` in `context`: always for the
    /// root user, else as its policies, boundary and session policies decide.
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
        let session = self.session_policies();
        if self.root && resource_policy.is_none() && session.is_none() {
            return Decision::Allow;
        }
        let policies: Vec<&Policy> = self.policies.iter().map(Arc::as_ref).collect();
        evaluate(
            &Policies {
                identity: &policies,
                resource: resource_policy,
                boundary: self.boundary(),
                session: session.as_deref(),
            },
            &Request {
                action,
                resource,
                context,
            },
        )
    }

    /// Whether the permissions boundary and session policies, where there are any,
    /// allow the request: what a grant to everyone (a public ACL) still needs, as a
    /// `"Principal": "*"` grant does.
    #[must_use]
    pub fn within_boundary(&self, context: &Context, action: &str, resource: &str) -> bool {
        let request = Request {
            action,
            resource,
            context,
        };
        let boundary = self.boundary().is_none_or(|boundary| {
            evaluate(
                &Policies {
                    identity: &[boundary],
                    ..Policies::default()
                },
                &request,
            )
            .is_allowed()
        });
        boundary
            && self.session_policies().is_none_or(|session| {
                session.iter().any(|policy| {
                    evaluate(
                        &Policies {
                            identity: &[policy],
                            ..Policies::default()
                        },
                        &request,
                    )
                    .is_allowed()
                })
            })
    }

    /// Whether a policy that decides its requests (its own, its boundary, its session's)
    /// tests a tag of `kind`, which the caller then has to look up.
    #[must_use]
    pub fn tests_tags(&self, kind: TagKind) -> bool {
        let session = self.session.as_ref().and_then(|s| s.policies.as_deref());
        self.policies
            .iter()
            .chain(&self.boundary)
            .chain(session.into_iter().flatten())
            .any(|policy| policy.tests_tags(kind))
    }

    fn session_policies(&self) -> Option<Vec<&Policy>> {
        self.session
            .as_ref()
            .and_then(|s| s.policies.as_ref())
            .map(|policies| policies.iter().map(Arc::as_ref).collect())
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

/// What a role's sessions start from.
#[derive(Debug)]
struct RoleEntry {
    id: String,
    path: String,
    name: String,
    arn: String,
    tags: Box<[(String, String)]>,
    policies: Box<[Arc<Policy>]>,
    boundary: Option<Arc<Policy>>,
}

/// A session's token, and the identity built from it.
type Cached = (Box<str>, Arc<Identity>);

/// How many sessions' identities are kept between IAM changes; past it the cache
/// starts again, so a flood of sessions can't grow it without bound.
const SESSIONS_CACHED: usize = 4096;

/// Every active access key, and what sessions are built from.
#[derive(Debug)]
pub(crate) struct Snapshot {
    account: Arc<str>,
    keys: HashMap<Box<str>, Credential>,
    /// Every user's identity, by unique id.
    users: HashMap<Box<str>, Arc<Identity>>,
    /// Every role, by unique id.
    roles: HashMap<Box<str>, RoleEntry>,
    /// Every managed policy's default version, by unique id.
    managed: HashMap<Box<str>, Arc<Policy>>,
    /// Every OpenID Connect provider's unique id.
    providers: std::collections::HashSet<Box<str>>,
    /// The policies mapped to each LDAP DN.
    ldap_policies: HashMap<Box<str>, Box<[Arc<Policy>]>>,
    /// Directory users with live sessions, by DN.
    ldap_users: HashMap<Box<str>, Arc<LdapSeen>>,
    root: Arc<Identity>,
    /// Sessions' identities by access key id, until IAM next changes (a new snapshot).
    sessions: RwLock<HashMap<Box<str>, Cached>>,
}

/// A policy that allows everything: the root user's, for a federated user it starts,
/// whose session policies then decide.
static ALLOW_ALL: LazyLock<Arc<Policy>> = LazyLock::new(|| {
    Arc::new(
        Policy::parse(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            PolicyKind::Identity,
        )
        .expect("the allow-all policy parses"),
    )
});

impl Snapshot {
    pub(crate) fn build(state: &State, root: Option<&RootKey>) -> Self {
        let root_identity = Arc::new(Identity {
            principal: Principal::root(&state.account),
            root: true,
            tags: Box::default(),
            policies: Box::default(),
            boundary: None,
            entity: None,
            session: None,
        });
        let users: HashMap<Box<str>, Arc<Identity>> = state
            .users
            .keys()
            .map(|id| (id.as_str().into(), Arc::new(identity(state, id))))
            .collect();
        let mut keys = HashMap::with_capacity(state.keys.len() + 1);
        if let Some(root) = root {
            keys.insert(
                root.access_key.as_str().into(),
                Credential {
                    secret: Arc::new(root.secret.clone()),
                    identity: Arc::clone(&root_identity),
                },
            );
        }
        for key in state.keys.values().filter(|k| k.active) {
            if root.is_some_and(|r| r.access_key == key.id) {
                continue;
            }
            if let Some(identity) = users.get(key.user.as_str()) {
                keys.insert(
                    key.id.as_str().into(),
                    Credential {
                        secret: key.secret.clone(),
                        identity: Arc::clone(identity),
                    },
                );
            }
        }
        let roles = state
            .roles
            .values()
            .map(|role| {
                let entry = RoleEntry {
                    id: role.id.clone(),
                    path: role.path.clone(),
                    name: role.name.clone(),
                    arn: state.role_arn(role),
                    tags: role.tags.clone().into_boxed_slice(),
                    policies: policies_of(state, &role.inline, &role.attached).into(),
                    boundary: boundary_of(state, role.boundary.as_deref()),
                };
                (role.id.as_str().into(), entry)
            })
            .collect();
        let managed = state
            .policies
            .iter()
            .map(|(id, p)| (id.as_str().into(), p.default_document().policy.clone()))
            .collect();
        let providers = state
            .oidc_providers
            .keys()
            .map(|id| id.as_str().into())
            .collect();
        let ldap_policies = state
            .ldap_policies
            .values()
            .map(|m| {
                let policies: Box<[Arc<Policy>]> = m
                    .policies
                    .iter()
                    .filter_map(|id| state.policies.get(id))
                    .map(|p| p.default_document().policy.clone())
                    .collect();
                (m.dn.as_str().into(), policies)
            })
            .collect();
        let ldap_users = state
            .ldap_sessions
            .values()
            .map(|seen| (seen.dn.as_str().into(), Arc::clone(seen)))
            .collect();
        Self {
            account: Arc::clone(&state.account),
            keys,
            users,
            roles,
            managed,
            providers,
            ldap_policies,
            ldap_users,
            root: root_identity,
            sessions: RwLock::default(),
        }
    }

    pub(crate) fn credential(&self, access_key: &str) -> Option<Credential> {
        self.keys.get(access_key).cloned()
    }

    /// The identity already built for the session with access key `id` from this very
    /// `token`.
    pub(crate) fn cached_session(&self, id: &str, token: &str) -> Option<Arc<Identity>> {
        self.sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .filter(|(from, _)| **from == *token)
            .map(|(_, identity)| Arc::clone(identity))
    }

    /// The identity of the session with access key `id`, whose `token` said `claims`:
    /// none if the user or role it acts as is gone, or a session policy no longer
    /// parses (fail closed).
    pub(crate) fn add_session(
        &self,
        id: &str,
        token: &str,
        claims: &Claims,
    ) -> Option<Arc<Identity>> {
        let identity = Arc::new(self.build_session(claims)?);
        let mut sessions = self
            .sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sessions.len() >= SESSIONS_CACHED {
            sessions.clear();
        }
        sessions.insert(id.into(), (token.into(), Arc::clone(&identity)));
        Some(identity)
    }

    fn build_session(&self, claims: &Claims) -> Option<Identity> {
        let session_policies = claims
            .policies
            .iter()
            .map(|text| Policy::parse(text, PolicyKind::Identity).ok().map(Arc::new))
            .collect::<Option<Box<[_]>>>()?;
        let transitive: Box<[(String, String)]> = claims
            .tags
            .iter()
            .filter(|(key, _)| {
                claims
                    .transitive
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(key))
            })
            .cloned()
            .collect();
        let session = |kind, scoped: bool| Session {
            kind,
            policies: (scoped || !session_policies.is_empty()).then(|| session_policies.clone()),
            issued: claims.iat,
            expires: claims.exp,
            source_identity: claims.source.as_deref().map(Into::into),
            transitive: transitive.clone(),
            web: claims.web.clone().map(Box::new),
            ldap: None,
        };
        Some(match &claims.who {
            Who::Role {
                role,
                name,
                chained,
            } => {
                let role = self.roles.get(role.as_str())?;
                let mut principal =
                    Principal::session(&self.account, &role.path, &role.name, &role.id, name);
                if let Some(web) = &claims.web {
                    principal = principal.with_federated_provider(&web.provider);
                }
                Identity {
                    principal,
                    root: false,
                    tags: merged(&role.tags, &claims.tags),
                    policies: role.policies.clone(),
                    boundary: role.boundary.clone(),
                    entity: Some((role.arn.as_str().into(), role.id.as_str().into())),
                    session: Some(session(SessionKind::Role { chained: *chained }, false)),
                }
            }
            Who::SessionToken { user } => {
                let base = match user {
                    Some(user) => self.users.get(user.as_str())?,
                    None => &self.root,
                };
                Identity {
                    session: Some(session(SessionKind::SessionToken, false)),
                    ..Identity::clone(base)
                }
            }
            Who::User { user } => Identity {
                session: Some(session(SessionKind::User, false)),
                ..Identity::clone(self.users.get(user.as_str())?)
            },
            Who::Web {
                provider,
                sub,
                policies,
            } => Identity {
                session: Some(session(SessionKind::Web, false)),
                ..self.web_identity(provider, sub, policies, claims.web.as_ref()?)?
            },
            Who::Ldap {
                dn,
                username,
                generation,
            } => {
                self.ldap_identity(dn, username, *generation, session(SessionKind::Ldap, false))?
            }
            Who::Federated { user, name } => {
                let (policies, boundary, tags) = match user {
                    Some(user) => {
                        let base = self.users.get(user.as_str())?;
                        (base.policies.clone(), base.boundary.clone(), &*base.tags)
                    }
                    None => (Box::from([Arc::clone(&ALLOW_ALL)]), None, &[][..]),
                };
                Identity {
                    principal: Principal::federated(&self.account, name),
                    root: false,
                    tags: merged(tags, &claims.tags),
                    policies,
                    boundary,
                    entity: None,
                    session: Some(session(SessionKind::Federated, true)),
                }
            }
        })
    }

    /// Whom MinIO's `AssumeRoleWithWebIdentity` without a role makes a session for:
    /// the web identity `sub` of the provider with unique id `provider`, with the
    /// managed policies (by unique id) its token named. A deleted provider takes its
    /// sessions with it; a deleted policy only its own permissions.
    /// An LDAP user's session: the policies mapped to its DN and to its groups' as the
    /// directory last said, while it's of the user's current generation.
    fn ldap_identity(
        &self,
        dn: &str,
        username: &str,
        generation: u32,
        base: Session,
    ) -> Option<Identity> {
        let seen = self.ldap_users.get(dn)?;
        if seen.generation != generation {
            return None;
        }
        let policies = std::iter::once(dn)
            .chain(seen.groups.iter().map(String::as_str))
            .filter_map(|dn| self.ldap_policies.get(dn))
            .flat_map(|p| p.iter().cloned())
            .collect();
        Some(Identity {
            principal: Principal::federated(&self.account, username),
            root: false,
            tags: Box::default(),
            policies,
            boundary: None,
            entity: None,
            session: Some(Session {
                ldap: Some(Box::new(LdapClaims {
                    dn: dn.to_owned(),
                    username: username.to_owned(),
                    groups: seen.groups.clone(),
                })),
                ..base
            }),
        })
    }

    fn web_identity(
        &self,
        provider: &str,
        sub: &str,
        policies: &[String],
        web: &crate::sessions::WebClaims,
    ) -> Option<Identity> {
        if !self.providers.contains(provider) {
            return None;
        }
        Some(Identity {
            principal: Principal::web_identity(&web.provider, sub).in_account(&self.account),
            root: false,
            tags: Box::default(),
            policies: policies
                .iter()
                .filter_map(|id| self.managed.get(id.as_str()))
                .cloned()
                .collect(),
            boundary: None,
            entity: None,
            session: None,
        })
    }
}

/// A user's or role's tags with a session's over them: a session tag replaces the tag
/// with its key, in any case.
fn merged(base: &[(String, String)], session: &[(String, String)]) -> Box<[(String, String)]> {
    base.iter()
        .filter(|(key, _)| !session.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)))
        .chain(session)
        .cloned()
        .collect()
}

/// The identity policies of an owner's inline and attached policies.
fn policies_of(
    state: &State,
    inline: &std::collections::BTreeMap<String, crate::state::Document>,
    attached: &std::collections::BTreeSet<String>,
) -> Vec<Arc<Policy>> {
    inline
        .values()
        .map(|d| d.policy.clone())
        .chain(
            attached
                .iter()
                .filter_map(|id| state.policies.get(id))
                .map(|p| p.default_document().policy.clone()),
        )
        .collect()
}

fn boundary_of(state: &State, id: Option<&str>) -> Option<Arc<Policy>> {
    id.and_then(|id| state.policies.get(id))
        .map(|p| p.default_document().policy.clone())
}

fn identity(state: &State, user_id: &str) -> Identity {
    let user = &state.users[user_id];
    let mut policies = policies_of(state, &user.inline, &user.attached);
    for group in state.groups_of(&user.id) {
        policies.extend(policies_of(state, &group.inline, &group.attached));
    }
    Identity {
        principal: Principal::user(&state.account, &user.path, &user.name, &user.id),
        root: false,
        tags: user.tags.clone().into_boxed_slice(),
        policies: policies.into_boxed_slice(),
        boundary: boundary_of(state, user.boundary.as_deref()),
        entity: Some((state.user_arn(user).into(), user.id.as_str().into())),
        session: None,
    }
}
