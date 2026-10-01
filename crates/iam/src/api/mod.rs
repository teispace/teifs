//! IAM's and STS's APIs as AWS has them: the Query protocol (`Action=CreateUser&UserName=…`
//! in a form body, answers in XML) for the actions TeiFS supports, so the AWS CLI and SDKs
//! manage a drive's IAM and get temporary credentials as they would from AWS.
//!
//! Every action is authorized before it runs, as on AWS: the caller's policies decide
//! the action on the resource's ARN, with the condition keys AWS's service reference
//! lists for it. A name given in another case resolves to the entity's own ARN first;
//! ARNs compare with case, so a Deny can't be dodged by spelling a name differently.

mod groups;
mod oidc;
mod params;
mod policies;
mod roles;
mod sts;
mod users;
mod xml;

use teifs_policy::{Context, IamKey, TagKind};
use zeroize::Zeroizing;

use crate::{
    Iam, IamError, Identity,
    ldap::{LdapError, SignedIn},
    rules, state,
};

use self::{
    params::{Page, Params, paged},
    xml::Xml,
};

/// A signed request to IAM's or STS's API.
#[derive(Debug)]
pub struct Call<'a> {
    /// Who signed it.
    pub identity: &'a Identity,
    /// What conditions may test about any request of theirs: the time, the connection,
    /// the principal's tags.
    pub context: &'a Context,
    /// The form body.
    pub body: &'a [u8],
    /// The id the answer gives the request.
    pub request_id: &'a str,
}

/// An answer: its HTTP status and XML body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The XML body.
    pub body: String,
}

const IAM_VERSION: &str = "2010-05-08";
const IAM_NAMESPACE: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
const STS_VERSION: &str = "2011-06-15";
const STS_NAMESPACE: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

impl Iam {
    /// Answers a request to the IAM API. Temporary credentials from
    /// `GetSessionToken` or `GetFederationToken` can't call it, as on AWS without MFA.
    #[must_use]
    pub fn serve_iam(&self, call: &Call<'_>) -> Reply {
        serve(call, IAM_VERSION, IAM_NAMESPACE, |name, params| {
            let action = find(ACTIONS, name, IAM_VERSION)?;
            if call.identity.session().is_some_and(|s| !s.may_manage()) {
                return Err(ApiError::invalid_token());
            }
            self.run(call, action, params, None)
        })
    }

    /// Answers a request to the STS API.
    #[must_use]
    pub fn serve_sts(&self, call: &Call<'_>) -> Reply {
        self.serve_sts_with(call, None)
    }

    /// [`Self::serve_sts`], with what the directory said of an LDAP sign-in.
    fn serve_sts_with(&self, call: &Call<'_>, ldap: Option<&Result<SignedIn, LdapError>>) -> Reply {
        serve(call, STS_VERSION, STS_NAMESPACE, |name, params| {
            let action = find(sts::ACTIONS, name, STS_VERSION)?;
            if let Some(session) = call.identity.session()
                && !sts::permitted(session.kind(), action.name)
            {
                return Err(ApiError::access_denied(format!(
                    "Cannot call {} with session credentials",
                    action.name
                )));
            }
            self.run(call, action, params, ldap)
        })
    }

    /// Whether a form is an STS request that carries its own proof of who is asking (a
    /// web identity token, or MinIO's LDAP user name and password): it's answered
    /// whether it's signed or not, as on AWS, and whoever signed it has no part in it.
    #[must_use]
    pub fn proves_itself(body: &[u8]) -> bool {
        Params::parse(body).is_ok_and(|p| {
            matches!(
                p.optional("Action"),
                Some(sts::WEB_IDENTITY | sts::LDAP_IDENTITY)
            )
        })
    }

    /// Answers a [`Self::proves_itself`] request, which `call` gives with the anonymous
    /// identity. For a web identity, first fetches the signing keys of the provider its
    /// token names, if they aren't known or the token is signed with a key that isn't;
    /// for an LDAP user, first asks the directory, unless the request is refused before.
    pub async fn serve_self_proving(&self, call: &Call<'_>) -> Reply {
        if let Some((username, password)) = self.ldap_sign_in(call) {
            let signed_in = match &self.ldap {
                Some(directory) => directory.sign_in(&username, &password).await,
                None => Err(LdapError::NotSetUp),
            };
            return self.serve_sts_with(call, Some(&signed_in));
        }
        if let Ok(params) = Params::parse(call.body)
            && let Some((iss, kid)) = params
                .optional("WebIdentityToken")
                .and_then(crate::oidc::issuer)
            && let Ok(Some((url, thumbprints))) = self.read(|s| {
                Ok(s.oidc_provider_by_issuer(&iss)
                    .map(|p| (p.url.clone(), p.thumbprints.clone())))
            })
        {
            self.web_keys
                .refresh(&url, &thumbprints, kid.as_deref())
                .await;
        }
        self.serve_sts(call)
    }

    /// The name and password of an LDAP sign-in to ask the directory about: none when
    /// the request isn't one, or the action refuses it before the directory is asked.
    fn ldap_sign_in(&self, call: &Call<'_>) -> Option<(String, Zeroizing<String>)> {
        let params = Params::parse(call.body).ok()?;
        if params.optional("Action") != Some(sts::LDAP_IDENTITY)
            || params.optional("Version").is_some_and(|v| v != STS_VERSION)
        {
            return None;
        }
        let run = Run {
            iam: self,
            identity: call.identity,
            base: call.context,
            p: params,
            account: self.account(),
            ldap: None,
        };
        let request = sts::ldap_request(&run).ok()?;
        Some((
            request.username.to_owned(),
            Zeroizing::new(request.password.to_owned()),
        ))
    }

    fn run(
        &self,
        call: &Call<'_>,
        action: &Action,
        params: Params,
        ldap: Option<&Result<SignedIn, LdapError>>,
    ) -> Result<(&'static str, Option<Xml>), ApiError> {
        let run = Run {
            iam: self,
            identity: call.identity,
            base: call.context,
            p: params,
            account: self.account(),
            ldap,
        };
        (action.run)(&run).map(|result| (action.name, result))
    }
}

/// The action called `name` in `actions`.
fn find<'a>(actions: &'a [Action], name: &str, version: &str) -> Result<&'a Action, ApiError> {
    actions
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| ApiError::invalid_action(name, version))
}

/// Parses the form, runs the action `f` finds, and writes the answer or the error.
fn serve(
    call: &Call<'_>,
    version: &str,
    namespace: &str,
    f: impl FnOnce(&str, Params) -> Result<(&'static str, Option<Xml>), ApiError>,
) -> Reply {
    let outcome = Params::parse(call.body).and_then(|params| {
        let action = params
            .optional("Action")
            .ok_or_else(ApiError::missing_action)?
            .to_owned();
        if let Some(given) = params.optional("Version")
            && given != version
        {
            return Err(ApiError::invalid_action(&action, given));
        }
        f(&action, params)
    });
    match outcome {
        Ok((action, result)) => {
            let mut x = Xml::new();
            x.el(&format!("{action}Response"), |x| {
                if let Some(result) = result {
                    x.el(&format!("{action}Result"), |x| {
                        x.raw(&result);
                    });
                }
                x.el("ResponseMetadata", |x| {
                    x.text("RequestId", call.request_id);
                });
            });
            Reply {
                status: 200,
                body: document(x, namespace),
            }
        }
        Err(err) => {
            let mut x = Xml::new();
            x.el("ErrorResponse", |x| {
                x.el("Error", |x| {
                    x.text(
                        "Type",
                        if err.status >= 500 {
                            "Receiver"
                        } else {
                            "Sender"
                        },
                    )
                    .text("Code", err.code)
                    .text("Message", &err.message);
                })
                .text("RequestId", call.request_id);
            });
            Reply {
                status: err.status,
                body: document(x, namespace),
            }
        }
    }
}

/// The XML declaration, and the namespace on the root element.
fn document(x: Xml, namespace: &str) -> String {
    let body = x.into_string();
    let split = body.find('>').unwrap_or(body.len());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{} xmlns=\"{namespace}\"{}",
        &body[..split],
        &body[split..]
    )
}

/// Why an API request failed: AWS's status, code and message.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: u16,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn validation(message: String) -> Self {
        Self {
            status: 400,
            code: "ValidationError",
            message,
        }
    }

    /// A required parameter is missing, as AWS words it (`userName`).
    pub(crate) fn missing(name: &str) -> Self {
        Self::validation(format!(
            "1 validation error detected: Value null at '{}' failed to satisfy constraint: \
             Member must not be null",
            camel(name)
        ))
    }

    /// A parameter's value breaks a constraint, as AWS words it.
    pub(crate) fn constraint(name: &str, value: &str, constraint: &str) -> Self {
        Self::validation(format!(
            "1 validation error detected: Value '{value}' at '{}' failed to satisfy \
             constraint: {constraint}",
            camel(name)
        ))
    }

    pub(crate) fn access_denied(message: String) -> Self {
        Self {
            status: 403,
            code: "AccessDenied",
            message,
        }
    }

    /// Temporary credentials that may not call the API at all.
    fn invalid_token() -> Self {
        Self {
            status: 403,
            code: "InvalidClientTokenId",
            message: "The security token included in the request is invalid".into(),
        }
    }

    /// A parameter that can't be used, as MinIO answers it.
    pub(crate) fn invalid_parameter(message: String) -> Self {
        Self {
            status: 400,
            code: "InvalidParameterValue",
            message,
        }
    }

    pub(crate) fn invalid_value(name: &str, value: &str) -> Self {
        Self::validation(format!("Invalid value '{value}' for {name}."))
    }

    fn missing_action() -> Self {
        Self {
            status: 400,
            code: "MissingAction",
            message: "Missing Action".into(),
        }
    }

    fn invalid_action(action: &str, version: &str) -> Self {
        Self {
            status: 400,
            code: "InvalidAction",
            message: format!("Could not find operation {action} for version {version}"),
        }
    }

    fn denied(identity: &Identity, action: &str, resource: &str) -> Self {
        let who = identity.principal().arn().unwrap_or("anonymous");
        Self::access_denied(format!(
            "User: {who} is not authorized to perform: {action} on resource: {resource}"
        ))
    }
}

/// A parameter's name as AWS's messages give it: `userName`.
fn camel(name: &str) -> String {
    let mut chars = name.chars();
    chars
        .next()
        .map(|c| c.to_ascii_lowercase())
        .into_iter()
        .chain(chars)
        .collect()
}

impl From<IamError> for ApiError {
    fn from(err: IamError) -> Self {
        let status = err.status();
        let message = if status >= 500 {
            tracing::error!(error = %err, "an IAM request failed");
            "The request processing has failed because of an unknown error, exception or \
             failure."
                .to_owned()
        } else {
            err.to_string()
        };
        Self {
            status,
            code: err.code(),
            message,
        }
    }
}

type Out = Result<Option<Xml>, ApiError>;

/// An answer with a result element, which `f` writes.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every action answers through the same type"
)]
fn answer(f: impl FnOnce(&mut Xml)) -> Out {
    let mut x = Xml::new();
    f(&mut x);
    Ok(Some(x))
}

/// An answer with no result element.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every action answers through the same type"
)]
fn done() -> Out {
    Ok(None)
}

/// `IsTruncated` and, when it is, the `Marker` of the next page.
fn truncation(x: &mut Xml, marker: Option<&str>) {
    x.boolean("IsTruncated", marker.is_some())
        .maybe("Marker", marker);
}

/// What kind of resource an action is on, as the service reference names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum On {
    /// `*`: the action names no resource (`ListUsers`).
    Any,
    User,
    Group,
    Role,
    Policy,
    OidcProvider,
    /// STS's `federated-user`.
    FederatedUser,
}

/// An action the API answers.
struct Action {
    name: &'static str,
    on: On,
    /// The condition keys the action sets besides the resource's tags.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "checked against AWS's reference")
    )]
    keys: &'static [&'static str],
    run: fn(&Run<'_>) -> Out,
}

const TAGGING: &[&str] = &["aws:RequestTag/${TagKey}", "aws:TagKeys"];
const TAG_KEYS: &[&str] = &["aws:TagKeys"];
const BOUNDARY: &[&str] = &["iam:PermissionsBoundary"];
const POLICY_ARN: &[&str] = &["iam:PolicyARN"];
const BOUNDARY_AND_POLICY_ARN: &[&str] = &["iam:PermissionsBoundary", "iam:PolicyARN"];
/// Roles' actions also name `iam:RoleTemplateARN`, which no TeiFS role has.
const BOUNDARY_TEMPLATE: &[&str] = &["iam:PermissionsBoundary", "iam:RoleTemplateARN"];
const CREATE_ROLE: &[&str] = &[
    "aws:RequestTag/${TagKey}",
    "aws:TagKeys",
    "iam:PermissionsBoundary",
    "iam:RoleTemplateARN",
];
const ATTACH_ROLE: &[&str] = &[
    "iam:PermissionsBoundary",
    "iam:PolicyARN",
    "iam:RoleTemplateARN",
];
const TAG_ROLE: &[&str] = &[
    "aws:RequestTag/${TagKey}",
    "aws:TagKeys",
    "iam:RoleTemplateARN",
];

macro_rules! actions {
    ($($name:ident: $on:ident, $keys:expr, $run:path;)*) => {
        const ACTIONS: &[Action] = &[$(Action {
            name: stringify!($name),
            on: On::$on,
            keys: $keys,
            run: $run,
        }),*];
    };
}

actions! {
    CreateUser: User, &["aws:RequestTag/${TagKey}", "aws:TagKeys", "iam:PermissionsBoundary"], users::create;
    GetUser: User, &[], users::get;
    ListUsers: Any, &[], users::list;
    UpdateUser: User, &[], users::update;
    DeleteUser: User, &[], users::delete;
    TagUser: User, TAGGING, users::tag;
    UntagUser: User, TAG_KEYS, users::untag;
    ListUserTags: User, &[], users::list_tags;
    PutUserPermissionsBoundary: User, BOUNDARY, users::put_boundary;
    DeleteUserPermissionsBoundary: User, BOUNDARY, users::delete_boundary;
    CreateAccessKey: User, &[], users::create_key;
    ListAccessKeys: User, &[], users::list_keys;
    UpdateAccessKey: User, &[], users::update_key;
    DeleteAccessKey: User, &[], users::delete_key;
    GetAccessKeyLastUsed: User, &[], users::key_last_used;
    CreateGroup: Group, &[], groups::create;
    GetGroup: Group, &[], groups::get;
    ListGroups: Any, &[], groups::list;
    UpdateGroup: Group, &[], groups::update;
    DeleteGroup: Group, &[], groups::delete;
    AddUserToGroup: Group, &[], groups::add_user;
    RemoveUserFromGroup: Group, &[], groups::remove_user;
    ListGroupsForUser: User, &[], groups::for_user;
    CreatePolicy: Policy, TAGGING, policies::create;
    GetPolicy: Policy, &[], policies::get;
    ListPolicies: Any, &[], policies::list;
    DeletePolicy: Policy, &[], policies::delete;
    CreatePolicyVersion: Policy, &[], policies::create_version;
    GetPolicyVersion: Policy, &[], policies::get_version;
    ListPolicyVersions: Policy, &[], policies::list_versions;
    DeletePolicyVersion: Policy, &[], policies::delete_version;
    SetDefaultPolicyVersion: Policy, &[], policies::set_default_version;
    ListEntitiesForPolicy: Policy, &[], policies::entities;
    TagPolicy: Policy, TAGGING, policies::tag;
    UntagPolicy: Policy, TAG_KEYS, policies::untag;
    ListPolicyTags: Policy, &[], policies::list_tags;
    AttachUserPolicy: User, BOUNDARY_AND_POLICY_ARN, policies::attach_user;
    DetachUserPolicy: User, BOUNDARY_AND_POLICY_ARN, policies::detach_user;
    ListAttachedUserPolicies: User, &[], policies::attached_user;
    AttachGroupPolicy: Group, POLICY_ARN, policies::attach_group;
    DetachGroupPolicy: Group, POLICY_ARN, policies::detach_group;
    ListAttachedGroupPolicies: Group, &[], policies::attached_group;
    PutUserPolicy: User, BOUNDARY, policies::put_user_inline;
    GetUserPolicy: User, &[], policies::get_user_inline;
    ListUserPolicies: User, &[], policies::list_user_inline;
    DeleteUserPolicy: User, BOUNDARY, policies::delete_user_inline;
    PutGroupPolicy: Group, &[], policies::put_group_inline;
    GetGroupPolicy: Group, &[], policies::get_group_inline;
    ListGroupPolicies: Group, &[], policies::list_group_inline;
    DeleteGroupPolicy: Group, &[], policies::delete_group_inline;
    CreateRole: Role, CREATE_ROLE, roles::create;
    GetRole: Role, BOUNDARY_TEMPLATE, roles::get;
    ListRoles: Any, &[], roles::list;
    UpdateRole: Role, BOUNDARY, roles::update;
    UpdateRoleDescription: Role, BOUNDARY, roles::update_description;
    DeleteRole: Role, BOUNDARY, roles::delete;
    UpdateAssumeRolePolicy: Role, BOUNDARY, roles::update_trust;
    TagRole: Role, TAG_ROLE, roles::tag;
    UntagRole: Role, TAG_KEYS, roles::untag;
    ListRoleTags: Role, &[], roles::list_tags;
    PutRolePermissionsBoundary: Role, BOUNDARY_TEMPLATE, roles::put_boundary;
    DeleteRolePermissionsBoundary: Role, BOUNDARY, roles::delete_boundary;
    AttachRolePolicy: Role, ATTACH_ROLE, policies::attach_role;
    DetachRolePolicy: Role, BOUNDARY_AND_POLICY_ARN, policies::detach_role;
    ListAttachedRolePolicies: Role, &[], policies::attached_role;
    PutRolePolicy: Role, BOUNDARY_TEMPLATE, policies::put_role_inline;
    GetRolePolicy: Role, &[], policies::get_role_inline;
    ListRolePolicies: Role, &[], policies::list_role_inline;
    DeleteRolePolicy: Role, BOUNDARY, policies::delete_role_inline;
    CreateOpenIDConnectProvider: OidcProvider, TAGGING, oidc::create;
    GetOpenIDConnectProvider: OidcProvider, &[], oidc::get;
    ListOpenIDConnectProviders: Any, &[], oidc::list;
    DeleteOpenIDConnectProvider: OidcProvider, &[], oidc::delete;
    AddClientIDToOpenIDConnectProvider: OidcProvider, &[], oidc::add_client_id;
    RemoveClientIDFromOpenIDConnectProvider: OidcProvider, &[], oidc::remove_client_id;
    UpdateOpenIDConnectProviderThumbprint: OidcProvider, &[], oidc::update_thumbprint;
    TagOpenIDConnectProvider: OidcProvider, TAGGING, oidc::tag;
    UntagOpenIDConnectProvider: OidcProvider, TAG_KEYS, oidc::untag;
    ListOpenIDConnectProviderTags: OidcProvider, &[], oidc::list_tags;
    GetAccountSummary: Any, &[], account_summary;
}

/// What an action is on: its ARN, and what conditions may test about it.
#[derive(Debug, Clone)]
struct Resource {
    on: On,
    arn: String,
    /// The entity's name and path as stored (or as given, for one that doesn't exist).
    name: String,
    path: String,
    /// `aws:ResourceTag` (and `iam:ResourceTag` for users and roles).
    tags: Vec<(String, String)>,
    /// A user's or role's permissions boundary (`iam:PermissionsBoundary` of actions
    /// on it).
    boundary: Option<String>,
}

/// An action being run.
struct Run<'a> {
    iam: &'a Iam,
    identity: &'a Identity,
    base: &'a Context,
    p: Params,
    account: String,
    /// What the directory said of an LDAP sign-in, which only
    /// [`Iam::serve_self_proving`] asks.
    ldap: Option<&'a Result<SignedIn, LdapError>>,
}

impl Run<'_> {
    /// Refuses the request unless the caller may do `action` on `resource`, with
    /// `context` (which the resource's tags are added to).
    fn check_with(
        &self,
        action: &str,
        resource: &Resource,
        context: &Context,
    ) -> Result<(), ApiError> {
        debug_assert!(
            action.strip_prefix("iam:").is_some_and(|name| ACTIONS
                .iter()
                .any(|a| a.name == name && (a.on == resource.on))),
            "{action} isn't declared on {:?}",
            resource.on
        );
        if self.identity.is_root() {
            return Ok(());
        }
        let tagged;
        let context = if resource.tags.is_empty() {
            context
        } else {
            tagged = with_resource_tags(context.clone(), resource.on, &resource.tags);
            &tagged
        };
        if self.identity.allows(context, action, &resource.arn) {
            Ok(())
        } else {
            Err(ApiError::denied(self.identity, action, &resource.arn))
        }
    }

    /// [`Self::check_with`] the request's own context.
    fn check(&self, action: &str, resource: &Resource) -> Result<(), ApiError> {
        self.check_with(action, resource, self.base)
    }

    /// The request's context, to add an action's keys to.
    fn context(&self) -> Context {
        self.base.clone()
    }

    fn new_resource(&self, on: On, path: &str, name: &str) -> Resource {
        let kind = match on {
            On::User => "user",
            On::Group => "group",
            On::Role => "role",
            On::Policy => "policy",
            On::Any | On::OidcProvider | On::FederatedUser => {
                unreachable!("only IAM's entities with paths are made")
            }
        };
        Resource {
            on,
            arn: state::arn(&self.account, kind, path, name),
            name: name.to_owned(),
            path: path.to_owned(),
            tags: Vec::new(),
            boundary: None,
        }
    }

    /// `*`, for actions on no resource.
    fn any() -> Resource {
        Resource {
            on: On::Any,
            arn: "*".into(),
            name: String::new(),
            path: String::new(),
            tags: Vec::new(),
            boundary: None,
        }
    }

    /// The user called `name` (in any case), or the ARN it would have.
    fn user(&self, name: &str) -> Resource {
        self.iam
            .read(|s| {
                Ok(s.user_named(name).ok().map(|u| Resource {
                    on: On::User,
                    arn: s.user_arn(u),
                    name: u.name.clone(),
                    path: u.path.clone(),
                    tags: u.tags.clone(),
                    boundary: u
                        .boundary
                        .as_ref()
                        .and_then(|id| s.policies.get(id))
                        .map(|p| s.policy_arn(&p.row)),
                }))
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| self.new_resource(On::User, "/", name))
    }

    /// The group called `name`, or the ARN it would have.
    fn group(&self, name: &str) -> Resource {
        self.iam
            .read(|s| {
                Ok(s.group_named(name).ok().map(|g| Resource {
                    on: On::Group,
                    arn: s.group_arn(g),
                    name: g.name.clone(),
                    path: g.path.clone(),
                    tags: Vec::new(),
                    boundary: None,
                }))
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| self.new_resource(On::Group, "/", name))
    }

    /// The role called `name`, or the ARN it would have.
    fn role(&self, name: &str) -> Resource {
        self.iam
            .read(|s| {
                Ok(s.role_named(name).ok().map(|r| Resource {
                    on: On::Role,
                    arn: s.role_arn(r),
                    name: r.name.clone(),
                    path: r.path.clone(),
                    tags: r.tags.clone(),
                    boundary: r
                        .boundary
                        .as_ref()
                        .and_then(|id| s.policies.get(id))
                        .map(|p| s.policy_arn(&p.row)),
                }))
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| self.new_resource(On::Role, "/", name))
    }

    /// The managed policy with this ARN, or the ARN as given.
    fn policy(&self, arn: &str) -> Resource {
        self.iam
            .read(|s| {
                Ok(s.policy_by_arn(arn).ok().map(|p| Resource {
                    on: On::Policy,
                    arn: s.policy_arn(&p.row),
                    name: p.row.name.clone(),
                    path: p.row.path.clone(),
                    tags: p.tags.clone(),
                    boundary: None,
                }))
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| Resource {
                on: On::Policy,
                arn: arn.to_owned(),
                name: String::new(),
                path: String::new(),
                tags: Vec::new(),
                boundary: None,
            })
    }

    /// The OpenID Connect provider with this ARN, or the ARN as given.
    fn oidc_provider(&self, arn: &str) -> Resource {
        self.iam
            .read(|s| {
                Ok(s.oidc_provider_by_arn(arn).ok().map(|p| Resource {
                    on: On::OidcProvider,
                    arn: s.oidc_provider_arn(p),
                    name: p.name().to_owned(),
                    path: String::new(),
                    tags: p.tags.clone(),
                    boundary: None,
                }))
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| Resource {
                on: On::OidcProvider,
                arn: arn.to_owned(),
                name: String::new(),
                path: String::new(),
                tags: Vec::new(),
                boundary: None,
            })
    }

    /// `UserName`, or the caller's own when it's left out, as AWS does; `None` for the
    /// root user's own.
    fn user_name(&self) -> Option<String> {
        self.p
            .optional("UserName")
            .or_else(|| self.identity.principal().username())
            .map(str::to_owned)
    }

    /// `PathPrefix`, checked.
    fn path_prefix(&self) -> Result<Option<&str>, ApiError> {
        let prefix = self.p.optional("PathPrefix");
        if let Some(prefix) = prefix {
            rules::path_prefix(prefix)?;
        }
        Ok(prefix)
    }

    fn page(&self) -> Result<Page, ApiError> {
        self.p.page()
    }
}

/// `aws:RequestTag` and `aws:TagKeys` of a request that sets tags.
fn with_request_tags(mut context: Context, tags: &[(String, String)]) -> Context {
    for (key, value) in tags {
        context = context.with_tag(TagKind::Request, key, value);
    }
    context
}

/// `aws:ResourceTag` of a resource's tags, and `iam:ResourceTag` for a user's or role's.
fn with_resource_tags(mut context: Context, on: On, tags: &[(String, String)]) -> Context {
    for (key, value) in tags {
        context = context.with_tag(TagKind::Resource, key, value);
        if matches!(on, On::User | On::Role) {
            context = context.with_tag(TagKind::IamResource, key, value);
        }
    }
    context
}

/// `iam:PermissionsBoundary`, if there's one.
fn with_boundary(context: Context, boundary: Option<&str>) -> Context {
    match boundary {
        Some(arn) => context.with_iam(IamKey::PermissionsBoundary, arn.to_owned()),
        None => context,
    }
}

/// The IAM quotas and how much of them is used (`GetAccountSummary`).
fn account_summary(r: &Run<'_>) -> Out {
    r.check("iam:GetAccountSummary", &Run::any())?;
    let counts = r.iam.read(|s| {
        Ok([
            ("Users", s.users.len()),
            ("Groups", s.groups.len()),
            ("Roles", s.roles.len()),
            ("Policies", s.policies.len()),
        ])
    })?;
    let quotas = [
        ("UsersQuota", rules::MAX_USERS),
        ("GroupsQuota", rules::MAX_GROUPS),
        ("RolesQuota", rules::MAX_ROLES),
        ("PoliciesQuota", rules::MAX_POLICIES),
        ("GroupsPerUserQuota", rules::MAX_GROUPS_PER_USER),
        ("AttachedPoliciesPerUserQuota", rules::MAX_ATTACHED),
        ("AttachedPoliciesPerGroupQuota", rules::MAX_ATTACHED),
        ("AttachedPoliciesPerRoleQuota", rules::MAX_ATTACHED),
        ("AccessKeysPerUserQuota", rules::MAX_KEYS_PER_USER),
        ("VersionsPerPolicyQuota", rules::MAX_VERSIONS),
        ("PolicySizeQuota", rules::MANAGED_SIZE),
        ("UserPolicySizeQuota", rules::USER_INLINE_TOTAL),
        ("GroupPolicySizeQuota", rules::GROUP_INLINE_TOTAL),
        ("RolePolicySizeQuota", rules::ROLE_INLINE_TOTAL),
        ("AssumeRolePolicySizeQuota", rules::TRUST_SIZE),
        ("AccountMFAEnabled", 0),
    ];
    answer(|x| {
        x.el("SummaryMap", |x| {
            for (key, value) in counts.iter().chain(&quotas) {
                x.el("entry", |x| {
                    x.text("key", key).number("value", *value);
                });
            }
        });
    })
}

/// A policy document as IAM answers with it: URL-encoded.
fn encoded(document: &str) -> String {
    const KEEP: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(document, KEEP).to_string()
}

#[cfg(test)]
mod tests;
