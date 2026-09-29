//! Managed policies and their versions and tags, attachments, and inline policies.

use teifs_policy::IamKey;

use super::{
    ApiError, On, Out, Resource, Run, answer, done, encoded, paged, truncation, with_boundary,
    with_request_tags, xml::Xml,
};
use crate::{Iam, Owner, PolicyInfo, PolicyVersionInfo};

/// A managed policy as IAM answers with it; `ListPolicies` leaves out the description
/// and tags, as AWS's does.
fn policy_xml(x: &mut Xml, policy: &PolicyInfo, full: bool) {
    x.text("PolicyName", &policy.name)
        .text("PolicyId", &policy.id)
        .text("Arn", &policy.arn)
        .text("Path", &policy.path)
        .text("DefaultVersionId", &policy.default_version)
        .number("AttachmentCount", policy.attachment_count)
        .number("PermissionsBoundaryUsageCount", policy.boundary_usage_count)
        .boolean("IsAttachable", true);
    if full && !policy.description.is_empty() {
        x.text("Description", &policy.description);
    }
    x.date("CreateDate", policy.created_ms)
        .date("UpdateDate", policy.updated_ms);
    if full && !policy.tags.is_empty() {
        x.tags(&policy.tags);
    }
}

/// A version; only `GetPolicyVersion` answers with its document.
fn version_xml(x: &mut Xml, version: &PolicyVersionInfo, document: bool) {
    if document {
        x.text("Document", &encoded(&version.document));
    }
    x.text("VersionId", &version.version)
        .boolean("IsDefaultVersion", version.is_default)
        .date("CreateDate", version.created_ms);
}

pub(super) fn create(r: &Run<'_>) -> Out {
    let name = r.p.required("PolicyName")?;
    let path = r.p.optional("Path");
    let document = r.p.required("PolicyDocument")?;
    let description = r.p.optional("Description");
    let tags = r.p.tags()?;
    let policy = r.new_resource(On::Policy, path.unwrap_or("/"), name);
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:CreatePolicy", &policy, &context)?;
    if !tags.is_empty() {
        r.check_with("iam:TagPolicy", &policy, &context)?;
    }
    let policy = r
        .iam
        .create_policy(name, path, description, document, &tags)?;
    answer(|x| {
        x.el("Policy", |x| policy_xml(x, &policy, true));
    })
}

pub(super) fn get(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    r.check("iam:GetPolicy", &r.policy(arn))?;
    let policy = r.iam.policy(arn)?;
    answer(|x| {
        x.el("Policy", |x| policy_xml(x, &policy, true));
    })
}

pub(super) fn list(r: &Run<'_>) -> Out {
    let scope = r.p.choice("Scope", &["All", "AWS", "Local"])?;
    let attached = r.p.boolean("OnlyAttached", false)?;
    // Any customer-managed policy can be either, so this filters nothing.
    r.p.choice(
        "PolicyUsageFilter",
        &["PermissionsPolicy", "PermissionsBoundary"],
    )?;
    let prefix = r.path_prefix()?;
    let page = r.page()?;
    r.check("iam:ListPolicies", &Run::any())?;
    // TeiFS has no AWS-managed policies.
    let policies = if scope == Some("AWS") {
        Vec::new()
    } else {
        r.iam.policies(prefix, attached)?
    };
    let (policies, marker) = paged(policies, &page, |p| p.name.to_ascii_lowercase());
    answer(|x| {
        x.members("Policies", &policies, |x, p| policy_xml(x, p, false));
        truncation(x, marker.as_deref());
    })
}

pub(super) fn delete(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    r.check("iam:DeletePolicy", &r.policy(arn))?;
    r.iam.delete_policy(arn)?;
    done()
}

pub(super) fn create_version(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let document = r.p.required("PolicyDocument")?;
    let set_default = r.p.boolean("SetAsDefault", false)?;
    r.check("iam:CreatePolicyVersion", &r.policy(arn))?;
    let version = r.iam.create_policy_version(arn, document, set_default)?;
    answer(|x| {
        x.el("PolicyVersion", |x| version_xml(x, &version, false));
    })
}

pub(super) fn get_version(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let id = r.p.required("VersionId")?;
    r.check("iam:GetPolicyVersion", &r.policy(arn))?;
    let version = r.iam.policy_version(arn, id)?;
    answer(|x| {
        x.el("PolicyVersion", |x| version_xml(x, &version, true));
    })
}

pub(super) fn list_versions(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let page = r.page()?;
    r.check("iam:ListPolicyVersions", &r.policy(arn))?;
    // Newest first, as AWS lists them.
    let (versions, marker) = paged(r.iam.policy_versions(arn)?, &page, |v| {
        let number: u32 = v
            .version
            .strip_prefix('v')
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        format!("{:010}", u32::MAX - number)
    });
    answer(|x| {
        x.members("Versions", &versions, |x, v| version_xml(x, v, false));
        truncation(x, marker.as_deref());
    })
}

pub(super) fn delete_version(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let id = r.p.required("VersionId")?;
    r.check("iam:DeletePolicyVersion", &r.policy(arn))?;
    r.iam.delete_policy_version(arn, id)?;
    done()
}

pub(super) fn set_default_version(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let id = r.p.required("VersionId")?;
    r.check("iam:SetDefaultPolicyVersion", &r.policy(arn))?;
    r.iam.set_default_policy_version(arn, id)?;
    done()
}

/// Who uses a policy, for `ListEntitiesForPolicy`.
struct Entity {
    kind: EntityKind,
    name: String,
    id: String,
    path: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntityKind {
    Group,
    Role,
    User,
}

impl EntityKind {
    /// Its element in the answer, and the elements of its name and id.
    fn elements(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Group => ("PolicyGroups", "GroupName", "GroupId"),
            Self::Role => ("PolicyRoles", "RoleName", "RoleId"),
            Self::User => ("PolicyUsers", "UserName", "UserId"),
        }
    }
}

pub(super) fn entities(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let filter = r.p.choice(
        "EntityFilter",
        &[
            "User",
            "Role",
            "Group",
            "LocalManagedPolicy",
            "AWSManagedPolicy",
        ],
    )?;
    let usage = r.p.choice(
        "PolicyUsageFilter",
        &["PermissionsPolicy", "PermissionsBoundary"],
    )?;
    let prefix = r.path_prefix()?;
    let page = r.page()?;
    r.check("iam:ListEntitiesForPolicy", &r.policy(arn))?;
    let (groups, users, roles) = r.iam.entities_for_policy(arn)?;
    let policies = usage != Some("PermissionsBoundary");
    let boundaries = usage != Some("PermissionsPolicy");
    let wanted = |kind: &str| filter.is_none_or(|f| f == kind);
    let mut all: Vec<Entity> = Vec::new();
    let mut add = |kind, name: String, id: String, path: String| {
        if !all.iter().any(|e| e.id == id) {
            all.push(Entity {
                kind,
                name,
                id,
                path,
            });
        }
    };
    if wanted("Group") && policies {
        for g in groups {
            add(EntityKind::Group, g.name, g.id, g.path);
        }
    }
    if wanted("User") {
        let bounded = if boundaries {
            r.iam.users_with_boundary(arn)?
        } else {
            Vec::new()
        };
        let attached = if policies { users } else { Vec::new() };
        for u in attached.into_iter().chain(bounded) {
            add(EntityKind::User, u.name, u.id, u.path);
        }
    }
    if wanted("Role") {
        let bounded = if boundaries {
            r.iam.roles_with_boundary(arn)?
        } else {
            Vec::new()
        };
        let attached = if policies { roles } else { Vec::new() };
        for role in attached.into_iter().chain(bounded) {
            add(EntityKind::Role, role.name, role.id, role.path);
        }
    }
    all.retain(|e| prefix.is_none_or(|p| e.path.starts_with(p)));
    let (all, marker) = paged(all, &page, |e| {
        let (element, ..) = e.kind.elements();
        format!("{element}{}", e.name.to_ascii_lowercase())
    });
    answer(|x| {
        for kind in [EntityKind::Group, EntityKind::User, EntityKind::Role] {
            let (element, name, id) = kind.elements();
            let these: Vec<&Entity> = all.iter().filter(|e| e.kind == kind).collect();
            x.members(element, &these, |x, e| {
                x.text(name, &e.name).text(id, &e.id);
            });
        }
        truncation(x, marker.as_deref());
    })
}

pub(super) fn tag(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let tags = r.p.tags()?;
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:TagPolicy", &r.policy(arn), &context)?;
    r.iam.tag_policy(arn, &tags)?;
    done()
}

pub(super) fn untag(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let keys = r.p.list("TagKeys")?;
    let context = r.context().with_tag_keys(keys.iter().copied());
    r.check_with("iam:UntagPolicy", &r.policy(arn), &context)?;
    let keys: Vec<String> = keys.into_iter().map(str::to_owned).collect();
    r.iam.untag_policy(arn, &keys)?;
    done()
}

pub(super) fn list_tags(r: &Run<'_>) -> Out {
    let arn = r.p.required("PolicyArn")?;
    let page = r.page()?;
    r.check("iam:ListPolicyTags", &r.policy(arn))?;
    let (tags, marker) = paged(r.iam.policy(arn)?.tags, &page, |(k, _)| k.clone());
    answer(|x| {
        x.tags(&tags);
        truncation(x, marker.as_deref());
    })
}

/// Users, groups or roles, for the actions that come in each kind.
#[derive(Clone, Copy)]
enum Kind {
    User,
    Group,
    Role,
}

impl Kind {
    fn param(self) -> &'static str {
        match self {
            Self::User => "UserName",
            Self::Group => "GroupName",
            Self::Role => "RoleName",
        }
    }

    /// The owner the request names, and its resource.
    fn owner<'p>(self, r: &'p Run<'_>) -> Result<(Owner<'p>, Resource), ApiError> {
        let name = r.p.required(self.param())?;
        Ok(match self {
            Self::User => (Owner::User(name), r.user(name)),
            Self::Group => (Owner::Group(name), r.group(name)),
            Self::Role => (Owner::Role(name), r.role(name)),
        })
    }
}

/// `iam:PermissionsBoundary` of an action on a user or role: the boundary it has.
fn owner_context(r: &Run<'_>, owner: &Resource) -> teifs_policy::Context {
    with_boundary(r.context(), owner.boundary.as_deref())
}

/// Attaches or detaches (`change`) a managed policy.
fn attachment(
    r: &Run<'_>,
    kind: Kind,
    action: &str,
    change: fn(&Iam, Owner<'_>, &str) -> crate::Result<()>,
) -> Out {
    let (owner, resource) = kind.owner(r)?;
    let arn = r.p.required("PolicyArn")?;
    let context = owner_context(r, &resource).with_iam(IamKey::PolicyArn, r.policy(arn).arn);
    r.check_with(action, &resource, &context)?;
    change(r.iam, owner, arn)?;
    done()
}

pub(super) fn attach_user(r: &Run<'_>) -> Out {
    attachment(r, Kind::User, "iam:AttachUserPolicy", Iam::attach)
}

pub(super) fn detach_user(r: &Run<'_>) -> Out {
    attachment(r, Kind::User, "iam:DetachUserPolicy", Iam::detach)
}

pub(super) fn attach_group(r: &Run<'_>) -> Out {
    attachment(r, Kind::Group, "iam:AttachGroupPolicy", Iam::attach)
}

pub(super) fn detach_group(r: &Run<'_>) -> Out {
    attachment(r, Kind::Group, "iam:DetachGroupPolicy", Iam::detach)
}

pub(super) fn attach_role(r: &Run<'_>) -> Out {
    attachment(r, Kind::Role, "iam:AttachRolePolicy", Iam::attach)
}

pub(super) fn detach_role(r: &Run<'_>) -> Out {
    attachment(r, Kind::Role, "iam:DetachRolePolicy", Iam::detach)
}

fn attached(r: &Run<'_>, kind: Kind, action: &str) -> Out {
    let (owner, resource) = kind.owner(r)?;
    let prefix = r.path_prefix()?;
    let page = r.page()?;
    r.check(action, &resource)?;
    let (policies, marker) = paged(r.iam.attached(owner, prefix)?, &page, |p| {
        p.name.to_ascii_lowercase()
    });
    answer(|x| {
        x.members("AttachedPolicies", &policies, |x, p| {
            x.text("PolicyName", &p.name).text("PolicyArn", &p.arn);
        });
        truncation(x, marker.as_deref());
    })
}

pub(super) fn attached_user(r: &Run<'_>) -> Out {
    attached(r, Kind::User, "iam:ListAttachedUserPolicies")
}

pub(super) fn attached_group(r: &Run<'_>) -> Out {
    attached(r, Kind::Group, "iam:ListAttachedGroupPolicies")
}

pub(super) fn attached_role(r: &Run<'_>) -> Out {
    attached(r, Kind::Role, "iam:ListAttachedRolePolicies")
}

fn put_inline(r: &Run<'_>, kind: Kind, action: &str) -> Out {
    let (owner, resource) = kind.owner(r)?;
    let name = r.p.required("PolicyName")?;
    let document = r.p.required("PolicyDocument")?;
    r.check_with(action, &resource, &owner_context(r, &resource))?;
    r.iam.put_inline(owner, name, document)?;
    done()
}

pub(super) fn put_user_inline(r: &Run<'_>) -> Out {
    put_inline(r, Kind::User, "iam:PutUserPolicy")
}

pub(super) fn put_group_inline(r: &Run<'_>) -> Out {
    put_inline(r, Kind::Group, "iam:PutGroupPolicy")
}

pub(super) fn put_role_inline(r: &Run<'_>) -> Out {
    put_inline(r, Kind::Role, "iam:PutRolePolicy")
}

fn get_inline(r: &Run<'_>, kind: Kind, action: &str) -> Out {
    let (owner, resource) = kind.owner(r)?;
    let name = r.p.required("PolicyName")?;
    r.check(action, &resource)?;
    let document = r.iam.inline(owner, name)?;
    answer(|x| {
        x.text(kind.param(), &resource.name)
            .text("PolicyName", name)
            .text("PolicyDocument", &encoded(&document));
    })
}

pub(super) fn get_user_inline(r: &Run<'_>) -> Out {
    get_inline(r, Kind::User, "iam:GetUserPolicy")
}

pub(super) fn get_group_inline(r: &Run<'_>) -> Out {
    get_inline(r, Kind::Group, "iam:GetGroupPolicy")
}

pub(super) fn get_role_inline(r: &Run<'_>) -> Out {
    get_inline(r, Kind::Role, "iam:GetRolePolicy")
}

fn list_inline(r: &Run<'_>, kind: Kind, action: &str) -> Out {
    let (owner, resource) = kind.owner(r)?;
    let page = r.page()?;
    r.check(action, &resource)?;
    let (names, marker) = paged(r.iam.inline_names(owner)?, &page, Clone::clone);
    answer(|x| {
        x.members("PolicyNames", &names, |x, n| {
            x.content(n);
        });
        truncation(x, marker.as_deref());
    })
}

pub(super) fn list_user_inline(r: &Run<'_>) -> Out {
    list_inline(r, Kind::User, "iam:ListUserPolicies")
}

pub(super) fn list_group_inline(r: &Run<'_>) -> Out {
    list_inline(r, Kind::Group, "iam:ListGroupPolicies")
}

pub(super) fn list_role_inline(r: &Run<'_>) -> Out {
    list_inline(r, Kind::Role, "iam:ListRolePolicies")
}

fn delete_inline(r: &Run<'_>, kind: Kind, action: &str) -> Out {
    let (owner, resource) = kind.owner(r)?;
    let name = r.p.required("PolicyName")?;
    r.check_with(action, &resource, &owner_context(r, &resource))?;
    r.iam.delete_inline(owner, name)?;
    done()
}

pub(super) fn delete_user_inline(r: &Run<'_>) -> Out {
    delete_inline(r, Kind::User, "iam:DeleteUserPolicy")
}

pub(super) fn delete_group_inline(r: &Run<'_>) -> Out {
    delete_inline(r, Kind::Group, "iam:DeleteGroupPolicy")
}

pub(super) fn delete_role_inline(r: &Run<'_>) -> Out {
    delete_inline(r, Kind::Role, "iam:DeleteRolePolicy")
}
