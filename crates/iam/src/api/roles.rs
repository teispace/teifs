//! Roles, their trust policies, tags and permissions boundaries. Their inline and
//! attached policies are in `policies`.

use super::{
    ApiError, On, Out, Resource, Run, answer, done, encoded, paged, truncation, with_boundary,
    with_request_tags, xml::Xml,
};
use crate::{NewRole, RoleInfo};

/// A role as IAM answers with it; `ListRoles` leaves out the boundary, tags and last
/// use, as AWS's does.
pub(super) fn role_xml(x: &mut Xml, role: &RoleInfo, full: bool) {
    x.text("Path", &role.path)
        .text("RoleName", &role.name)
        .text("RoleId", &role.id)
        .text("Arn", &role.arn)
        .date("CreateDate", role.created_ms)
        .text("AssumeRolePolicyDocument", &encoded(&role.trust));
    if !role.description.is_empty() {
        x.text("Description", &role.description);
    }
    x.number("MaxSessionDuration", role.max_session as usize);
    if full {
        if let Some(boundary) = &role.boundary {
            x.el("PermissionsBoundary", |x| {
                x.text("PermissionsBoundaryType", "PermissionsBoundaryPolicy")
                    .text("PermissionsBoundaryArn", boundary);
            });
        }
        if !role.tags.is_empty() {
            x.tags(&role.tags);
        }
        // TeiFS doesn't record when roles are used.
        x.el("RoleLastUsed", |_| {});
    }
}

/// `MaxSessionDuration`, if given: a whole number of seconds.
fn max_session(r: &Run<'_>) -> Result<Option<u32>, ApiError> {
    r.p.optional("MaxSessionDuration")
        .map(|text| {
            text.parse()
                .map_err(|_| ApiError::invalid_value("MaxSessionDuration", text))
        })
        .transpose()
}

/// The role `RoleName` names, and the context of an action on it that sets
/// `iam:PermissionsBoundary` (to the boundary it has).
fn named<'p>(r: &'p Run<'_>) -> Result<(&'p str, Resource, teifs_policy::Context), ApiError> {
    let name = r.p.required("RoleName")?;
    let role = r.role(name);
    let context = with_boundary(r.context(), role.boundary.as_deref());
    Ok((name, role, context))
}

pub(super) fn create(r: &Run<'_>) -> Out {
    let name = r.p.required("RoleName")?;
    let path = r.p.optional("Path");
    let trust = r.p.required("AssumeRolePolicyDocument")?;
    let boundary = r.p.optional("PermissionsBoundary");
    let tags = r.p.tags()?;
    let role = r.new_resource(On::Role, path.unwrap_or("/"), name);
    let boundary_arn = boundary.map(|arn| r.policy(arn).arn);
    let context = with_boundary(
        with_request_tags(r.context(), &tags),
        boundary_arn.as_deref(),
    );
    r.check_with("iam:CreateRole", &role, &context)?;
    if !tags.is_empty() {
        r.check_with("iam:TagRole", &role, &context)?;
    }
    let role = r.iam.create_role(
        name,
        &NewRole {
            path,
            trust,
            description: r.p.optional("Description"),
            max_session: max_session(r)?,
            tags: &tags,
            boundary,
        },
    )?;
    answer(|x| {
        x.el("Role", |x| role_xml(x, &role, true));
    })
}

pub(super) fn get(r: &Run<'_>) -> Out {
    let (name, role, context) = named(r)?;
    r.check_with("iam:GetRole", &role, &context)?;
    let role = r.iam.role(name)?;
    answer(|x| {
        x.el("Role", |x| role_xml(x, &role, true));
    })
}

pub(super) fn list(r: &Run<'_>) -> Out {
    let prefix = r.path_prefix()?;
    let page = r.page()?;
    r.check("iam:ListRoles", &Run::any())?;
    let (roles, marker) = paged(r.iam.roles(prefix)?, &page, |role| {
        role.name.to_ascii_lowercase()
    });
    answer(|x| {
        x.members("Roles", &roles, |x, role| role_xml(x, role, false));
        truncation(x, marker.as_deref());
    })
}

pub(super) fn update(r: &Run<'_>) -> Out {
    let (name, role, context) = named(r)?;
    let max_session = max_session(r)?;
    r.check_with("iam:UpdateRole", &role, &context)?;
    r.iam
        .update_role(name, r.p.optional("Description"), max_session)?;
    done()
}

pub(super) fn update_description(r: &Run<'_>) -> Out {
    let (name, role, context) = named(r)?;
    let description = r.p.required("Description")?;
    r.check_with("iam:UpdateRoleDescription", &role, &context)?;
    let role = r.iam.update_role(name, Some(description), None)?;
    answer(|x| {
        x.el("Role", |x| role_xml(x, &role, true));
    })
}

pub(super) fn delete(r: &Run<'_>) -> Out {
    let (name, role, context) = named(r)?;
    r.check_with("iam:DeleteRole", &role, &context)?;
    r.iam.delete_role(name)?;
    done()
}

pub(super) fn update_trust(r: &Run<'_>) -> Out {
    let (name, role, context) = named(r)?;
    let document = r.p.required("PolicyDocument")?;
    r.check_with("iam:UpdateAssumeRolePolicy", &role, &context)?;
    r.iam.update_trust(name, document)?;
    done()
}

pub(super) fn tag(r: &Run<'_>) -> Out {
    let name = r.p.required("RoleName")?;
    let tags = r.p.tags()?;
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:TagRole", &r.role(name), &context)?;
    r.iam.tag_role(name, &tags)?;
    done()
}

pub(super) fn untag(r: &Run<'_>) -> Out {
    let name = r.p.required("RoleName")?;
    let keys = r.p.list("TagKeys")?;
    let context = r.context().with_tag_keys(keys.iter().copied());
    r.check_with("iam:UntagRole", &r.role(name), &context)?;
    let keys: Vec<String> = keys.into_iter().map(str::to_owned).collect();
    r.iam.untag_role(name, &keys)?;
    done()
}

pub(super) fn list_tags(r: &Run<'_>) -> Out {
    let name = r.p.required("RoleName")?;
    let page = r.page()?;
    r.check("iam:ListRoleTags", &r.role(name))?;
    let (tags, marker) = paged(r.iam.role(name)?.tags, &page, |(k, _)| {
        k.to_ascii_lowercase()
    });
    answer(|x| {
        x.tags(&tags);
        truncation(x, marker.as_deref());
    })
}

pub(super) fn put_boundary(r: &Run<'_>) -> Out {
    let name = r.p.required("RoleName")?;
    let boundary = r.p.required("PermissionsBoundary")?;
    let context = with_boundary(r.context(), Some(&r.policy(boundary).arn));
    r.check_with("iam:PutRolePermissionsBoundary", &r.role(name), &context)?;
    r.iam.set_role_boundary(name, Some(boundary))?;
    done()
}

pub(super) fn delete_boundary(r: &Run<'_>) -> Out {
    let (name, role, context) = named(r)?;
    r.check_with("iam:DeleteRolePermissionsBoundary", &role, &context)?;
    r.iam.set_role_boundary(name, None)?;
    done()
}
