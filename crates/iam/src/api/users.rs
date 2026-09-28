//! Users, their tags and permissions boundaries, and access keys.

use super::{
    ApiError, On, Out, Run, answer, done, paged, truncation, with_boundary, with_request_tags,
    xml::Xml,
};
use crate::{AccessKeyInfo, IamError, UserInfo};

/// A user as IAM answers with it; lists leave out the boundary and tags, as AWS's do.
pub(super) fn user_xml(x: &mut Xml, user: &UserInfo, full: bool) {
    x.text("Path", &user.path)
        .text("UserName", &user.name)
        .text("UserId", &user.id)
        .text("Arn", &user.arn)
        .date("CreateDate", user.created_ms);
    if full {
        if let Some(boundary) = &user.boundary {
            x.el("PermissionsBoundary", |x| {
                x.text("PermissionsBoundaryType", "PermissionsBoundaryPolicy")
                    .text("PermissionsBoundaryArn", boundary);
            });
        }
        if !user.tags.is_empty() {
            x.tags(&user.tags);
        }
    }
}

/// The sort key users are listed by: the name, without case.
pub(super) fn by_name(user: &UserInfo) -> String {
    user.name.to_ascii_lowercase()
}

pub(super) fn create(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let path = r.p.optional("Path");
    let boundary = r.p.optional("PermissionsBoundary");
    let tags = r.p.tags()?;
    let user = r.new_resource(On::User, path.unwrap_or("/"), name);
    let boundary_arn = boundary.map(|arn| r.policy(arn).arn);
    let context = with_boundary(
        with_request_tags(r.context(), &tags),
        boundary_arn.as_deref(),
    );
    r.check_with("iam:CreateUser", &user, &context)?;
    if !tags.is_empty() {
        r.check_with("iam:TagUser", &user, &context)?;
    }
    let user = r.iam.create_user(name, path, &tags, boundary)?;
    answer(|x| {
        x.el("User", |x| user_xml(x, &user, true));
    })
}

pub(super) fn get(r: &Run<'_>) -> Out {
    let Some(name) = r.user_name() else {
        // The root user, about itself.
        let principal = r.identity.principal();
        return answer(|x| {
            x.el("User", |x| {
                x.text("UserId", principal.user_id())
                    .maybe("Arn", principal.arn());
            });
        });
    };
    r.check("iam:GetUser", &r.user(&name))?;
    let user = r.iam.user(&name)?;
    answer(|x| {
        x.el("User", |x| user_xml(x, &user, true));
    })
}

pub(super) fn list(r: &Run<'_>) -> Out {
    let prefix = r.path_prefix()?;
    let page = r.page()?;
    r.check("iam:ListUsers", &Run::any())?;
    let (users, marker) = paged(r.iam.users(prefix)?, &page, by_name);
    answer(|x| {
        x.members("Users", &users, |x, u| user_xml(x, u, false));
        truncation(x, marker.as_deref());
    })
}

pub(super) fn update(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let new_name = r.p.optional("NewUserName");
    let new_path = r.p.optional("NewPath");
    let user = r.user(name);
    r.check("iam:UpdateUser", &user)?;
    if new_name.is_some() || new_path.is_some() {
        // AWS: renaming or moving needs the permission on the new ARN as well.
        let target = r.new_resource(
            On::User,
            new_path.unwrap_or(&user.path),
            new_name.unwrap_or(&user.name),
        );
        r.check("iam:UpdateUser", &target)?;
    }
    r.iam.update_user(name, new_name, new_path)?;
    done()
}

pub(super) fn delete(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    r.check("iam:DeleteUser", &r.user(name))?;
    r.iam.delete_user(name)?;
    done()
}

pub(super) fn tag(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let tags = r.p.tags()?;
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:TagUser", &r.user(name), &context)?;
    r.iam.tag_user(name, &tags)?;
    done()
}

pub(super) fn untag(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let keys = r.p.list("TagKeys")?;
    let context = r.context().with_tag_keys(keys.iter().copied());
    r.check_with("iam:UntagUser", &r.user(name), &context)?;
    let keys: Vec<String> = keys.into_iter().map(str::to_owned).collect();
    r.iam.untag_user(name, &keys)?;
    done()
}

pub(super) fn list_tags(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let page = r.page()?;
    r.check("iam:ListUserTags", &r.user(name))?;
    let (tags, marker) = paged(r.iam.user(name)?.tags, &page, |(k, _)| {
        k.to_ascii_lowercase()
    });
    answer(|x| {
        x.tags(&tags);
        truncation(x, marker.as_deref());
    })
}

pub(super) fn put_boundary(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let boundary = r.p.required("PermissionsBoundary")?;
    let context = with_boundary(r.context(), Some(&r.policy(boundary).arn));
    r.check_with("iam:PutUserPermissionsBoundary", &r.user(name), &context)?;
    r.iam.set_user_boundary(name, Some(boundary))?;
    done()
}

pub(super) fn delete_boundary(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let user = r.user(name);
    let context = with_boundary(r.context(), user.boundary.as_deref());
    r.check_with("iam:DeleteUserPermissionsBoundary", &user, &context)?;
    r.iam.set_user_boundary(name, None)?;
    done()
}

/// The user whose keys an action is on: `UserName` or the caller; the root user's own
/// key is the drive's, set in its configuration.
fn key_owner(r: &Run<'_>) -> Result<String, ApiError> {
    r.user_name().ok_or_else(|| {
        IamError::InvalidInput(
            "The root user's access key is part of the drive's configuration; name a user \
             (UserName) to manage IAM access keys."
                .into(),
        )
        .into()
    })
}

fn key_xml(x: &mut Xml, key: &AccessKeyInfo) {
    x.text("UserName", &key.user)
        .text("AccessKeyId", &key.id)
        .text("Status", if key.active { "Active" } else { "Inactive" });
}

pub(super) fn create_key(r: &Run<'_>) -> Out {
    let name = key_owner(r)?;
    r.check("iam:CreateAccessKey", &r.user(&name))?;
    let key = r.iam.create_access_key(&name)?;
    answer(|x| {
        x.el("AccessKey", |x| {
            key_xml(x, &key.info);
            x.text("SecretAccessKey", &key.secret)
                .date("CreateDate", key.info.created_ms);
        });
    })
}

pub(super) fn list_keys(r: &Run<'_>) -> Out {
    let name = key_owner(r)?;
    let page = r.page()?;
    r.check("iam:ListAccessKeys", &r.user(&name))?;
    let (keys, marker) = paged(r.iam.access_keys(&name)?, &page, |k| {
        format!("{:020}{}", k.created_ms, k.id)
    });
    answer(|x| {
        x.members("AccessKeyMetadata", &keys, |x, k| {
            key_xml(x, k);
            x.date("CreateDate", k.created_ms);
        });
        truncation(x, marker.as_deref());
    })
}

pub(super) fn update_key(r: &Run<'_>) -> Out {
    let name = key_owner(r)?;
    let id = r.p.required("AccessKeyId")?;
    let status =
        r.p.choice("Status", &["Active", "Inactive"])?
            .ok_or_else(|| ApiError::missing("Status"))?;
    r.check("iam:UpdateAccessKey", &r.user(&name))?;
    r.iam.update_access_key(&name, id, status == "Active")?;
    done()
}

pub(super) fn delete_key(r: &Run<'_>) -> Out {
    let name = key_owner(r)?;
    let id = r.p.required("AccessKeyId")?;
    r.check("iam:DeleteAccessKey", &r.user(&name))?;
    r.iam.delete_access_key(&name, id)?;
    done()
}

/// TeiFS doesn't record when keys are used, so a key reads as never used.
pub(super) fn key_last_used(r: &Run<'_>) -> Out {
    let id = r.p.required("AccessKeyId")?;
    let key = r.iam.access_key(id)?;
    r.check("iam:GetAccessKeyLastUsed", &r.user(&key.user))?;
    answer(|x| {
        x.text("UserName", &key.user).el("AccessKeyLastUsed", |x| {
            x.text("Region", "N/A").text("ServiceName", "N/A");
        });
    })
}
