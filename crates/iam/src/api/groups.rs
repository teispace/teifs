//! Groups and their members.

use super::{On, Out, Run, answer, done, paged, truncation, users, xml::Xml};
use crate::GroupInfo;

fn group_xml(x: &mut Xml, group: &GroupInfo) {
    x.text("Path", &group.path)
        .text("GroupName", &group.name)
        .text("GroupId", &group.id)
        .text("Arn", &group.arn)
        .date("CreateDate", group.created_ms);
}

fn by_name(group: &GroupInfo) -> String {
    group.name.to_ascii_lowercase()
}

pub(super) fn create(r: &Run<'_>) -> Out {
    let name = r.p.required("GroupName")?;
    let path = r.p.optional("Path");
    r.check(
        "iam:CreateGroup",
        &r.new_resource(On::Group, path.unwrap_or("/"), name),
    )?;
    let group = r.iam.create_group(name, path)?;
    answer(|x| {
        x.el("Group", |x| group_xml(x, &group));
    })
}

pub(super) fn get(r: &Run<'_>) -> Out {
    let name = r.p.required("GroupName")?;
    let page = r.page()?;
    r.check("iam:GetGroup", &r.group(name))?;
    let (group, members) = r.iam.group(name)?;
    let (members, marker) = paged(members, &page, users::by_name);
    answer(|x| {
        x.el("Group", |x| group_xml(x, &group))
            .members("Users", &members, |x, u| users::user_xml(x, u, false));
        truncation(x, marker.as_deref());
    })
}

pub(super) fn list(r: &Run<'_>) -> Out {
    let prefix = r.path_prefix()?;
    let page = r.page()?;
    r.check("iam:ListGroups", &Run::any())?;
    let (groups, marker) = paged(r.iam.groups(prefix)?, &page, by_name);
    answer(|x| {
        x.members("Groups", &groups, group_xml);
        truncation(x, marker.as_deref());
    })
}

pub(super) fn update(r: &Run<'_>) -> Out {
    let name = r.p.required("GroupName")?;
    let new_name = r.p.optional("NewGroupName");
    let new_path = r.p.optional("NewPath");
    let group = r.group(name);
    r.check("iam:UpdateGroup", &group)?;
    if new_name.is_some() || new_path.is_some() {
        // AWS: renaming or moving needs the permission on the new ARN as well.
        let target = r.new_resource(
            On::Group,
            new_path.unwrap_or(&group.path),
            new_name.unwrap_or(&group.name),
        );
        r.check("iam:UpdateGroup", &target)?;
    }
    r.iam.update_group(name, new_name, new_path)?;
    done()
}

pub(super) fn delete(r: &Run<'_>) -> Out {
    let name = r.p.required("GroupName")?;
    r.check("iam:DeleteGroup", &r.group(name))?;
    r.iam.delete_group(name)?;
    done()
}

pub(super) fn add_user(r: &Run<'_>) -> Out {
    let group = r.p.required("GroupName")?;
    let user = r.p.required("UserName")?;
    r.check("iam:AddUserToGroup", &r.group(group))?;
    r.iam.add_user_to_group(group, user)?;
    done()
}

pub(super) fn remove_user(r: &Run<'_>) -> Out {
    let group = r.p.required("GroupName")?;
    let user = r.p.required("UserName")?;
    r.check("iam:RemoveUserFromGroup", &r.group(group))?;
    r.iam.remove_user_from_group(group, user)?;
    done()
}

pub(super) fn for_user(r: &Run<'_>) -> Out {
    let name = r.p.required("UserName")?;
    let page = r.page()?;
    r.check("iam:ListGroupsForUser", &r.user(name))?;
    let (groups, marker) = paged(r.iam.groups_for_user(name)?, &page, by_name);
    answer(|x| {
        x.members("Groups", &groups, group_xml);
        truncation(x, marker.as_deref());
    })
}
