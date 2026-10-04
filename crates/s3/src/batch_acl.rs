//! S3 Batch Operations' `S3PutObjectAcl`: each object's ACL is replaced with
//! `PutObjectAcl`, as the job's role, by the canned ACL or the grants and owner S3
//! Control's `S3SetObjectAclOperation` gives.

use aws_sdk_s3::{
    Client,
    operation::put_object_acl::builders::PutObjectAclFluentBuilder,
    types::{
        AccessControlPolicy, Grant as SdkGrant, Grantee, ObjectCannedAcl, Owner, Permission, Type,
    },
};
use s3s::S3Result;
use serde::{Deserialize, Serialize};
use teifs_types::batch::{AclOperation, Grant};

use crate::{
    batch_copy::{CANNED_ACLS, GrantXml, grants_of, grants_xml, one_of},
    batch_operations::{Failure, Task},
    control_jobs::{Members, bad_request},
};

/// `S3PutObjectAcl`, as S3 Control takes and answers it.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct AclXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_control_policy: Option<PolicyXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PolicyXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_control_list: Option<ListXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canned_access_control_list: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    grants: Option<Members<GrantXml>>,
    owner: Option<OwnerXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OwnerXml {
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

/// The ACL a job gives, checked.
pub(crate) fn parse(given: AclXml) -> S3Result<AclOperation> {
    let policy = given.access_control_policy.unwrap_or_default();
    let canned = policy.canned_access_control_list;
    one_of("CannedAccessControlList", canned.as_deref(), &CANNED_ACLS)?;
    match (canned, policy.access_control_list) {
        (Some(canned), None) => Ok(AclOperation {
            canned_acl: Some(canned),
            ..AclOperation::default()
        }),
        (None, Some(list)) => {
            let Some(owner) = list.owner else {
                return Err(bad_request("An AccessControlList names its Owner."));
            };
            Ok(AclOperation {
                canned_acl: None,
                owner_id: owner.id.filter(|id| !id.is_empty()),
                owner_name: owner.display_name.filter(|name| !name.is_empty()),
                grants: grants_of(list.grants.unwrap_or_default())?,
            })
        }
        _ => Err(bad_request(
            "An AccessControlPolicy has an AccessControlList or a CannedAccessControlList.",
        )),
    }
}

/// A job's ACL, as `DescribeJob` answers it.
pub(crate) fn xml(acl: &AclOperation) -> AclXml {
    let list = acl.canned_acl.is_none().then(|| ListXml {
        grants: grants_xml(&acl.grants),
        owner: Some(OwnerXml {
            id: acl.owner_id.clone(),
            display_name: acl.owner_name.clone(),
        }),
    });
    AclXml {
        access_control_policy: Some(PolicyXml {
            access_control_list: list,
            canned_access_control_list: acl.canned_acl.clone(),
        }),
    }
}

/// Replaces the task's object's ACL.
pub(crate) async fn run(client: &Client, acl: &AclOperation, task: &Task) -> Result<(), Failure> {
    request(client, acl, task)?
        .send()
        .await
        .map(drop)
        .map_err(|err| Failure::of(&err))
}

/// The `PutObjectAcl` that gives the task's object its ACL.
fn request(
    client: &Client,
    acl: &AclOperation,
    task: &Task,
) -> Result<PutObjectAclFluentBuilder, Failure> {
    let put = client
        .put_object_acl()
        .bucket(&task.bucket)
        .key(&task.key)
        .set_version_id(task.version.clone());
    if let Some(canned) = &acl.canned_acl {
        return Ok(put.acl(ObjectCannedAcl::from(canned.as_str())));
    }
    let grants = acl
        .grants
        .iter()
        .map(grant)
        .collect::<Result<Vec<_>, _>>()?;
    let owner = Owner::builder()
        .set_id(acl.owner_id.clone())
        .set_display_name(acl.owner_name.clone())
        .build();
    let policy = AccessControlPolicy::builder()
        .set_grants(Some(grants))
        .owner(owner)
        .build();
    Ok(put.access_control_policy(policy))
}

/// A grant, as `PutObjectAcl`'s body gives it.
fn grant(grant: &Grant) -> Result<SdkGrant, Failure> {
    let grantee = Grantee::builder();
    let grantee = match grant.kind.as_str() {
        "id" => grantee.r#type(Type::CanonicalUser).id(&grant.identifier),
        "emailAddress" => grantee
            .r#type(Type::AmazonCustomerByEmail)
            .email_address(&grant.identifier),
        _ => grantee.r#type(Type::Group).uri(&grant.identifier),
    };
    Ok(SdkGrant::builder()
        .grantee(grantee.build().map_err(Failure::internal)?)
        .permission(Permission::from(grant.permission.as_str()))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(xml: &str) -> S3Result<AclOperation> {
        parse(quick_xml::de::from_str(xml).unwrap())
    }

    const GRANTS: &str = r"<S3PutObjectAcl><AccessControlPolicy><AccessControlList>
        <Grants>
          <member><Grantee><TypeIdentifier>id</TypeIdentifier><Identifier>teifs</Identifier>
            <DisplayName>owner</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></member>
          <member><Grantee><TypeIdentifier>uri</TypeIdentifier>
            <Identifier>http://acs.amazonaws.com/groups/global/AllUsers</Identifier></Grantee>
            <Permission>READ</Permission></member>
          <member><Grantee><TypeIdentifier>emailAddress</TypeIdentifier><Identifier>a@b.c</Identifier>
            </Grantee><Permission>READ_ACP</Permission></member>
        </Grants>
        <Owner><ID>teifs</ID><DisplayName>owner</DisplayName></Owner>
      </AccessControlList></AccessControlPolicy></S3PutObjectAcl>";

    #[test]
    fn grants_and_their_owner_are_taken_and_described_again() {
        let acl = parsed(GRANTS).unwrap();
        assert_eq!(acl.owner_id.as_deref(), Some("teifs"));
        assert_eq!(acl.owner_name.as_deref(), Some("owner"));
        assert_eq!(acl.canned_acl, None);
        assert_eq!(acl.grants.len(), 3);
        assert_eq!(acl.grants[1].kind, "uri");
        assert_eq!(acl.grants[2].permission, "READ_ACP");
        let again = quick_xml::se::to_string_with_root("S3PutObjectAcl", &xml(&acl)).unwrap();
        assert_eq!(parsed(&again).unwrap(), acl);

        let canned = parsed(
            "<S3PutObjectAcl><AccessControlPolicy><CannedAccessControlList>public-read\
             </CannedAccessControlList></AccessControlPolicy></S3PutObjectAcl>",
        )
        .unwrap();
        assert_eq!(canned.canned_acl.as_deref(), Some("public-read"));
        let again = quick_xml::se::to_string_with_root("S3PutObjectAcl", &xml(&canned)).unwrap();
        assert!(!again.contains("<AccessControlList>"), "{again}");
        assert_eq!(parsed(&again).unwrap(), canned);
    }

    #[test]
    fn a_policy_is_a_list_with_an_owner_or_a_canned_acl() {
        for xml in [
            "<S3PutObjectAcl/>",
            "<S3PutObjectAcl><AccessControlPolicy/></S3PutObjectAcl>",
            "<S3PutObjectAcl><AccessControlPolicy><AccessControlList><Owner><ID>teifs</ID>\
             </Owner></AccessControlList><CannedAccessControlList>private\
             </CannedAccessControlList></AccessControlPolicy></S3PutObjectAcl>",
            "<S3PutObjectAcl><AccessControlPolicy><AccessControlList/>\
             </AccessControlPolicy></S3PutObjectAcl>",
            "<S3PutObjectAcl><AccessControlPolicy><CannedAccessControlList>everyone\
             </CannedAccessControlList></AccessControlPolicy></S3PutObjectAcl>",
            "<S3PutObjectAcl><AccessControlPolicy><AccessControlList><Grants><member><Grantee>\
             <TypeIdentifier>id</TypeIdentifier><Identifier>teifs</Identifier></Grantee>\
             <Permission>WRITE</Permission></member></Grants><Owner><ID>teifs</ID></Owner>\
             </AccessControlList></AccessControlPolicy></S3PutObjectAcl>",
        ] {
            assert!(parsed(xml).is_err(), "{xml}");
        }
        // An owner with no id is left for PutObjectAcl to judge.
        let blank = parsed(
            "<S3PutObjectAcl><AccessControlPolicy><AccessControlList><Owner><ID></ID>\
             <DisplayName></DisplayName></Owner></AccessControlList></AccessControlPolicy>\
             </S3PutObjectAcl>",
        )
        .unwrap();
        assert_eq!(blank.owner_id, None);
        assert_eq!(blank.owner_name, None);
        assert!(blank.grants.is_empty());
    }

    fn task() -> Task {
        Task {
            bucket: "photos".to_owned(),
            key: "a.jpg".to_owned(),
            version: Some("v1".to_owned()),
        }
    }

    fn client() -> Client {
        Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version_latest()
                .build(),
        )
    }

    #[test]
    fn each_task_puts_the_acl_on_its_object() {
        let client = client();
        let acl = parsed(GRANTS).unwrap();
        let put = request(&client, &acl, &task()).unwrap();
        let input = put.as_input();
        assert_eq!(input.get_bucket().as_deref(), Some("photos"));
        assert_eq!(input.get_key().as_deref(), Some("a.jpg"));
        assert_eq!(input.get_version_id().as_deref(), Some("v1"));
        assert_eq!(input.get_acl(), &None);
        let policy = input.get_access_control_policy().as_ref().unwrap();
        let owner = policy.owner().unwrap();
        assert_eq!(owner.id(), Some("teifs"));
        assert_eq!(owner.display_name(), Some("owner"));
        let grants = policy.grants();
        let grantee = |i: usize| grants[i].grantee().unwrap();
        assert_eq!(grantee(0).r#type(), &Type::CanonicalUser);
        assert_eq!(grantee(0).id(), Some("teifs"));
        assert_eq!(grants[0].permission(), Some(&Permission::FullControl));
        assert_eq!(grantee(1).r#type(), &Type::Group);
        assert_eq!(
            grantee(1).uri(),
            Some("http://acs.amazonaws.com/groups/global/AllUsers")
        );
        assert_eq!(grantee(2).r#type(), &Type::AmazonCustomerByEmail);
        assert_eq!(grantee(2).email_address(), Some("a@b.c"));
        assert_eq!(grants[2].permission(), Some(&Permission::ReadAcp));

        let canned = AclOperation {
            canned_acl: Some("public-read".to_owned()),
            ..AclOperation::default()
        };
        let put = request(&client, &canned, &task()).unwrap();
        assert_eq!(put.as_input().get_acl(), &Some(ObjectCannedAcl::PublicRead));
        assert!(put.as_input().get_access_control_policy().is_none());
    }
}
