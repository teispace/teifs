//! The managed policies every account has: AWS's (`arn:aws:iam::aws:policy/NAME`) and
//! MinIO's canned ones, under the same ARNs. Their documents are here, not in the
//! database; each has a row there only so attachments can name it (an anchor, whose
//! name is the policy's after [`ANCHOR`], which no customer's policy name can have).
//! They can be attached and read, never changed, tagged or deleted.

use teifs_meta::PolicyRow;

/// What starts an anchor row's name: `:` is never in a customer's policy name.
pub(crate) const ANCHOR: char = ':';

/// The account in built-in policies' ARNs, as AWS's managed policies have it.
pub(crate) const ACCOUNT: &str = "aws";

#[derive(Debug)]
pub(crate) struct Builtin {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    /// The version AWS has in effect (`v1` for MinIO's).
    pub(crate) version: u32,
    pub(crate) created_ms: i64,
    pub(crate) updated_ms: i64,
    pub(crate) document: &'static str,
}

impl Builtin {
    /// The policy's row (its anchor's, without [`ANCHOR`]).
    pub(crate) fn row(&self) -> PolicyRow {
        PolicyRow {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            path: "/".to_owned(),
            description: self.description.to_owned(),
            default_version: self.version,
            latest_version: self.version,
            created_ms: self.created_ms,
            updated_ms: self.updated_ms,
        }
    }

    /// The anchor row the database keeps.
    pub(crate) fn anchor(&self) -> PolicyRow {
        PolicyRow {
            name: format!("{ANCHOR}{}", self.name),
            ..self.row()
        }
    }
}

/// The built-in policy an anchor row's name names.
pub(crate) fn anchored(name: &str) -> Option<&'static Builtin> {
    let name = name.strip_prefix(ANCHOR)?;
    BUILTINS.iter().find(|b| b.name == name)
}

/// AWS's policies were created on 2015-02-06 at 18:40 UTC (`AdministratorAccess` a
/// minute before).
const AWS_CREATED: i64 = 1_423_248_000_000;
/// When TeiFS added MinIO's: 2026-10-01.
const MINIO_ADDED: i64 = 1_790_812_800_000;

/// Every built-in policy; ids are fixed (`ANPA` and 17 base32 characters of a hash of the
/// name) so that every drive has the same.
pub(crate) const BUILTINS: &[Builtin] = &[
    Builtin {
        id: "ANPA5TQ7CCDU27J3JGG4G",
        name: "AdministratorAccess",
        description: "Provides full access to AWS services and resources.",
        version: 1,
        created_ms: 1_423_247_940_000,
        updated_ms: 1_423_247_940_000,
        document: r#"{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : "*",
      "Resource" : "*"
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPANPXPLD5NGXKUDZRID",
        name: "AmazonS3FullAccess",
        description: "Provides full access to all buckets via the AWS Management Console.",
        version: 2,
        created_ms: AWS_CREATED,
        updated_ms: 1_632_773_760_000,
        document: r#"{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : [
        "s3:*",
        "s3-object-lambda:*"
      ],
      "Resource" : "*"
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAR6WQ75X2AI4SZR63P",
        name: "AmazonS3ReadOnlyAccess",
        description: "Provides read only access to all buckets via the AWS Management Console.",
        version: 3,
        created_ms: AWS_CREATED,
        updated_ms: 1_691_703_060_000,
        document: r#"{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : [
        "s3:Get*",
        "s3:List*",
        "s3:Describe*",
        "s3-object-lambda:Get*",
        "s3-object-lambda:List*"
      ],
      "Resource" : "*"
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAEZ3H2RYCZCZEKOVHG",
        name: "IAMFullAccess",
        description: "Provides full access to IAM via the AWS Management Console.",
        version: 2,
        created_ms: AWS_CREATED,
        updated_ms: 1_561_146_000_000,
        document: r#"{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : [
        "iam:*",
        "organizations:DescribeAccount",
        "organizations:DescribeOrganization",
        "organizations:DescribeOrganizationalUnit",
        "organizations:DescribePolicy",
        "organizations:ListChildren",
        "organizations:ListParents",
        "organizations:ListPoliciesForTarget",
        "organizations:ListRoots",
        "organizations:ListPolicies",
        "organizations:ListTargetsForPolicy"
      ],
      "Resource" : "*"
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPATFMM6Z2ODDPPBKV7Q",
        name: "IAMReadOnlyAccess",
        description: "Provides read only access to IAM via the AWS Management Console.",
        version: 4,
        created_ms: AWS_CREATED,
        updated_ms: 1_516_907_460_000,
        document: r#"{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : [
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:Get*",
        "iam:List*",
        "iam:SimulateCustomPolicy",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource" : "*"
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAR7HNHUW2II7DJGUQG",
        name: "readwrite",
        description: "MinIO's readwrite: every S3 action on every bucket.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAPR7OK5VMC73NUKHAS",
        name: "readonly",
        description: "MinIO's readonly: reading objects and buckets' locations.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:GetObject"],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPA7SS4WL5N3N3BJ37MH",
        name: "consolereadonly",
        description: "MinIO's consolereadonly: reading objects, listing them and buckets' locations.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAQK6TUYSVHP4FSUBP6",
        name: "writeonly",
        description: "MinIO's writeonly: writing objects.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAIDBBJNEBEWGVNCW5Y",
        name: "diagnostics",
        description: "MinIO's diagnostics: profiling, traces, logs, server information and metrics.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "admin:Profiling",
        "admin:ServerTrace",
        "admin:ConsoleLog",
        "admin:ServerInfo",
        "admin:TopLocksInfo",
        "admin:OBDInfo",
        "admin:BandwidthMonitor",
        "admin:Prometheus"
      ],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPASNZRKE5EJFXAK2SFJ",
        name: "iamAdmin",
        description: "MinIO's iamAdmin: users, groups, policies, service accounts, and IAM's export and import.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "admin:CreateUser",
        "admin:DeleteUser",
        "admin:ListUsers",
        "admin:EnableUser",
        "admin:DisableUser",
        "admin:GetUser",
        "admin:AddUserToGroup",
        "admin:RemoveUserFromGroup",
        "admin:GetGroup",
        "admin:ListGroups",
        "admin:EnableGroup",
        "admin:DisableGroup",
        "admin:CreatePolicy",
        "admin:DeletePolicy",
        "admin:GetPolicy",
        "admin:AttachUserOrGroupPolicy",
        "admin:UpdatePolicyAssociation",
        "admin:ListUserPolicies",
        "admin:CreateServiceAccount",
        "admin:UpdateServiceAccount",
        "admin:RemoveServiceAccount",
        "admin:ListServiceAccounts",
        "admin:ListTemporaryAccounts",
        "admin:ExportIAM",
        "admin:ImportIAM"
      ]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAH2YG2Y4J3TBHN2CT6",
        name: "infraAdmin",
        description: "MinIO's infraAdmin: the service, configuration, healing, pools, quotas, tiers, \
                      bucket metadata, batch jobs and the cluster's topology.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "admin:ServerUpdate",
        "admin:ServiceRestart",
        "admin:ServiceStop",
        "admin:ServiceFreeze",
        "admin:ServiceCordon",
        "admin:ServerInfo",
        "admin:StorageInfo",
        "admin:ConfigUpdate",
        "admin:Heal",
        "admin:ForceUnlock",
        "admin:Decommission",
        "admin:Rebalance",
        "admin:SetBucketQuota",
        "admin:GetBucketQuota",
        "admin:SetBucketCompression",
        "admin:GetBucketCompression",
        "admin:SetTier",
        "admin:ListTier",
        "admin:LicenseInfo",
        "admin:DataUsageInfo",
        "admin:ImportBucketMetadata",
        "admin:ExportBucketMetadata",
        "admin:StartBatchJob",
        "admin:ListBatchJobs",
        "admin:DescribeBatchJob",
        "admin:CancelBatchJob",
        "admin:GenerateBatchJob",
        "admin:InventoryControl",
        "admin:ClusterInfo",
        "admin:PoolList",
        "admin:PoolInfo",
        "admin:NodeList",
        "admin:NodeInfo",
        "admin:SetInfo",
        "admin:DriveList",
        "admin:DriveInfo"
      ]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAIHC3TD4EQJE2HVZAR",
        name: "replicationAdmin",
        description: "MinIO's replicationAdmin: site and bucket replication.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "admin:SiteReplicationAdd",
        "admin:SiteReplicationDisable",
        "admin:SiteReplicationRemove",
        "admin:SiteReplicationResync",
        "admin:SiteReplicationInfo",
        "admin:SiteReplicationOperation",
        "admin:TablesReplicationAdd",
        "admin:TablesReplicationRemove",
        "admin:TablesReplicationInfo",
        "admin:TablesReplicationStartFailover",
        "admin:TablesReplicationCatalogAdmin",
        "admin:ReplicationDiff"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetReplicationConfiguration",
        "s3:PutReplicationConfiguration",
        "s3:ResetBucketReplicationState",
        "s3:GetObjectVersionForReplication"
      ],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPA5R7LU2BG5SZSFSEO3",
        name: "securityAuditAdmin",
        description: "MinIO's securityAuditAdmin: reading IAM, the cluster's topology, diagnostics \
                      and buckets' security settings.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "admin:ListUsers",
        "admin:GetUser",
        "admin:ListGroups",
        "admin:GetGroup",
        "admin:GetPolicy",
        "admin:ListUserPolicies",
        "admin:ListServiceAccounts",
        "admin:ListTemporaryAccounts",
        "admin:ExportIAM",
        "admin:SiteReplicationInfo",
        "admin:TablesReplicationInfo",
        "admin:ServerInfo",
        "admin:StorageInfo",
        "admin:DataUsageInfo",
        "admin:LicenseInfo",
        "admin:ClusterInfo",
        "admin:PoolList",
        "admin:PoolInfo",
        "admin:NodeList",
        "admin:NodeInfo",
        "admin:SetInfo",
        "admin:DriveList",
        "admin:DriveInfo",
        "admin:Profiling",
        "admin:ServerTrace",
        "admin:ConsoleLog",
        "admin:TopLocksInfo",
        "admin:OBDInfo",
        "admin:BandwidthMonitor",
        "admin:Prometheus"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPolicy",
        "s3:GetBucketLocation",
        "s3:GetBucketNotification",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetReplicationConfiguration"
      ],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
    Builtin {
        id: "ANPAZRU4D7IKNYDBWXUWB",
        name: "consoleAdmin",
        description: "MinIO's consoleAdmin: every admin, KMS and S3 action.",
        version: 1,
        created_ms: MINIO_ADDED,
        updated_ms: MINIO_ADDED,
        document: r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["admin:*"]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": ["arn:aws:s3:::*"]
    }
  ]
}"#,
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn every_builtin_is_a_valid_managed_policy_with_its_own_id_and_name() {
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for b in BUILTINS {
            assert!(ids.insert(b.id), "{}", b.id);
            assert!(names.insert(b.name.to_ascii_lowercase()), "{}", b.name);
            assert_eq!(b.id.len(), 21, "{}", b.id);
            assert!(b.id.starts_with("ANPA"), "{}", b.id);
            crate::rules::name("policy name", b.name, crate::rules::OTHER_NAME).unwrap();
            let document = crate::state::Document::parse(b.document)
                .unwrap_or_else(|e| panic!("{}: {e}", b.name));
            assert!(document.size <= crate::rules::MANAGED_SIZE, "{}", b.name);
            assert!(b.created_ms <= b.updated_ms, "{}", b.name);
            assert_eq!(anchored(&b.anchor().name).map(|a| a.id), Some(b.id));
        }
        assert!(anchored("readwrite").is_none());
        assert!(anchored(":nothing").is_none());
    }
}
