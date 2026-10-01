//! `MinIO`'s admin and KMS actions, its "policy-based access control": policies written
//! for `MinIO` name them, and each of TeiFS's own admin actions answers to the `MinIO` names
//! of the same permission too, so `admin:ServerInfo` lets a user read the server's info
//! as `teifs:GetServerInfo` does. As on `MinIO`, a statement of these actions alone needs
//! no `Resource`, and an admin action that isn't a bucket's ignores the statement's
//! `Resource` (it has none of its own).

/// `MinIO`'s admin actions (`admin:*` aside), sorted.
pub const ADMIN_ACTIONS: &[&str] = &[
    "admin:AddUserToGroup",
    "admin:AttachUserOrGroupPolicy",
    "admin:BandwidthMonitor",
    "admin:CancelBatchJob",
    "admin:ChangeMyPassword",
    "admin:ClusterInfo",
    "admin:ConfigUpdate",
    "admin:ConsoleLog",
    "admin:CreatePolicy",
    "admin:CreateServiceAccount",
    "admin:CreateUser",
    "admin:DataUsageInfo",
    "admin:Decommission",
    "admin:DeletePolicy",
    "admin:DeleteUser",
    "admin:DeltaSharing",
    "admin:DeltaSharingCreateShare",
    "admin:DeltaSharingCreateToken",
    "admin:DeltaSharingDeleteShare",
    "admin:DeltaSharingDeleteToken",
    "admin:DeltaSharingGetShare",
    "admin:DeltaSharingListShares",
    "admin:DeltaSharingListTokens",
    "admin:DeltaSharingUpdateShare",
    "admin:DescribeBatchJob",
    "admin:DisableGroup",
    "admin:DisableUser",
    "admin:DistJobStatus",
    "admin:DriveInfo",
    "admin:DriveList",
    "admin:EnableGroup",
    "admin:EnableUser",
    "admin:ExportBucketMetadata",
    "admin:ExportIAM",
    "admin:ForceUnlock",
    "admin:GenerateBatchJob",
    "admin:GetBucketCompression",
    "admin:GetBucketQuota",
    "admin:GetBucketTarget",
    "admin:GetGroup",
    "admin:GetPolicy",
    "admin:GetUser",
    "admin:Heal",
    "admin:ImportBucketMetadata",
    "admin:ImportIAM",
    "admin:InspectData",
    "admin:InventoryControl",
    "admin:KMSBackup",
    "admin:KMSCreateKey",
    "admin:KMSEnable",
    "admin:KMSKeyRotate",
    "admin:KMSKeyStatus",
    "admin:KMSRestore",
    "admin:LicenseInfo",
    "admin:ListBatchJobs",
    "admin:ListGroups",
    "admin:ListServiceAccounts",
    "admin:ListTemporaryAccounts",
    "admin:ListTier",
    "admin:ListUserPolicies",
    "admin:ListUsers",
    "admin:NodeInfo",
    "admin:NodeList",
    "admin:OBDInfo",
    "admin:PoolInfo",
    "admin:PoolList",
    "admin:Profiling",
    "admin:Prometheus",
    "admin:ReadAPILogs",
    "admin:ReadAlerts",
    "admin:ReadAuditLogs",
    "admin:ReadErrorLogs",
    "admin:Rebalance",
    "admin:RemoveServiceAccount",
    "admin:RemoveUserFromGroup",
    "admin:ReplicationDiff",
    "admin:ServerInfo",
    "admin:ServerTrace",
    "admin:ServerUpdate",
    "admin:ServiceCordon",
    "admin:ServiceFreeze",
    "admin:ServiceRestart",
    "admin:ServiceStop",
    "admin:SetBucketCompression",
    "admin:SetBucketQuota",
    "admin:SetBucketTarget",
    "admin:SetInfo",
    "admin:SetRootAccess",
    "admin:SetTier",
    "admin:SiteReplicationAdd",
    "admin:SiteReplicationDisable",
    "admin:SiteReplicationInfo",
    "admin:SiteReplicationOperation",
    "admin:SiteReplicationRemove",
    "admin:SiteReplicationResync",
    "admin:StartBatchJob",
    "admin:StorageInfo",
    "admin:TablesReplicationAdd",
    "admin:TablesReplicationCatalogAdmin",
    "admin:TablesReplicationInfo",
    "admin:TablesReplicationRemove",
    "admin:TablesReplicationStartFailover",
    "admin:TopLocksInfo",
    "admin:UpdatePolicyAssociation",
    "admin:UpdateServiceAccount",
];

/// The admin actions on a bucket, whose ARN a statement's `Resource` is matched against.
const BUCKET_ADMIN_ACTIONS: &[&str] = &[
    "admin:ExportBucketMetadata",
    "admin:GetBucketCompression",
    "admin:GetBucketQuota",
    "admin:GetBucketTarget",
    "admin:Heal",
    "admin:ImportBucketMetadata",
    "admin:InventoryControl",
    "admin:ReplicationDiff",
    "admin:SetBucketCompression",
    "admin:SetBucketQuota",
    "admin:SetBucketTarget",
];

/// `MinIO`'s KMS actions (`kms:*` aside), sorted.
pub const KMS_ACTIONS: &[&str] = &[
    "kms:API",
    "kms:AssignPolicy",
    "kms:AuditLog",
    "kms:CreateKey",
    "kms:DeleteIdentity",
    "kms:DeleteKey",
    "kms:DeletePolicy",
    "kms:DescribeIdentity",
    "kms:DescribePolicy",
    "kms:DescribeSelfIdentity",
    "kms:Enable",
    "kms:ErrorLog",
    "kms:GetPolicy",
    "kms:ImportKey",
    "kms:KeyRotate",
    "kms:KeyStatus",
    "kms:ListIdentities",
    "kms:ListKeys",
    "kms:ListPolicies",
    "kms:Metrics",
    "kms:SetPolicy",
    "kms:Status",
    "kms:Version",
];

/// TeiFS's admin actions, sorted, and the `MinIO` actions that grant the same
/// permission (any of them does, as `MinIO` takes any for its request).
const SAME_AS: &[(&str, &[&str])] = &[
    ("teifs:AttachLDAPPolicy", &["admin:UpdatePolicyAssociation"]),
    ("teifs:DetachLDAPPolicy", &["admin:UpdatePolicyAssociation"]),
    (
        "teifs:ExportBucketMetadata",
        &["admin:ExportBucketMetadata"],
    ),
    ("teifs:ExportIAM", &["admin:ExportIAM"]),
    ("teifs:GetMetrics", &["admin:Prometheus"]),
    ("teifs:GetServerConfig", &["admin:ConfigUpdate"]),
    ("teifs:GetServerInfo", &["admin:ServerInfo"]),
    (
        "teifs:ImportBucketMetadata",
        &["admin:ImportBucketMetadata"],
    ),
    (
        "teifs:ListLDAPPolicies",
        &[
            "admin:ListGroups",
            "admin:ListUserPolicies",
            "admin:ListUsers",
        ],
    ),
    ("teifs:ServerTrace", &["admin:ServerTrace"]),
];

/// The `MinIO` actions that grant the same permission as `action`, if it's one of
/// TeiFS's admin actions.
#[must_use]
pub fn minio_names(action: &str) -> &'static [&'static str] {
    SAME_AS
        .binary_search_by(|(name, _)| (*name).cmp(action))
        .map_or(&[], |i| SAME_AS[i].1)
}

/// How policies name a key of `MinIO`'s KMS: `arn:minio:kms:::KEY`, with wildcards.
pub const KMS_KEY_ARN_PREFIX: &str = "arn:minio:kms:::";

/// `arn:minio:kms:::KEY`, the resource a call on one key of the KMS is decided on.
#[must_use]
pub fn kms_key_arn(key: &str) -> String {
    format!("{KMS_KEY_ARN_PREFIX}{key}")
}

/// Whether `service:` (`admin`, `kms`) is one of `MinIO`'s, whose statements need no
/// `Resource`.
pub(crate) fn resourceless_service(service: &str) -> bool {
    service.eq_ignore_ascii_case("admin") || service.eq_ignore_ascii_case("kms")
}

/// Whether deciding `action` ignores a statement's `Resource`: TeiFS's admin actions and
/// `MinIO`'s that aren't a bucket's, which apply to no resource.
pub(crate) fn ignores_resource(action: &str) -> bool {
    let Some((service, _)) = action.split_once(':') else {
        return false;
    };
    service == "teifs"
        || (service == "admin" && BUCKET_ADMIN_ACTIONS.binary_search(&action).is_err())
        || service == "kms"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_are_sorted_and_named_alike() {
        for list in [ADMIN_ACTIONS, BUCKET_ADMIN_ACTIONS, KMS_ACTIONS] {
            assert!(list.is_sorted(), "{list:?}");
        }
        assert!(SAME_AS.is_sorted_by_key(|(name, _)| *name));
        for action in BUCKET_ADMIN_ACTIONS {
            assert!(ADMIN_ACTIONS.contains(action), "{action}");
        }
        for (action, names) in SAME_AS {
            assert!(action.starts_with("teifs:"));
            for name in *names {
                assert!(ADMIN_ACTIONS.contains(name), "{action}: {name}");
            }
        }
        assert_eq!(minio_names("teifs:GetServerInfo"), ["admin:ServerInfo"]);
        assert!(minio_names("teifs:TakeSnapshot").is_empty());
        assert!(minio_names("s3:GetObject").is_empty());
        assert!(ignores_resource("teifs:GetServerInfo") && ignores_resource("admin:ServerInfo"));
        assert!(ignores_resource("kms:Status"));
        assert!(!ignores_resource("admin:SetBucketQuota") && !ignores_resource("s3:GetObject"));
        assert!(!ignores_resource("sts:AssumeRole") && !ignores_resource("*"));
    }
}
