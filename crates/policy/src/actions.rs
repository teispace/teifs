//! Which IAM actions each S3 operation needs, on which resource.
//!
//! Checked against AWS's Service Authorization Reference (a trimmed copy is in
//! `tests/fixtures/s3-reference.json`): every action named here is one S3 defines, and
//! every action an operation needs is one the reference lists for it. Where the
//! reference lists several, which apply depends on the request: a `versionId` makes it
//! the `…Version` action (asking for an old version is a different permission), a tag,
//! ACL or object-lock header adds that action.

use std::ops::Deref;

/// What an action applies to, and so which ARN to decide it for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The account ([`crate::S3_ACCOUNT_RESOURCE`]).
    Account,
    /// The bucket ([`crate::bucket_arn`]).
    Bucket,
    /// The object ([`crate::object_arn`]).
    Object,
    /// The object a copy or rename reads from (`x-amz-copy-source`, the renamed key).
    Source,
    /// Something S3 has that TeiFS doesn't (access points, jobs, Storage Lens…).
    Other,
}

/// One permission a request needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorization {
    /// `s3:GetObject`.
    pub action: &'static str,
    /// What to decide it for.
    pub target: Target,
    /// `false` when the request goes ahead without it, only leaving out what it
    /// covers (a `GetObject` without `s3:GetObjectRetention` gets no retention headers).
    pub required: bool,
}

/// The facts about a request that change which actions it needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Facts {
    /// It names a `versionId`.
    pub version_id: bool,
    /// Its copy source names a `versionId`.
    pub source_version_id: bool,
    /// It sets tags (`x-amz-tagging`).
    pub tagging: bool,
    /// It sets an ACL (`x-amz-acl` or an `x-amz-grant-…` header).
    pub acl: bool,
    /// It sets a retention (`x-amz-object-lock-mode` / `…-retain-until-date`).
    pub retention: bool,
    /// It sets a legal hold (`x-amz-object-lock-legal-hold`).
    pub legal_hold: bool,
    /// It asks to bypass governance retention (`x-amz-bypass-governance-retention`).
    pub bypass_governance: bool,
    /// A new bucket with Object Lock (`x-amz-bucket-object-lock-enabled`).
    pub object_lock: bool,
    /// A new bucket with an ownership setting (`x-amz-object-ownership`).
    pub ownership: bool,
    /// A new bucket with tags (its configuration's `Tags`).
    pub bucket_tags: bool,
    /// Another server replicating (`MinIO`'s `x-minio-source-replication-request`).
    pub replication: bool,
    /// A replicated delete marker (`MinIO`'s `x-minio-source-deletemarker`).
    pub replica_marker: bool,
}

/// The permissions one request needs (at most six).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorizations {
    items: [Authorization; 6],
    len: usize,
}

impl Authorizations {
    const fn new() -> Self {
        Self {
            items: [Authorization {
                action: "",
                target: Target::Other,
                required: false,
            }; 6],
            len: 0,
        }
    }

    fn push(&mut self, action: &'static str, target: Target, required: bool) {
        self.items[self.len] = Authorization {
            action,
            target,
            required,
        };
        self.len += 1;
    }

    /// `action` on its own resource (the object, the bucket or the account).
    fn need(&mut self, action: &'static str) {
        self.push(action, target(action), true);
    }

    /// `action`, also needed when `when`.
    fn need_if(&mut self, when: bool, action: &'static str) {
        if when {
            self.need(action);
        }
    }

    /// `action`, or `version` when the request names a version.
    fn versioned(&mut self, facts: &Facts, action: &'static str, version: &'static str) {
        self.need(if facts.version_id { version } else { action });
    }

    /// The source of a copy: `s3:GetObject`, or `s3:GetObjectVersion` for a version.
    fn source(&mut self, facts: &Facts) {
        let action = if facts.source_version_id {
            "s3:GetObjectVersion"
        } else {
            "s3:GetObject"
        };
        self.push(action, Target::Source, true);
    }

    /// What writing an object with these headers needs.
    fn write(&mut self, facts: &Facts) {
        self.need("s3:PutObject");
        self.need_if(facts.tagging, "s3:PutObjectTagging");
        self.need_if(facts.acl, "s3:PutObjectAcl");
        self.need_if(facts.retention, "s3:PutObjectRetention");
        self.need_if(facts.legal_hold, "s3:PutObjectLegalHold");
    }

    /// Reading an object: the object (or version), and what only adds headers.
    fn read(&mut self, facts: &Facts, extras: &[&'static str]) {
        self.versioned(facts, "s3:GetObject", "s3:GetObjectVersion");
        for extra in extras {
            self.push(extra, Target::Object, false);
        }
    }
}

impl Deref for Authorizations {
    type Target = [Authorization];

    fn deref(&self) -> &[Authorization] {
        &self.items[..self.len]
    }
}

/// The permissions `operation` (an S3 API name: `GetObject`) needs, or `None` for an
/// operation with none TeiFS can grant (only the root user may make it).
#[must_use]
pub fn authorizations(operation: &str, facts: &Facts) -> Option<Authorizations> {
    let mut needs = Authorizations::new();
    match operation {
        // Reading an object also shows its tag count and lock state to whoever may
        // read those. The reference lists neither `GetObjectVersion` nor
        // `GetObjectTagging` for HeadObject; its API page says it needs "the relevant
        // read object (or version) permission", and returns x-amz-tagging-count only to
        // those who may read tags, as GetObject does.
        "GetObject" | "HeadObject" => needs.read(
            facts,
            &[
                "s3:GetObjectTagging",
                "s3:GetObjectRetention",
                "s3:GetObjectLegalHold",
            ],
        ),
        "GetObjectAttributes" => needs.read(facts, &[]),
        // A browser upload (a form; not in the SDK's reference) is a PutObject.
        "PutObject" => {
            needs.write(facts);
            needs.need_if(facts.replication, "s3:ReplicateObject");
        }
        "PostObject" | "CreateMultipartUpload" => needs.write(facts),
        "CopyObject" => {
            needs.source(facts);
            needs.write(facts);
        }
        "UploadPartCopy" => {
            needs.source(facts);
            needs.need("s3:PutObject");
        }
        // Not in the reference for general buckets: TeiFS's rename reads the old key,
        // writes the new one and deletes the old one, so it needs all three (without
        // `GetObject` on the source, a rename could move an object somewhere readable).
        "RenameObject" => {
            needs.push("s3:GetObject", Target::Source, true);
            needs.push("s3:DeleteObject", Target::Source, true);
            needs.need("s3:PutObject");
        }
        // A replicated delete marker names its id but removes nothing, as `MinIO` decides
        // it: replicating it needs `s3:ReplicateDelete`.
        "DeleteObject" if facts.replication && facts.replica_marker => {
            needs.need("s3:DeleteObject");
            needs.need("s3:ReplicateDelete");
        }
        "DeleteObject" | "DeleteObjects" => {
            needs.versioned(facts, "s3:DeleteObject", "s3:DeleteObjectVersion");
            needs.need_if(facts.bypass_governance, "s3:BypassGovernanceRetention");
        }
        "PutObjectRetention" => {
            needs.need("s3:PutObjectRetention");
            needs.need_if(facts.bypass_governance, "s3:BypassGovernanceRetention");
        }
        "CreateBucket" => {
            needs.need("s3:CreateBucket");
            needs.need_if(facts.object_lock, "s3:PutBucketObjectLockConfiguration");
            needs.need_if(facts.object_lock, "s3:PutBucketVersioning");
            needs.need_if(facts.ownership, "s3:PutBucketOwnershipControls");
            needs.need_if(facts.acl, "s3:PutBucketAcl");
            // "You must have the s3:TagResource permission to create a general purpose
            // bucket with tags" (CreateBucketConfiguration); not in the reference.
            needs.need_if(facts.bucket_tags, "s3:TagResource");
        }
        "ListObjects" | "ListObjectsV2" => {
            needs.need("s3:ListBucket");
            // Owners are listed only for those allowed to read ACLs.
            needs.push("s3:GetObjectAcl", Target::Object, false);
        }
        "GetObjectTagging" => {
            needs.versioned(facts, "s3:GetObjectTagging", "s3:GetObjectVersionTagging");
        }
        "PutObjectTagging" => {
            needs.versioned(facts, "s3:PutObjectTagging", "s3:PutObjectVersionTagging");
        }
        "DeleteObjectTagging" => needs.versioned(
            facts,
            "s3:DeleteObjectTagging",
            "s3:DeleteObjectVersionTagging",
        ),
        "GetObjectAcl" => needs.versioned(facts, "s3:GetObjectAcl", "s3:GetObjectVersionAcl"),
        "PutObjectAcl" => needs.versioned(facts, "s3:PutObjectAcl", "s3:PutObjectVersionAcl"),
        _ => needs.need(SIMPLE.iter().find(|(op, _)| *op == operation)?.1),
    }
    Some(needs)
}

/// Operations that always need exactly one action.
const SIMPLE: &[(&str, &str)] = &[
    ("AbortMultipartUpload", "s3:AbortMultipartUpload"),
    ("CompleteMultipartUpload", "s3:PutObject"),
    (
        "CreateBucketMetadataConfiguration",
        "s3:CreateBucketMetadataTableConfiguration",
    ),
    (
        "CreateBucketMetadataTableConfiguration",
        "s3:CreateBucketMetadataTableConfiguration",
    ),
    ("DeleteBucket", "s3:DeleteBucket"),
    (
        "DeleteBucketAnalyticsConfiguration",
        "s3:PutAnalyticsConfiguration",
    ),
    ("DeleteBucketCors", "s3:PutBucketCORS"),
    ("DeleteBucketEncryption", "s3:PutEncryptionConfiguration"),
    (
        "DeleteBucketIntelligentTieringConfiguration",
        "s3:PutIntelligentTieringConfiguration",
    ),
    (
        "DeleteBucketInventoryConfiguration",
        "s3:PutInventoryConfiguration",
    ),
    ("DeleteBucketLifecycle", "s3:PutLifecycleConfiguration"),
    (
        "DeleteBucketMetadataConfiguration",
        "s3:DeleteBucketMetadataTableConfiguration",
    ),
    (
        "DeleteBucketMetadataTableConfiguration",
        "s3:DeleteBucketMetadataTableConfiguration",
    ),
    (
        "DeleteBucketMetricsConfiguration",
        "s3:PutMetricsConfiguration",
    ),
    (
        "DeleteBucketOwnershipControls",
        "s3:PutBucketOwnershipControls",
    ),
    ("DeleteBucketPolicy", "s3:DeleteBucketPolicy"),
    ("DeleteBucketReplication", "s3:PutReplicationConfiguration"),
    ("DeleteBucketTagging", "s3:PutBucketTagging"),
    ("DeleteBucketWebsite", "s3:DeleteBucketWebsite"),
    ("DeletePublicAccessBlock", "s3:PutBucketPublicAccessBlock"),
    (
        "GetBucketAccelerateConfiguration",
        "s3:GetAccelerateConfiguration",
    ),
    ("GetBucketAbac", "s3:GetBucketAbac"),
    ("GetBucketAcl", "s3:GetBucketAcl"),
    (
        "GetBucketAnalyticsConfiguration",
        "s3:GetAnalyticsConfiguration",
    ),
    ("GetBucketCors", "s3:GetBucketCORS"),
    ("GetBucketEncryption", "s3:GetEncryptionConfiguration"),
    (
        "GetBucketIntelligentTieringConfiguration",
        "s3:GetIntelligentTieringConfiguration",
    ),
    (
        "GetBucketInventoryConfiguration",
        "s3:GetInventoryConfiguration",
    ),
    ("GetBucketLifecycle", "s3:GetLifecycleConfiguration"),
    (
        "GetBucketLifecycleConfiguration",
        "s3:GetLifecycleConfiguration",
    ),
    ("GetBucketLocation", "s3:GetBucketLocation"),
    ("GetBucketLogging", "s3:GetBucketLogging"),
    (
        "GetBucketMetadataConfiguration",
        "s3:GetBucketMetadataTableConfiguration",
    ),
    (
        "GetBucketMetadataTableConfiguration",
        "s3:GetBucketMetadataTableConfiguration",
    ),
    (
        "GetBucketMetricsConfiguration",
        "s3:GetMetricsConfiguration",
    ),
    ("GetBucketNotification", "s3:GetBucketNotification"),
    (
        "GetBucketNotificationConfiguration",
        "s3:GetBucketNotification",
    ),
    (
        "GetBucketOwnershipControls",
        "s3:GetBucketOwnershipControls",
    ),
    ("GetBucketPolicy", "s3:GetBucketPolicy"),
    ("GetBucketPolicyStatus", "s3:GetBucketPolicyStatus"),
    ("GetBucketReplication", "s3:GetReplicationConfiguration"),
    ("GetBucketRequestPayment", "s3:GetBucketRequestPayment"),
    ("GetBucketTagging", "s3:GetBucketTagging"),
    ("GetBucketVersioning", "s3:GetBucketVersioning"),
    ("GetBucketWebsite", "s3:GetBucketWebsite"),
    ("GetObjectLegalHold", "s3:GetObjectLegalHold"),
    (
        "GetObjectLockConfiguration",
        "s3:GetBucketObjectLockConfiguration",
    ),
    ("GetObjectRetention", "s3:GetObjectRetention"),
    ("GetObjectTorrent", "s3:GetObject"),
    ("GetPublicAccessBlock", "s3:GetBucketPublicAccessBlock"),
    ("HeadBucket", "s3:ListBucket"),
    (
        "ListBucketAnalyticsConfigurations",
        "s3:GetAnalyticsConfiguration",
    ),
    (
        "ListBucketIntelligentTieringConfigurations",
        "s3:GetIntelligentTieringConfiguration",
    ),
    (
        "ListBucketInventoryConfigurations",
        "s3:GetInventoryConfiguration",
    ),
    (
        "ListBucketMetricsConfigurations",
        "s3:GetMetricsConfiguration",
    ),
    ("ListBuckets", "s3:ListAllMyBuckets"),
    ("ListMultipartUploads", "s3:ListBucketMultipartUploads"),
    ("ListObjectVersions", "s3:ListBucketVersions"),
    ("ListParts", "s3:ListMultipartUploadParts"),
    (
        "PutBucketAccelerateConfiguration",
        "s3:PutAccelerateConfiguration",
    ),
    ("PutBucketAbac", "s3:PutBucketAbac"),
    ("PutBucketAcl", "s3:PutBucketAcl"),
    (
        "PutBucketAnalyticsConfiguration",
        "s3:PutAnalyticsConfiguration",
    ),
    ("PutBucketCors", "s3:PutBucketCORS"),
    ("PutBucketEncryption", "s3:PutEncryptionConfiguration"),
    (
        "PutBucketIntelligentTieringConfiguration",
        "s3:PutIntelligentTieringConfiguration",
    ),
    (
        "PutBucketInventoryConfiguration",
        "s3:PutInventoryConfiguration",
    ),
    ("PutBucketLifecycle", "s3:PutLifecycleConfiguration"),
    (
        "PutBucketLifecycleConfiguration",
        "s3:PutLifecycleConfiguration",
    ),
    ("PutBucketLogging", "s3:PutBucketLogging"),
    (
        "PutBucketMetricsConfiguration",
        "s3:PutMetricsConfiguration",
    ),
    (
        "PutBucketNotificationConfiguration",
        "s3:PutBucketNotification",
    ),
    (
        "PutBucketOwnershipControls",
        "s3:PutBucketOwnershipControls",
    ),
    ("PutBucketPolicy", "s3:PutBucketPolicy"),
    ("PutBucketReplication", "s3:PutReplicationConfiguration"),
    ("PutBucketRequestPayment", "s3:PutBucketRequestPayment"),
    ("PutBucketTagging", "s3:PutBucketTagging"),
    ("PutBucketVersioning", "s3:PutBucketVersioning"),
    ("PutBucketWebsite", "s3:PutBucketWebsite"),
    ("PutObjectLegalHold", "s3:PutObjectLegalHold"),
    (
        "PutObjectLockConfiguration",
        "s3:PutBucketObjectLockConfiguration",
    ),
    ("PutPublicAccessBlock", "s3:PutBucketPublicAccessBlock"),
    ("RestoreObject", "s3:RestoreObject"),
    ("SelectObjectContent", "s3:GetObject"),
    (
        "UpdateBucketMetadataInventoryTableConfiguration",
        "s3:UpdateBucketMetadataInventoryTableConfiguration",
    ),
    (
        "UpdateBucketMetadataJournalTableConfiguration",
        "s3:UpdateBucketMetadataJournalTableConfiguration",
    ),
    ("UploadPart", "s3:PutObject"),
];

/// The action's own target, from [`ACTIONS`].
fn target(action: &str) -> Target {
    ACTIONS
        .binary_search_by(|(name, _)| (*name).cmp(action))
        .map_or(Target::Other, |i| ACTIONS[i].1)
}

/// `MinIO`'s actions that S3 doesn't have, for its APIs TeiFS serves too: policies
/// written for `MinIO` may name them. Sorted, and none is an S3 action.
pub const MINIO_ACTIONS: &[(&str, Target)] = &[
    ("s3:ListenBucketNotification", Target::Bucket),
    ("s3:ListenNotification", Target::Other),
];

/// Every S3 action, sorted, with what it applies to.
pub const ACTIONS: &[(&str, Target)] = &[
    ("s3:AbortMultipartUpload", Target::Object),
    ("s3:AllowVendedLogDeliveryForResource", Target::Bucket),
    ("s3:AssociateAccessGrantsIdentityCenter", Target::Other),
    ("s3:BypassGovernanceRetention", Target::Object),
    ("s3:CreateAccessGrant", Target::Other),
    ("s3:CreateAccessGrantsInstance", Target::Other),
    ("s3:CreateAccessGrantsLocation", Target::Other),
    ("s3:CreateAccessPoint", Target::Other),
    ("s3:CreateAccessPointForObjectLambda", Target::Other),
    ("s3:CreateBucket", Target::Bucket),
    ("s3:CreateBucketMetadataTableConfiguration", Target::Bucket),
    ("s3:CreateJob", Target::Account),
    ("s3:CreateMultiRegionAccessPoint", Target::Other),
    ("s3:CreateStorageLensGroup", Target::Account),
    ("s3:DeleteAccessGrant", Target::Other),
    ("s3:DeleteAccessGrantsInstance", Target::Other),
    ("s3:DeleteAccessGrantsInstanceResourcePolicy", Target::Other),
    ("s3:DeleteAccessGrantsLocation", Target::Other),
    ("s3:DeleteAccessPoint", Target::Other),
    ("s3:DeleteAccessPointForObjectLambda", Target::Other),
    ("s3:DeleteAccessPointPolicy", Target::Other),
    ("s3:DeleteAccessPointPolicyForObjectLambda", Target::Other),
    ("s3:DeleteBucket", Target::Bucket),
    ("s3:DeleteBucketMetadataTableConfiguration", Target::Bucket),
    ("s3:DeleteBucketPolicy", Target::Bucket),
    ("s3:DeleteBucketWebsite", Target::Bucket),
    ("s3:DeleteJobTagging", Target::Other),
    ("s3:DeleteMultiRegionAccessPoint", Target::Other),
    ("s3:DeleteObject", Target::Object),
    ("s3:DeleteObjectAnnotation", Target::Object),
    ("s3:DeleteObjectTagging", Target::Object),
    ("s3:DeleteObjectVersion", Target::Object),
    ("s3:DeleteObjectVersionAnnotation", Target::Object),
    ("s3:DeleteObjectVersionTagging", Target::Object),
    ("s3:DeleteStorageLensConfiguration", Target::Other),
    ("s3:DeleteStorageLensConfigurationTagging", Target::Other),
    ("s3:DeleteStorageLensGroup", Target::Other),
    ("s3:DescribeJob", Target::Other),
    ("s3:DescribeMultiRegionAccessPointOperation", Target::Other),
    ("s3:DissociateAccessGrantsIdentityCenter", Target::Other),
    ("s3:GetAccelerateConfiguration", Target::Bucket),
    ("s3:GetAccessGrant", Target::Other),
    ("s3:GetAccessGrantsInstance", Target::Other),
    ("s3:GetAccessGrantsInstanceForPrefix", Target::Other),
    ("s3:GetAccessGrantsInstanceResourcePolicy", Target::Other),
    ("s3:GetAccessGrantsLocation", Target::Other),
    ("s3:GetAccessPoint", Target::Account),
    (
        "s3:GetAccessPointConfigurationForObjectLambda",
        Target::Other,
    ),
    ("s3:GetAccessPointForObjectLambda", Target::Other),
    ("s3:GetAccessPointPolicy", Target::Other),
    ("s3:GetAccessPointPolicyForObjectLambda", Target::Other),
    ("s3:GetAccessPointPolicyStatus", Target::Other),
    (
        "s3:GetAccessPointPolicyStatusForObjectLambda",
        Target::Other,
    ),
    ("s3:GetAccountPublicAccessBlock", Target::Account),
    ("s3:GetAnalyticsConfiguration", Target::Bucket),
    ("s3:GetBucketAbac", Target::Bucket),
    ("s3:GetBucketAcl", Target::Bucket),
    ("s3:GetBucketCORS", Target::Bucket),
    ("s3:GetBucketLocation", Target::Bucket),
    ("s3:GetBucketLogging", Target::Bucket),
    ("s3:GetBucketMetadataTableConfiguration", Target::Bucket),
    ("s3:GetBucketNotification", Target::Bucket),
    ("s3:GetBucketObjectLockConfiguration", Target::Bucket),
    ("s3:GetBucketOwnershipControls", Target::Bucket),
    ("s3:GetBucketPolicy", Target::Bucket),
    ("s3:GetBucketPolicyStatus", Target::Bucket),
    ("s3:GetBucketPublicAccessBlock", Target::Bucket),
    ("s3:GetBucketRequestPayment", Target::Bucket),
    ("s3:GetBucketTagging", Target::Bucket),
    ("s3:GetBucketVersioning", Target::Bucket),
    ("s3:GetBucketWebsite", Target::Bucket),
    ("s3:GetDataAccess", Target::Other),
    ("s3:GetEncryptionConfiguration", Target::Bucket),
    ("s3:GetIntelligentTieringConfiguration", Target::Bucket),
    ("s3:GetInventoryConfiguration", Target::Bucket),
    ("s3:GetJobTagging", Target::Other),
    ("s3:GetLifecycleConfiguration", Target::Bucket),
    ("s3:GetMetricsConfiguration", Target::Bucket),
    ("s3:GetMultiRegionAccessPoint", Target::Other),
    ("s3:GetMultiRegionAccessPointPolicy", Target::Other),
    ("s3:GetMultiRegionAccessPointPolicyStatus", Target::Other),
    ("s3:GetMultiRegionAccessPointRoutes", Target::Other),
    ("s3:GetObject", Target::Object),
    ("s3:GetObjectAcl", Target::Object),
    ("s3:GetObjectAnnotation", Target::Object),
    ("s3:GetObjectAttributes", Target::Object),
    ("s3:GetObjectLegalHold", Target::Object),
    ("s3:GetObjectRetention", Target::Object),
    ("s3:GetObjectTagging", Target::Object),
    ("s3:GetObjectTorrent", Target::Object),
    ("s3:GetObjectVersion", Target::Object),
    ("s3:GetObjectVersionAcl", Target::Object),
    ("s3:GetObjectVersionAnnotation", Target::Object),
    (
        "s3:GetObjectVersionAnnotationForReplication",
        Target::Object,
    ),
    ("s3:GetObjectVersionAttributes", Target::Object),
    ("s3:GetObjectVersionForReplication", Target::Object),
    ("s3:GetObjectVersionTagging", Target::Object),
    ("s3:GetObjectVersionTorrent", Target::Object),
    ("s3:GetReplicationConfiguration", Target::Bucket),
    ("s3:GetStorageLensConfiguration", Target::Other),
    ("s3:GetStorageLensConfigurationTagging", Target::Other),
    ("s3:GetStorageLensDashboard", Target::Other),
    ("s3:GetStorageLensGroup", Target::Other),
    ("s3:InitiateReplication", Target::Object),
    ("s3:ListAccessGrants", Target::Other),
    ("s3:ListAccessGrantsInstances", Target::Account),
    ("s3:ListAccessGrantsLocations", Target::Other),
    ("s3:ListAccessPoints", Target::Account),
    ("s3:ListAccessPointsForObjectLambda", Target::Account),
    ("s3:ListAllMyBuckets", Target::Account),
    ("s3:ListBucket", Target::Bucket),
    ("s3:ListBucketMultipartUploads", Target::Bucket),
    ("s3:ListBucketVersions", Target::Bucket),
    ("s3:ListCallerAccessGrants", Target::Other),
    ("s3:ListJobs", Target::Account),
    ("s3:ListMultiRegionAccessPoints", Target::Account),
    ("s3:ListMultipartUploadParts", Target::Object),
    ("s3:ListObjectAnnotations", Target::Object),
    ("s3:ListObjectVersionAnnotations", Target::Object),
    ("s3:ListStorageLensConfigurations", Target::Account),
    ("s3:ListStorageLensGroups", Target::Account),
    ("s3:ListTagsForResource", Target::Bucket),
    ("s3:ObjectOwnerOverrideToBucketOwner", Target::Object),
    ("s3:PauseReplication", Target::Bucket),
    ("s3:PutAccelerateConfiguration", Target::Bucket),
    ("s3:PutAccessGrantsInstanceResourcePolicy", Target::Other),
    (
        "s3:PutAccessPointConfigurationForObjectLambda",
        Target::Other,
    ),
    ("s3:PutAccessPointPolicy", Target::Other),
    ("s3:PutAccessPointPolicyForObjectLambda", Target::Other),
    ("s3:PutAccessPointPublicAccessBlock", Target::Account),
    ("s3:PutAccountPublicAccessBlock", Target::Account),
    ("s3:PutAnalyticsConfiguration", Target::Bucket),
    ("s3:PutBucketAbac", Target::Bucket),
    ("s3:PutBucketAcl", Target::Bucket),
    ("s3:PutBucketCORS", Target::Bucket),
    ("s3:PutBucketLogging", Target::Bucket),
    ("s3:PutBucketNotification", Target::Bucket),
    ("s3:PutBucketObjectLockConfiguration", Target::Bucket),
    ("s3:PutBucketOwnershipControls", Target::Bucket),
    ("s3:PutBucketPolicy", Target::Bucket),
    ("s3:PutBucketPublicAccessBlock", Target::Bucket),
    ("s3:PutBucketRequestPayment", Target::Bucket),
    ("s3:PutBucketTagging", Target::Bucket),
    ("s3:PutBucketVersioning", Target::Bucket),
    ("s3:PutBucketWebsite", Target::Bucket),
    ("s3:PutEncryptionConfiguration", Target::Bucket),
    ("s3:PutIntelligentTieringConfiguration", Target::Bucket),
    ("s3:PutInventoryConfiguration", Target::Bucket),
    ("s3:PutJobTagging", Target::Other),
    ("s3:PutLifecycleConfiguration", Target::Bucket),
    ("s3:PutMetricsConfiguration", Target::Bucket),
    ("s3:PutMultiRegionAccessPointPolicy", Target::Other),
    ("s3:PutObject", Target::Object),
    ("s3:PutObjectAcl", Target::Object),
    ("s3:PutObjectAnnotation", Target::Object),
    ("s3:PutObjectLegalHold", Target::Object),
    ("s3:PutObjectRetention", Target::Object),
    ("s3:PutObjectTagging", Target::Object),
    ("s3:PutObjectVersionAcl", Target::Object),
    ("s3:PutObjectVersionAnnotation", Target::Object),
    ("s3:PutObjectVersionTagging", Target::Object),
    ("s3:PutReplicationConfiguration", Target::Bucket),
    ("s3:PutStorageLensConfiguration", Target::Account),
    ("s3:PutStorageLensConfigurationTagging", Target::Other),
    ("s3:ReplicateDelete", Target::Object),
    ("s3:ReplicateObject", Target::Object),
    ("s3:ReplicateObjectAnnotation", Target::Object),
    ("s3:ReplicateTags", Target::Object),
    ("s3:RestoreObject", Target::Object),
    ("s3:SubmitMultiRegionAccessPointRoutes", Target::Other),
    ("s3:TagResource", Target::Bucket),
    ("s3:UntagResource", Target::Bucket),
    ("s3:UpdateAccessGrantsLocation", Target::Other),
    (
        "s3:UpdateBucketMetadataAnnotationTableConfiguration",
        Target::Bucket,
    ),
    (
        "s3:UpdateBucketMetadataInventoryTableConfiguration",
        Target::Bucket,
    ),
    (
        "s3:UpdateBucketMetadataJournalTableConfiguration",
        Target::Bucket,
    ),
    ("s3:UpdateJobPriority", Target::Other),
    ("s3:UpdateJobStatus", Target::Other),
    ("s3:UpdateObjectEncryption", Target::Object),
    ("s3:UpdateStorageLensGroup", Target::Other),
];
