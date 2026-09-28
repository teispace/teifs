//! Condition keys. A policy names them as text; here they become one of a closed set,
//! so a request's context can only answer for keys TeiFS knows and fills in itself —
//! never, say, an arbitrary request header a client chose to send. A name that isn't
//! known is kept as [`Key::Unknown`], which never has a value (as on AWS, where a key
//! the request doesn't carry is simply absent).
//!
//! Names compare without case, the tag key in `aws:PrincipalTag/…` too (AWS: a
//! condition on `aws:ResourceTag/TagKey1` matches a tag named `tagkey1`).

macro_rules! keys {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $text:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(#[doc = concat!("`", $text, "`")] $variant,)*
        }

        impl $name {
            /// Every key, in the order declared.
            pub const ALL: &[Self] = &[$(Self::$variant),*];

            /// The key's name as AWS writes it.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)*
                }
            }

            fn find(name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|key| key.name().eq_ignore_ascii_case(name))
            }
        }
    };
}

keys! {
    /// The `aws:` keys TeiFS recognizes. The ones it has no source for (VPCs,
    /// organizations, MFA, calling services) are recognized but never present.
    GlobalKey {
        CalledVia = "aws:CalledVia",
        CalledViaFirst = "aws:CalledViaFirst",
        CalledViaLast = "aws:CalledViaLast",
        CurrentTime = "aws:CurrentTime",
        EpochTime = "aws:EpochTime",
        FederatedProvider = "aws:FederatedProvider",
        MultiFactorAuthAge = "aws:MultiFactorAuthAge",
        MultiFactorAuthPresent = "aws:MultiFactorAuthPresent",
        PrincipalAccount = "aws:PrincipalAccount",
        PrincipalArn = "aws:PrincipalArn",
        PrincipalIsAwsService = "aws:PrincipalIsAWSService",
        PrincipalOrgId = "aws:PrincipalOrgID",
        PrincipalOrgPaths = "aws:PrincipalOrgPaths",
        PrincipalServiceName = "aws:PrincipalServiceName",
        PrincipalServiceNamesList = "aws:PrincipalServiceNamesList",
        PrincipalType = "aws:PrincipalType",
        Referer = "aws:referer",
        RequestedRegion = "aws:RequestedRegion",
        ResourceAccount = "aws:ResourceAccount",
        ResourceOrgId = "aws:ResourceOrgID",
        ResourceOrgPaths = "aws:ResourceOrgPaths",
        RoleSessionName = "aws:RoleSessionName",
        SecureTransport = "aws:SecureTransport",
        SourceAccount = "aws:SourceAccount",
        SourceArn = "aws:SourceArn",
        SourceIdentity = "aws:SourceIdentity",
        SourceIp = "aws:SourceIp",
        SourceOrgId = "aws:SourceOrgID",
        SourceOrgPaths = "aws:SourceOrgPaths",
        SourceVpc = "aws:SourceVpc",
        SourceVpce = "aws:SourceVpce",
        TagKeys = "aws:TagKeys",
        TokenIssueTime = "aws:TokenIssueTime",
        UserAgent = "aws:UserAgent",
        UserId = "aws:userid",
        Username = "aws:username",
        ViaAwsService = "aws:ViaAWSService",
        VpcSourceIp = "aws:VpcSourceIp",
    }
}

keys! {
    /// S3's own keys (from AWS's Service Authorization Reference), except the tag
    /// families, which are [`TagKind`]s.
    S3Key {
        AccessGrantScope = "s3:AccessGrantScope",
        AccessGrantsInstanceArn = "s3:AccessGrantsInstanceArn",
        AccessGrantsLocationScope = "s3:AccessGrantsLocationScope",
        AccessPointNetworkOrigin = "s3:AccessPointNetworkOrigin",
        DataAccessPointAccount = "s3:DataAccessPointAccount",
        DataAccessPointArn = "s3:DataAccessPointArn",
        ExistingJobOperation = "s3:ExistingJobOperation",
        ExistingJobPriority = "s3:ExistingJobPriority",
        InventoryAccessibleOptionalFields = "s3:InventoryAccessibleOptionalFields",
        JobSuspendedCause = "s3:JobSuspendedCause",
        ObjectCreationOperation = "s3:ObjectCreationOperation",
        RequestJobOperation = "s3:RequestJobOperation",
        RequestJobPriority = "s3:RequestJobPriority",
        RequestObjectTagKeys = "s3:RequestObjectTagKeys",
        ResourceAccount = "s3:ResourceAccount",
        TlsVersion = "s3:TlsVersion",
        AnnotationPrefix = "s3:annotation-prefix",
        AuthType = "s3:authType",
        Delimiter = "s3:delimiter",
        DeliverySourceArn = "s3:deliverySourceArn",
        DestinationRegion = "s3:destinationRegion",
        IfMatch = "s3:if-match",
        IfNoneMatch = "s3:if-none-match",
        IsReplicationPauseRequest = "s3:isReplicationPauseRequest",
        LocationConstraint = "s3:locationconstraint",
        LogType = "s3:logType",
        MaxAnnotationResults = "s3:max-annotation-results",
        MaxKeys = "s3:max-keys",
        ObjectLockEventHold = "s3:object-lock-event-hold",
        ObjectLockEventHoldDurationDays = "s3:object-lock-event-hold-duration-days",
        ObjectLockLegalHold = "s3:object-lock-legal-hold",
        ObjectLockMode = "s3:object-lock-mode",
        ObjectLockRemainingRetentionDays = "s3:object-lock-remaining-retention-days",
        ObjectLockRetainUntilDate = "s3:object-lock-retain-until-date",
        Prefix = "s3:prefix",
        ResourceArnBeingAuthorized = "s3:resourceArnBeingAuthorized",
        SignatureAge = "s3:signatureAge",
        SignatureVersion = "s3:signatureversion",
        VersionId = "s3:versionid",
        Acl = "s3:x-amz-acl",
        BucketNamespace = "s3:x-amz-bucket-namespace",
        ContentSha256 = "s3:x-amz-content-sha256",
        CopySource = "s3:x-amz-copy-source",
        GrantFullControl = "s3:x-amz-grant-full-control",
        GrantRead = "s3:x-amz-grant-read",
        GrantReadAcp = "s3:x-amz-grant-read-acp",
        GrantWrite = "s3:x-amz-grant-write",
        GrantWriteAcp = "s3:x-amz-grant-write-acp",
        MetadataDirective = "s3:x-amz-metadata-directive",
        ObjectAnnotationDirective = "s3:x-amz-object-annotation-directive",
        ObjectIfMatch = "s3:x-amz-object-if-match",
        ObjectOwnership = "s3:x-amz-object-ownership",
        ServerSideEncryption = "s3:x-amz-server-side-encryption",
        ServerSideEncryptionKmsKeyId = "s3:x-amz-server-side-encryption-aws-kms-key-id",
        ServerSideEncryptionCustomerAlgorithm = "s3:x-amz-server-side-encryption-customer-algorithm",
        StorageClass = "s3:x-amz-storage-class",
        WebsiteRedirectLocation = "s3:x-amz-website-redirect-location",
    }
}

keys! {
    /// IAM's own keys (from AWS's Service Authorization Reference), except
    /// `iam:ResourceTag`, which is a [`TagKind`]. Those with no IAM feature in TeiFS
    /// (FIDO keys, Organizations, delegation) are recognized but never present.
    IamKey {
        AccountPropertyNamespaces = "iam:AccountPropertyNamespaces",
        AssociatedResourceArn = "iam:AssociatedResourceArn",
        AwsServiceName = "iam:AWSServiceName",
        DelegationDuration = "iam:DelegationDuration",
        DelegationRequestOwner = "iam:DelegationRequestOwner",
        FidoFips1402Certification = "iam:FIDO-FIPS-140-2-certification",
        FidoFips1403Certification = "iam:FIDO-FIPS-140-3-certification",
        FidoCertification = "iam:FIDO-certification",
        NotificationChannel = "iam:NotificationChannel",
        OrganizationsPolicyId = "iam:OrganizationsPolicyId",
        PassedToService = "iam:PassedToService",
        PermissionsBoundary = "iam:PermissionsBoundary",
        PolicyArn = "iam:PolicyARN",
        RegisterSecurityKey = "iam:RegisterSecurityKey",
        RoleTemplateArn = "iam:RoleTemplateARN",
        ServiceSpecificCredentialAgeDays = "iam:ServiceSpecificCredentialAgeDays",
        ServiceSpecificCredentialServiceName = "iam:ServiceSpecificCredentialServiceName",
        TemplateArn = "iam:TemplateArn",
    }
}

keys! {
    /// The keys that carry a tag key after a `/`: `aws:ResourceTag/team`.
    TagKind {
        Principal = "aws:PrincipalTag",
        Request = "aws:RequestTag",
        Resource = "aws:ResourceTag",
        AccessPoint = "s3:AccessPointTag",
        Bucket = "s3:BucketTag",
        ExistingObject = "s3:ExistingObjectTag",
        RequestObject = "s3:RequestObjectTag",
        IamResource = "iam:ResourceTag",
    }
}

/// A condition key, as a policy names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Key {
    Global(GlobalKey),
    S3(S3Key),
    Iam(IamKey),
    /// A tag family and the tag's key.
    Tag(TagKind, Box<str>),
    /// Any other name: never present in a request.
    Unknown(Box<str>),
}

impl Key {
    pub(crate) fn parse(name: &str) -> Result<Self, crate::Error> {
        if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(crate::Error::new(format!("`{name}` isn't a condition key")));
        }
        if let Some((family, tag)) = name.split_once('/')
            && let Some(kind) = TagKind::find(family)
        {
            return if tag.is_empty() {
                Err(crate::Error::new(format!(
                    "`{name}` needs a tag key after the `/`"
                )))
            } else {
                Ok(Self::Tag(kind, tag.into()))
            };
        }
        Ok(GlobalKey::find(name)
            .map(Self::Global)
            .or_else(|| S3Key::find(name).map(Self::S3))
            .or_else(|| IamKey::find(name).map(Self::Iam))
            .unwrap_or_else(|| Self::Unknown(name.into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_compare_without_case() {
        assert_eq!(
            Key::parse("aws:SourceIp").unwrap(),
            Key::Global(GlobalKey::SourceIp)
        );
        assert_eq!(
            Key::parse("AWS:SOURCEIP").unwrap(),
            Key::Global(GlobalKey::SourceIp)
        );
        assert_eq!(
            Key::parse("s3:VersionId").unwrap(),
            Key::S3(S3Key::VersionId)
        );
        assert_eq!(
            Key::parse("aws:principaltag/Team").unwrap(),
            Key::Tag(TagKind::Principal, "Team".into())
        );
        assert_eq!(
            Key::parse("s3:ExistingObjectTag/a/b").unwrap(),
            Key::Tag(TagKind::ExistingObject, "a/b".into()),
            "a tag key may itself contain `/`"
        );
        assert_eq!(
            Key::parse("IAM:policyarn").unwrap(),
            Key::Iam(IamKey::PolicyArn)
        );
        assert_eq!(
            Key::parse("iam:ResourceTag/team").unwrap(),
            Key::Tag(TagKind::IamResource, "team".into())
        );
        assert_eq!(
            Key::parse("s3:madeup").unwrap(),
            Key::Unknown("s3:madeup".into())
        );
        assert_eq!(
            Key::parse("aws:SourceIp/x").unwrap(),
            Key::Unknown("aws:SourceIp/x".into())
        );
        for bad in ["", "aws:Source Ip", "aws:RequestTag/", "a\tb"] {
            assert!(Key::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_are_distinct() {
        let mut names: Vec<String> = GlobalKey::ALL
            .iter()
            .map(|k| k.name())
            .chain(S3Key::ALL.iter().map(|k| k.name()))
            .chain(IamKey::ALL.iter().map(|k| k.name()))
            .chain(TagKind::ALL.iter().map(|k| k.name()))
            .map(str::to_ascii_lowercase)
            .collect();
        let count = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
