//! S3 Batch Operations' `S3UpdateObjectEncryption`: each object's encryption is changed
//! in place with `UpdateObjectEncryption`, as the job's role, to the SSE-KMS key (and S3
//! Bucket Key setting) S3 Control's `S3UpdateObjectEncryptionOperation` gives. As on
//! AWS, the job is checked as `UpdateObjectEncryption` checks its request: SSE-KMS only,
//! with a key's full ARN.

use aws_sdk_s3::{
    Client,
    operation::update_object_encryption::builders::UpdateObjectEncryptionFluentBuilder,
    types::{ObjectEncryption, SsekmsEncryption},
};
use s3s::{S3Result, dto};
use serde::{Deserialize, Serialize};

use crate::{
    batch_operations::{Failure, Task},
    control_jobs::bad_request,
};

/// `S3UpdateObjectEncryption`, as S3 Control takes and answers it.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct EncryptionXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    object_encryption: Option<ObjectEncryptionXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ObjectEncryptionXml {
    #[serde(rename = "SSE-KMS", skip_serializing_if = "Option::is_none")]
    kms: Option<KmsXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KmsXml {
    #[serde(rename = "KMSKeyArn", skip_serializing_if = "Option::is_none")]
    key_arn: Option<String>,
    #[serde(rename = "BucketKeyEnabled", skip_serializing_if = "Option::is_none")]
    bucket_key: Option<bool>,
}

/// The KMS key ARN and S3 Bucket Key setting a job gives, checked as
/// `UpdateObjectEncryption` checks them (a bucket key is off unless it says).
pub(crate) fn parse(given: EncryptionXml) -> S3Result<(String, bool)> {
    let kms = given
        .object_encryption
        .and_then(|encryption| encryption.kms)
        .ok_or_else(|| bad_request("ObjectEncryption is SSE-KMS, with a KMSKeyArn."))?;
    let arn = kms
        .key_arn
        .filter(|arn| !arn.is_empty())
        .ok_or_else(|| bad_request("SSE-KMS names its KMSKeyArn."))?;
    let bucket_key = kms.bucket_key.unwrap_or(false);
    crate::sse::update_target(dto::ObjectEncryption::SSEKMS(dto::SSEKMSEncryption {
        kms_key_arn: arn.clone(),
        bucket_key_enabled: Some(bucket_key),
    }))
    .map_err(|err| {
        bad_request(
            err.message()
                .unwrap_or("KMSKeyArn is a KMS key's full ARN.")
                .to_owned(),
        )
    })?;
    Ok((arn, bucket_key))
}

/// A job's encryption, as `DescribeJob` answers it.
pub(crate) fn xml(key_arn: &str, bucket_key: bool) -> EncryptionXml {
    EncryptionXml {
        object_encryption: Some(ObjectEncryptionXml {
            kms: Some(KmsXml {
                key_arn: Some(key_arn.to_owned()),
                bucket_key: Some(bucket_key),
            }),
        }),
    }
}

/// Changes the task's object's encryption.
pub(crate) async fn run(
    client: &Client,
    (key_arn, bucket_key): (&str, bool),
    task: &Task,
) -> Result<(), Failure> {
    request(client, (key_arn, bucket_key), task)?
        .send()
        .await
        .map(drop)
        .map_err(|err| Failure::of(&err))
}

/// The `UpdateObjectEncryption` that changes the task's object.
fn request(
    client: &Client,
    (key_arn, bucket_key): (&str, bool),
    task: &Task,
) -> Result<UpdateObjectEncryptionFluentBuilder, Failure> {
    let kms = SsekmsEncryption::builder()
        .kms_key_arn(key_arn)
        .bucket_key_enabled(bucket_key)
        .build()
        .map_err(Failure::internal)?;
    Ok(client
        .update_object_encryption()
        .bucket(&task.bucket)
        .key(&task.key)
        .set_version_id(task.version.clone())
        .object_encryption(ObjectEncryption::Ssekms(kms)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/teifs-default";

    fn parsed(xml: &str) -> S3Result<(String, bool)> {
        parse(quick_xml::de::from_str(xml).unwrap())
    }

    #[test]
    fn jobs_name_a_kms_key_by_its_arn() {
        let given = format!(
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS><KMSKeyArn>{ARN}</KMSKeyArn>\
             <BucketKeyEnabled>true</BucketKeyEnabled></SSE-KMS></ObjectEncryption>\
             </S3UpdateObjectEncryption>"
        );
        assert_eq!(parsed(&given).unwrap(), (ARN.to_owned(), true));
        let again = quick_xml::se::to_string_with_root("S3UpdateObjectEncryption", &xml(ARN, true))
            .unwrap();
        assert_eq!(again, given);
        // No bucket key unless it says.
        let plain = format!(
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS><KMSKeyArn>{ARN}</KMSKeyArn>\
             </SSE-KMS></ObjectEncryption></S3UpdateObjectEncryption>"
        );
        assert_eq!(parsed(&plain).unwrap(), (ARN.to_owned(), false));
        for xml in [
            "<S3UpdateObjectEncryption/>".to_owned(),
            "<S3UpdateObjectEncryption><ObjectEncryption/></S3UpdateObjectEncryption>".to_owned(),
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS/></ObjectEncryption>\
             </S3UpdateObjectEncryption>"
                .to_owned(),
            // An alias, or a bare key id, isn't a key's ARN.
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS><KMSKeyArn>alias/mine\
             </KMSKeyArn></SSE-KMS></ObjectEncryption></S3UpdateObjectEncryption>"
                .to_owned(),
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS><KMSKeyArn>\
             arn:aws:kms:us-east-1:111122223333:alias/mine</KMSKeyArn></SSE-KMS>\
             </ObjectEncryption></S3UpdateObjectEncryption>"
                .to_owned(),
        ] {
            assert!(parsed(&xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn each_task_updates_its_objects_encryption() {
        let client = Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version_latest()
                .build(),
        );
        let task = Task {
            bucket: "vault".to_owned(),
            key: "a".to_owned(),
            version: Some("v1".to_owned()),
        };
        let update = request(&client, (ARN, true), &task).unwrap();
        let input = update.as_input();
        assert_eq!(input.get_bucket().as_deref(), Some("vault"));
        assert_eq!(input.get_key().as_deref(), Some("a"));
        assert_eq!(input.get_version_id().as_deref(), Some("v1"));
        let Some(ObjectEncryption::Ssekms(kms)) = input.get_object_encryption() else {
            panic!("{input:?}");
        };
        assert_eq!(kms.kms_key_arn(), ARN);
        assert_eq!(kms.bucket_key_enabled(), Some(true));
    }
}
