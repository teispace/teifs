//! S3 Batch Operations' `S3ComputeObjectChecksum`: each object's checksum is worked out
//! from its bytes, read as the job's role, and written to the job's completion report
//! (which such a job must have), as AWS writes it: the task's result message is
//! `{"checksum_base64":…,"etag":…,"checksumAlgorithm":…,"checksumType":…,"checksum_hex":…}`.
//! The object isn't changed.
//!
//! A full-object checksum is of the whole object. A composite one is of its parts'
//! checksums, then `-N` for `N` parts, as S3 gives a multipart object's; an object
//! uploaded in one piece is one part.

use aws_sdk_s3::{Client, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use s3s::S3Result;
use serde::{Deserialize, Serialize};
use teifs_store::checksum::Checksums;

use crate::{
    batch_copy::one_of,
    batch_operations::{Failure, Task},
    control_jobs::bad_request,
};

/// `S3ComputeObjectChecksum`, as S3 Control takes and answers it.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ComputeXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_type: Option<String>,
}

/// The algorithm and type a job asks for, checked: full object unless it says.
pub(crate) fn parse(given: ComputeXml) -> S3Result<(String, String)> {
    let algorithm = given
        .checksum_algorithm
        .filter(|a| Checksums::supports(a))
        .ok_or_else(|| {
            bad_request(
                "ChecksumAlgorithm is one of CRC32, CRC32C, CRC64NVME, MD5, SHA1, SHA256, \
                 SHA512, XXHASH64, XXHASH3, XXHASH128.",
            )
        })?;
    let kind = given
        .checksum_type
        .unwrap_or_else(|| "FULL_OBJECT".to_owned());
    one_of("ChecksumType", Some(&kind), &["FULL_OBJECT", "COMPOSITE"])?;
    if algorithm == "CRC64NVME" && kind == "COMPOSITE" {
        return Err(bad_request(
            "A CRC64NVME checksum is of the full object: ChecksumType is FULL_OBJECT.",
        ));
    }
    Ok((algorithm, kind))
}

/// A job's checksum, as `DescribeJob` answers it.
pub(crate) fn xml(algorithm: &str, kind: &str) -> ComputeXml {
    ComputeXml {
        checksum_algorithm: Some(algorithm.to_owned()),
        checksum_type: Some(kind.to_owned()),
    }
}

/// Works out the task's object's checksum; what its report says.
pub(crate) async fn run(
    client: &Client,
    (algorithm, kind): (&str, &str),
    task: &Task,
) -> Result<String, Failure> {
    let get = || {
        client
            .get_object()
            .bucket(&task.bucket)
            .key(&task.key)
            .set_version_id(task.version.clone())
    };
    let (etag, value) = if kind == "COMPOSITE" {
        // Each part read at the ETag the first was, so all are of the same object.
        let first = get()
            .part_number(1)
            .send()
            .await
            .map_err(|err| Failure::of(&err))?;
        let etag = first.e_tag.clone().unwrap_or_default();
        let parts = first.parts_count.unwrap_or(1);
        let mut digests = vec![digest(algorithm, first.body).await?];
        for number in 2..=parts {
            let part = get()
                .part_number(number)
                .if_match(&etag)
                .send()
                .await
                .map_err(|err| Failure::of(&err))?;
            digests.push(digest(algorithm, part.body).await?);
        }
        let mut sums = sums_of(algorithm);
        for digest in &digests {
            sums.update(digest);
        }
        (etag, (finish(sums, algorithm)?, Some(parts)))
    } else {
        let object = get().send().await.map_err(|err| Failure::of(&err))?;
        let etag = object.e_tag.clone().unwrap_or_default();
        (etag, (digest(algorithm, object.body).await?, None))
    };
    Ok(message(algorithm, kind, &etag, value))
}

fn sums_of(algorithm: &str) -> Checksums {
    let mut sums = Checksums::default();
    // Checked when the job was made.
    sums.add(algorithm);
    sums
}

fn finish(sums: Checksums, algorithm: &str) -> Result<Vec<u8>, Failure> {
    let value = sums
        .finish()
        .remove(algorithm)
        .ok_or_else(|| Failure::internal("no checksum was worked out"))?;
    STANDARD.decode(value).map_err(Failure::internal)
}

/// The digest of a body.
async fn digest(algorithm: &str, mut body: ByteStream) -> Result<Vec<u8>, Failure> {
    let mut sums = sums_of(algorithm);
    while let Some(chunk) = body.try_next().await.map_err(Failure::internal)? {
        sums.update(&chunk);
    }
    finish(sums, algorithm)
}

/// What the report says of a checksum (`parts` for a composite one): JSON as AWS writes
/// it, `=` escaped.
fn message(
    algorithm: &str,
    kind: &str,
    etag: &str,
    (digest, parts): (Vec<u8>, Option<i32>),
) -> String {
    #[derive(Serialize)]
    struct Said<'a> {
        checksum_base64: String,
        etag: &'a str,
        #[serde(rename = "checksumAlgorithm")]
        algorithm: &'a str,
        #[serde(rename = "checksumType")]
        kind: &'a str,
        checksum_hex: String,
    }
    let suffix = parts.map(|n| format!("-{n}")).unwrap_or_default();
    let said = Said {
        checksum_base64: format!("{}{suffix}", STANDARD.encode(&digest)),
        etag: etag.trim_matches('"'),
        algorithm,
        kind,
        checksum_hex: format!(
            "{}{suffix}",
            crate::inventory::hex(&digest).to_ascii_uppercase()
        ),
    };
    serde_json::to_string(&said)
        .unwrap_or_default()
        .replace('=', "\\u003d")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(algorithm: Option<&str>, kind: Option<&str>) -> S3Result<(String, String)> {
        parse(ComputeXml {
            checksum_algorithm: algorithm.map(str::to_owned),
            checksum_type: kind.map(str::to_owned),
        })
    }

    #[test]
    fn jobs_name_an_algorithm_and_a_type_s3_has() {
        assert_eq!(
            parsed(Some("CRC32"), None).unwrap(),
            ("CRC32".to_owned(), "FULL_OBJECT".to_owned())
        );
        assert_eq!(
            parsed(Some("SHA256"), Some("COMPOSITE")).unwrap(),
            ("SHA256".to_owned(), "COMPOSITE".to_owned())
        );
        // Every algorithm S3 has, either type, but CRC64NVME only of the full object.
        for algorithm in teifs_store::checksum::ALGORITHMS {
            assert!(
                parsed(Some(algorithm), Some("FULL_OBJECT")).is_ok(),
                "{algorithm}"
            );
            assert_eq!(
                parsed(Some(algorithm), Some("COMPOSITE")).is_ok(),
                algorithm != "CRC64NVME",
                "{algorithm}"
            );
        }
        for (algorithm, kind) in [
            (None, None),
            (Some("ADLER32"), None),
            (Some("sha256"), None),
            (Some("SHA256"), Some("PARTS")),
            (Some("CRC64NVME"), Some("COMPOSITE")),
        ] {
            assert!(parsed(algorithm, kind).is_err(), "{algorithm:?} {kind:?}");
        }
        let xml =
            quick_xml::se::to_string_with_root("S3ComputeObjectChecksum", &xml("MD5", "COMPOSITE"))
                .unwrap();
        assert_eq!(
            xml,
            "<S3ComputeObjectChecksum><ChecksumAlgorithm>MD5</ChecksumAlgorithm>\
             <ChecksumType>COMPOSITE</ChecksumType></S3ComputeObjectChecksum>"
        );
    }

    #[test]
    fn reports_say_the_checksum_as_aws_does() {
        // AWS's example: CRC32 6D2F5339.
        let said = message(
            "CRC32",
            "FULL_OBJECT",
            "\"3c3c1813042989094598e4b57ecbdc82\"",
            (vec![0x6d, 0x2f, 0x53, 0x39], None),
        );
        assert_eq!(
            said,
            r#"{"checksum_base64":"bS9TOQ\u003d\u003d","etag":"3c3c1813042989094598e4b57ecbdc82","checksumAlgorithm":"CRC32","checksumType":"FULL_OBJECT","checksum_hex":"6D2F5339"}"#
        );
        let composite = message("CRC32", "COMPOSITE", "e-2", (vec![0, 0, 0, 1], Some(2)));
        assert!(
            composite.contains(r#""checksum_base64":"AAAAAQ\u003d\u003d-2""#),
            "{composite}"
        );
        assert!(
            composite.contains(r#""checksum_hex":"00000001-2""#),
            "{composite}"
        );
    }
}
