//! S3's additional checksums (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, …): the ones a
//! client sends (as headers or as trailers after the body) are checked against the bytes,
//! and kept so reads can return them.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use s3s::{S3Result, TrailingHeaders, checksum::ChecksumHasher, dto::Checksum, s3_error};
use teifs_store::{ChecksumType, UploadChecksum};

use crate::crc_combine::Crc;

/// Checksums by algorithm name (`CRC32`, `SHA256`, …), base64 as S3 sends them.
pub(crate) type Sums = BTreeMap<String, String>;

macro_rules! algorithms {
    ($(($field:ident, $hasher:ident, $name:literal, $header:literal)),* $(,)?) => {
        /// The checksums in a DTO, by algorithm.
        pub(crate) fn from_dto(dto: &Checksum) -> Sums {
            let mut sums = Sums::new();
            $(if let Some(value) = &dto.$field { sums.insert($name.to_owned(), value.clone()); })*
            sums
        }

        /// A DTO holding these checksums.
        pub(crate) fn to_dto(sums: &Sums) -> Checksum {
            Checksum { $($field: sums.get($name).cloned(),)* ..Checksum::default() }
        }

        fn enable(hasher: &mut ChecksumHasher, name: &str) -> bool {
            match name {
                $($name => { hasher.$hasher = Some(Default::default()); true })*
                _ => false,
            }
        }

        /// Adds checksums sent as trailers after an `aws-chunked` body.
        pub(crate) fn add_trailers(sums: &mut Sums, trailers: Option<TrailingHeaders>) -> S3Result<()> {
            let Some(headers) = trailers.and_then(|t| t.take()) else { return Ok(()) };
            $(if let Some(value) = headers.get($header) {
                let value = value.to_str().map_err(|_| s3_error!(InvalidArgument, "invalid {} trailer", $header))?;
                sums.insert($name.to_owned(), value.to_owned());
            })*
            Ok(())
        }
    };
}

algorithms! {
    (checksum_crc32, crc32, "CRC32", "x-amz-checksum-crc32"),
    (checksum_crc32c, crc32c, "CRC32C", "x-amz-checksum-crc32c"),
    (checksum_crc64nvme, crc64nvme, "CRC64NVME", "x-amz-checksum-crc64nvme"),
    (checksum_sha1, sha1, "SHA1", "x-amz-checksum-sha1"),
    (checksum_sha256, sha256, "SHA256", "x-amz-checksum-sha256"),
    (checksum_sha512, sha512, "SHA512", "x-amz-checksum-sha512"),
    (checksum_md5, md5, "MD5", "x-amz-checksum-md5"),
    (checksum_xxhash64, xxhash64, "XXHASH64", "x-amz-checksum-xxhash64"),
    (checksum_xxhash3, xxhash3, "XXHASH3", "x-amz-checksum-xxhash3"),
    (checksum_xxhash128, xxhash128, "XXHASH128", "x-amz-checksum-xxhash128"),
}

/// A hasher for the checksums sent and the algorithms asked for.
pub(crate) fn hasher<'a>(
    sent: &'a Sums,
    algorithms: impl IntoIterator<Item = &'a str>,
) -> S3Result<ChecksumHasher> {
    let mut hasher = ChecksumHasher::default();
    for name in sent.keys().map(String::as_str).chain(algorithms) {
        if !enable(&mut hasher, name) {
            return Err(s3_error!(
                InvalidRequest,
                "unsupported checksum algorithm {name}"
            ));
        }
    }
    Ok(hasher)
}

/// Fails with `BadDigest` unless every checksum sent matches the bytes received.
pub(crate) fn verify(sent: &Sums, computed: &Sums) -> S3Result<()> {
    for (name, value) in sent {
        if computed.get(name) != Some(value) {
            return Err(s3_error!(
                BadDigest,
                "the {name} checksum doesn't match the data"
            ));
        }
    }
    Ok(())
}

/// S3's default checksum, attached to objects uploaded without one.
pub(crate) const DEFAULT_ALGORITHM: &str = "CRC64NVME";

/// The checksum a new multipart upload's object gets: the algorithm and type the client
/// asked for, checked against what S3 allows, else S3's default (CRC64NVME, full object).
pub(crate) fn for_upload(algorithm: Option<&str>, kind: Option<&str>) -> S3Result<UploadChecksum> {
    let Some(algorithm) = algorithm else {
        if kind.is_some() {
            return Err(s3_error!(
                InvalidRequest,
                "The x-amz-checksum-type header can only be used with the x-amz-checksum-algorithm header."
            ));
        }
        return Ok(UploadChecksum {
            algorithm: DEFAULT_ALGORITHM.to_owned(),
            kind: ChecksumType::FullObject,
            requested: false,
        });
    };
    let algorithm = algorithm.to_ascii_uppercase();
    if !enable(&mut ChecksumHasher::default(), &algorithm) {
        return Err(s3_error!(
            InvalidRequest,
            "unsupported checksum algorithm {algorithm}"
        ));
    }
    let combinable = Crc::for_algorithm(&algorithm).is_some();
    let default = if algorithm == DEFAULT_ALGORITHM {
        "FULL_OBJECT"
    } else {
        "COMPOSITE"
    };
    let kind = match kind.unwrap_or(default) {
        "FULL_OBJECT" => ChecksumType::FullObject,
        "COMPOSITE" => ChecksumType::Composite,
        other => {
            return Err(s3_error!(
                InvalidRequest,
                "Value for x-amz-checksum-type header is invalid: {other}"
            ));
        }
    };
    let allowed = match kind {
        ChecksumType::FullObject => combinable,
        ChecksumType::Composite => algorithm != DEFAULT_ALGORITHM,
    };
    if !allowed {
        return Err(s3_error!(
            InvalidRequest,
            "The {} checksum type cannot be used with the {} checksum algorithm.",
            kind.as_str(),
            algorithm.to_ascii_lowercase()
        ));
    }
    Ok(UploadChecksum {
        algorithm,
        kind,
        requested: true,
    })
}

/// Refuses a part checksum of another algorithm than the one its upload asked for.
pub(crate) fn check_part(upload: &UploadChecksum, sent: &Sums) -> S3Result<()> {
    if !upload.requested {
        return Ok(());
    }
    match sent.keys().find(|name| **name != upload.algorithm) {
        Some(other) => Err(s3_error!(
            InvalidRequest,
            "Checksum Type mismatch occurred, expected checksum Type: {}, actual checksum Type: {}",
            upload.algorithm.to_ascii_lowercase(),
            other.to_ascii_lowercase()
        )),
        None => Ok(()),
    }
}

/// The checksum of a multipart object, from its parts' checksums and sizes, in order;
/// `None` when a part has none. Composite: the algorithm over the parts' digests, then
/// `-N`. Full object: the parts' CRCs combined.
pub(crate) fn of_parts(upload: &UploadChecksum, parts: &[(u64, Option<&str>)]) -> Option<String> {
    let digests = parts
        .iter()
        .map(|(size, sum)| Some((*size, STANDARD.decode((*sum)?).ok()?)))
        .collect::<Option<Vec<_>>>()?;
    match upload.kind {
        ChecksumType::Composite => {
            let mut hasher = ChecksumHasher::default();
            enable(&mut hasher, &upload.algorithm);
            for (_, digest) in &digests {
                hasher.update(digest);
            }
            let value = from_dto(&hasher.finalize()).remove(&upload.algorithm)?;
            Some(format!("{value}-{}", digests.len()))
        }
        ChecksumType::FullObject => {
            let crc = Crc::for_algorithm(&upload.algorithm)?;
            let mut acc: Option<u64> = None;
            for (size, digest) in &digests {
                if digest.len() != crc.bytes() {
                    return None;
                }
                let value = digest.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
                acc = Some(match acc {
                    None => value,
                    Some(before) => crc.combine(before, value, *size),
                });
            }
            let value = acc?;
            let bytes = value.to_be_bytes();
            Some(STANDARD.encode(&bytes[8 - crc.bytes()..]))
        }
    }
}

/// Whether a whole-object checksum a client sent matches the one worked out. A composite
/// one may be sent with or without its `-N`.
pub(crate) fn same_object_checksum(kind: ChecksumType, sent: &str, computed: &str) -> bool {
    match kind {
        ChecksumType::FullObject => sent == computed,
        ChecksumType::Composite => {
            let base = |v: &str| v.split_once('-').map_or(v, |(b, _)| b).to_owned();
            base(sent) == base(computed)
        }
    }
}

/// The checksum fields of an input or output struct.
macro_rules! checksum_of {
    ($x:expr) => {
        s3s::dto::Checksum {
            checksum_crc32: $x.checksum_crc32.clone(),
            checksum_crc32c: $x.checksum_crc32c.clone(),
            checksum_crc64nvme: $x.checksum_crc64nvme.clone(),
            checksum_sha1: $x.checksum_sha1.clone(),
            checksum_sha256: $x.checksum_sha256.clone(),
            checksum_sha512: $x.checksum_sha512.clone(),
            checksum_md5: $x.checksum_md5.clone(),
            checksum_xxhash64: $x.checksum_xxhash64.clone(),
            checksum_xxhash3: $x.checksum_xxhash3.clone(),
            checksum_xxhash128: $x.checksum_xxhash128.clone(),
            ..Default::default()
        }
    };
}

/// Sets an output struct's checksum fields.
macro_rules! set_checksums {
    ($out:expr, $sums:expr) => {{
        let dto = crate::checksums::to_dto($sums);
        $out.checksum_crc32 = dto.checksum_crc32;
        $out.checksum_crc32c = dto.checksum_crc32c;
        $out.checksum_crc64nvme = dto.checksum_crc64nvme;
        $out.checksum_sha1 = dto.checksum_sha1;
        $out.checksum_sha256 = dto.checksum_sha256;
        $out.checksum_sha512 = dto.checksum_sha512;
        $out.checksum_md5 = dto.checksum_md5;
        $out.checksum_xxhash64 = dto.checksum_xxhash64;
        $out.checksum_xxhash3 = dto.checksum_xxhash3;
        $out.checksum_xxhash128 = dto.checksum_xxhash128;
    }};
}

pub(crate) use {checksum_of, set_checksums};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sent_checksums_are_verified() {
        let sent: Sums = [("CRC32".to_owned(), "NSRBwg==".to_owned())].into();
        let mut hasher = hasher(&sent, None).unwrap();
        hasher.update(b"hello world");
        let computed = from_dto(&hasher.finalize());
        assert_eq!(computed.get("CRC32").map(String::as_str), Some("DUoRhQ=="));
        assert!(verify(&sent, &computed).is_err());
        let right: Sums = [("CRC32".to_owned(), "DUoRhQ==".to_owned())].into();
        assert!(verify(&right, &computed).is_ok());
    }

    #[test]
    fn unknown_algorithms_are_refused() {
        assert!(hasher(&Sums::new(), Some("CRC99")).is_err());
        assert_eq!(to_dto(&from_dto(&Checksum::default())), Checksum::default());
    }

    fn sum_of(algorithm: &str, bytes: &[u8]) -> String {
        let mut h = hasher(&Sums::new(), Some(algorithm)).unwrap();
        h.update(bytes);
        from_dto(&h.finalize()).remove(algorithm).unwrap()
    }

    #[test]
    fn uploads_get_the_checksum_s3_allows() {
        let default = for_upload(None, None).unwrap();
        assert_eq!(
            (default.algorithm.as_str(), default.kind, default.requested),
            ("CRC64NVME", ChecksumType::FullObject, false)
        );
        let sha = for_upload(Some("sha256"), None).unwrap();
        assert_eq!((sha.kind, sha.requested), (ChecksumType::Composite, true));
        assert_eq!(
            for_upload(Some("CRC64NVME"), None).unwrap().kind,
            ChecksumType::FullObject
        );
        assert_eq!(
            for_upload(Some("CRC32"), Some("FULL_OBJECT")).unwrap().kind,
            ChecksumType::FullObject
        );
        // AWS's table: SHA and MD5 can't be full object, CRC64NVME can't be composite.
        assert!(for_upload(Some("SHA256"), Some("FULL_OBJECT")).is_err());
        assert!(for_upload(Some("CRC64NVME"), Some("COMPOSITE")).is_err());
        assert!(for_upload(None, Some("COMPOSITE")).is_err());
        assert!(for_upload(Some("CRC32"), Some("PARTIAL")).is_err());
        assert!(for_upload(Some("CRC99"), None).is_err());
    }

    #[test]
    fn parts_must_use_the_upload_algorithm_when_it_was_asked_for() {
        let sha = for_upload(Some("SHA256"), None).unwrap();
        let crc: Sums = [("CRC32".to_owned(), "x".to_owned())].into();
        assert!(check_part(&sha, &crc).is_err());
        let own: Sums = [("SHA256".to_owned(), "x".to_owned())].into();
        assert!(check_part(&sha, &own).is_ok());
        // SDKs send CRC32 on parts of uploads that didn't choose: that's fine.
        assert!(check_part(&for_upload(None, None).unwrap(), &crc).is_ok());
    }

    #[test]
    fn composite_checksums_match_s3() {
        // From ceph/s3-tests: 1 KiB of 'A' in one SHA-256 part.
        let part = sum_of("SHA256", &[b'A'; 1024]);
        assert_eq!(part, "arcu6553sHVAiX4MjW0j7I7vD4w6R+Gz9Ok0Q9lTa+0=");
        let upload = for_upload(Some("SHA256"), None).unwrap();
        assert_eq!(
            of_parts(&upload, &[(1024, Some(&part))]).unwrap(),
            "Ok6Cs5b96ux6+MWQkJO7UBT5sKPBeXBLwvj/hK89smg=-1"
        );
        // Three 5 MiB parts of A, B and C.
        let parts: Vec<(u64, String)> = b"ABC"
            .iter()
            .map(|b| (5 << 20, sum_of("SHA256", &vec![*b; 5 << 20])))
            .collect();
        let refs: Vec<(u64, Option<&str>)> =
            parts.iter().map(|(n, s)| (*n, Some(s.as_str()))).collect();
        assert_eq!(
            of_parts(&upload, &refs).unwrap(),
            "uWBwpe1dxI4Vw8Gf0X9ynOdw/SS6VBzfWm9giiv1sf4=-3"
        );
        assert!(of_parts(&upload, &[(1, None)]).is_none());
    }

    #[test]
    fn full_object_checksums_are_the_checksum_of_the_whole() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let pieces = [&data[..100_000], &data[100_000..100_001], &data[100_001..]];
        for algorithm in ["CRC32", "CRC32C", "CRC64NVME"] {
            let upload = for_upload(Some(algorithm), Some("FULL_OBJECT")).unwrap();
            let sums: Vec<String> = pieces.iter().map(|p| sum_of(algorithm, p)).collect();
            let parts: Vec<(u64, Option<&str>)> = pieces
                .iter()
                .zip(&sums)
                .map(|(p, s)| (p.len() as u64, Some(s.as_str())))
                .collect();
            assert_eq!(of_parts(&upload, &parts).unwrap(), sum_of(algorithm, &data));
        }
    }

    #[test]
    fn composite_values_compare_with_or_without_their_count() {
        assert!(same_object_checksum(
            ChecksumType::Composite,
            "abc=",
            "abc=-3"
        ));
        assert!(same_object_checksum(
            ChecksumType::Composite,
            "abc=-3",
            "abc=-3"
        ));
        assert!(!same_object_checksum(
            ChecksumType::Composite,
            "bad",
            "abc=-3"
        ));
        assert!(!same_object_checksum(
            ChecksumType::FullObject,
            "abc=-3",
            "abc="
        ));
    }
}
