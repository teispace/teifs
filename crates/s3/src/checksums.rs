//! S3's additional checksums (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, …): the ones a
//! client sends (as headers or as trailers after the body) are checked against the bytes,
//! and kept so reads can return them.

use std::collections::BTreeMap;

use s3s::{S3Result, TrailingHeaders, checksum::ChecksumHasher, dto::Checksum, s3_error};

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

/// A hasher for the checksums sent and the algorithm asked for.
pub(crate) fn hasher(sent: &Sums, algorithm: Option<&str>) -> S3Result<ChecksumHasher> {
    let mut hasher = ChecksumHasher::default();
    for name in sent.keys().map(String::as_str).chain(algorithm) {
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
}
