//! How a replicating server writes a replica, as minio-go does it (so TeiFS and `MinIO`
//! keep each other's version ids): a `PutObject` with the version's id as `versionId`
//! in the query and `MinIO`'s headers saying it's a replication request, when the
//! version was made and its ETag. Such a write, from a caller allowed
//! `s3:ReplicateObject` (the access check sees to it), is recorded as a replica of that
//! version; a `DeleteObject` saying it makes a delete marker, from a caller allowed
//! `s3:ReplicateDelete`, makes a marker with that id, and one that doesn't removes the
//! version it names (`MinIO`'s `DeleteReplication`), as a replicated removal.

use http::HeaderMap;
use s3s::{S3Result, s3_error};
use teifs_store::Replica;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Says the write is a replica.
pub(crate) const REQUEST: &str = "x-minio-source-replication-request";
/// When the replicated version was made (RFC 3339, to the nanosecond).
pub(crate) const MTIME: &str = "x-minio-source-mtime";
/// The replicated version's ETag.
pub(crate) const ETAG: &str = "x-minio-source-etag";
/// Says a replicated delete makes a delete marker (with the `versionId` given).
pub(crate) const DELETE_MARKER: &str = "x-minio-source-deletemarker";
/// When the replicated version's tags, retention and legal hold were last changed: a
/// `MinIO` replica takes each only with its time.
pub(crate) const TAGGING_TIMESTAMP: &str = "x-minio-source-replication-tagging-timestamp";
pub(crate) const RETENTION_TIMESTAMP: &str = "x-minio-source-replication-retention-timestamp";
pub(crate) const LEGAL_HOLD_TIMESTAMP: &str = "x-minio-source-replication-legalhold-timestamp";
/// What minio-go also sends with a replica: its status there.
pub(crate) const STATUS: &str = "x-amz-replication-status";
/// The query parameter naming the replicated version.
pub(crate) const VERSION_ID: &str = "versionId";

/// The replica a write describes (its headers, and the `versionId` of its query), if
/// its headers say it's one.
pub(crate) fn replica(headers: &HeaderMap, version_id: Option<&str>) -> S3Result<Option<Replica>> {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    // Elsewhere, `versionId` means nothing to a write, as on S3.
    if !text(REQUEST).is_some_and(|value| value.eq_ignore_ascii_case("true")) {
        return Ok(None);
    }
    let version_id = version_id
        .filter(|id| is_version_id(id))
        .ok_or_else(|| s3_error!(InvalidArgument, "a replica's versionId must name a version"))?;
    let modified = text(MTIME)
        .and_then(|mtime| OffsetDateTime::parse(mtime, &Rfc3339).ok())
        .ok_or_else(|| s3_error!(InvalidArgument, "{MTIME} must be an RFC 3339 time"))?;
    let modified_ms = i64::try_from(modified.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| s3_error!(InvalidArgument, "{MTIME} must be an RFC 3339 time"))?;
    let etag = match text(ETAG) {
        None => None,
        Some(etag) => Some(
            valid_etag(etag.trim_matches('"'))
                .ok_or_else(|| s3_error!(InvalidArgument, "{ETAG} must be an ETag"))?,
        ),
    };
    Ok(Some(Replica {
        version_id: version_id.to_owned(),
        modified_ms,
        etag,
    }))
}

/// The delete marker a delete describes (its headers, and the `versionId` of its
/// query), if its headers say it's a replicated one.
pub(crate) fn marker(headers: &HeaderMap, version_id: Option<&str>) -> S3Result<Option<Replica>> {
    let flag = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    };
    if !(flag(REQUEST) && flag(DELETE_MARKER)) {
        return Ok(None);
    }
    replica(headers, version_id)
}

/// The version a delete removes as a replicated removal (the `versionId` of its query),
/// if its headers say it's one (a replication request that doesn't make a marker).
pub(crate) fn removal<'a>(
    headers: &HeaderMap,
    version_id: Option<&'a str>,
) -> S3Result<Option<&'a str>> {
    let flag = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    };
    if !flag(REQUEST) || flag(DELETE_MARKER) {
        return Ok(None);
    }
    version_id
        .filter(|id| is_version_id(id))
        .map(Some)
        .ok_or_else(|| {
            s3_error!(
                InvalidArgument,
                "a replicated removal's versionId must name a version"
            )
        })
}

/// The headers that make a delete of a version a replicated removal.
pub(crate) fn of_removal() -> Vec<(&'static str, String)> {
    vec![(REQUEST, "true".to_owned()), (STATUS, "REPLICA".to_owned())]
}

/// The headers that make a delete of `replica`'s id a replicated delete marker.
pub(crate) fn of_marker(replica: &Replica) -> Vec<(&'static str, String)> {
    let mut headers = of(replica);
    headers.push((DELETE_MARKER, "true".to_owned()));
    headers
}

/// The headers that make a write of `replica` one, for a `MinIO` or TeiFS target (its
/// version id goes in the query, as [`VERSION_ID`]).
pub(crate) fn of(replica: &Replica) -> Vec<(&'static str, String)> {
    let mut headers = vec![(REQUEST, "true".to_owned()), (STATUS, "REPLICA".to_owned())];
    let nanos = i128::from(replica.modified_ms) * 1_000_000;
    if let Ok(mtime) = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        && let Ok(mtime) = mtime.format(&Rfc3339)
    {
        headers.push((MTIME, mtime));
    }
    if let Some(etag) = &replica.etag {
        headers.push((ETAG, etag.clone()));
    }
    headers
}

/// The headers that make a copy of `replica` onto itself a change of its metadata,
/// which changed at `changed_ms` (sent with the version's tags, retention and legal
/// hold).
pub(crate) fn of_metadata(replica: &Replica, changed_ms: i64) -> Vec<(&'static str, String)> {
    let mut headers = of(replica);
    let nanos = i128::from(changed_ms) * 1_000_000;
    if let Ok(time) = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        && let Ok(time) = time.format(&Rfc3339)
    {
        for name in [TAGGING_TIMESTAMP, RETENTION_TIMESTAMP, LEGAL_HOLD_TIMESTAMP] {
            headers.push((name, time.clone()));
        }
    }
    headers
}

/// A version id TeiFS makes (a UUID's 32 hex digits) or `MinIO` does (a UUID with its
/// dashes), so replicas keep either.
pub(crate) fn is_version_id(id: &str) -> bool {
    let hex =
        |part: &str, len: usize| part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit());
    match id.len() {
        32 => hex(id, 32),
        36 => {
            let parts: Vec<&str> = id.split('-').collect();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(&parts)
                    .all(|(len, part)| hex(part, *len))
        }
        _ => false,
    }
}

/// An ETag as S3 makes them: an MD5's hex, with `-PARTS` for a multipart upload's.
fn valid_etag(etag: &str) -> Option<String> {
    let (md5, parts) = etag
        .split_once('-')
        .map_or((etag, None), |(m, p)| (m, Some(p)));
    let md5_ok = md5.len() == 32 && md5.bytes().all(|b| b.is_ascii_hexdigit());
    let parts_ok = parts
        .is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    (md5_ok && parts_ok).then(|| etag.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use http::HeaderValue;

    use super::*;

    const MINIO_ID: &str = "7bdae243-adae-45de-9ccf-602e9882190d";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn a_replica_round_trips_through_its_headers() {
        let replica = Replica {
            version_id: MINIO_ID.to_owned(),
            modified_ms: 1_700_000_000_123,
            etag: Some("9b2cf535f27731c974343645a3985328-2".to_owned()),
        };
        let mut map = HeaderMap::new();
        for (name, value) in of(&replica) {
            map.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        assert_eq!(map.get(STATUS).unwrap(), "REPLICA");
        assert_eq!(map.get(MTIME).unwrap(), "2023-11-14T22:13:20.123Z");
        assert_eq!(super::replica(&map, Some(MINIO_ID)).unwrap(), Some(replica));
    }

    #[test]
    fn only_a_replication_request_is_a_replica() {
        assert_eq!(replica(&HeaderMap::new(), None).unwrap(), None);
        assert_eq!(replica(&HeaderMap::new(), Some(MINIO_ID)).unwrap(), None);
        assert_eq!(
            replica(&headers(&[(REQUEST, "false")]), Some(MINIO_ID)).unwrap(),
            None
        );
    }

    #[test]
    fn what_a_replica_names_is_checked() {
        let good = [(REQUEST, "true"), (MTIME, "2023-11-14T22:13:20.123456789Z")];
        let kept = replica(&headers(&good), Some("0192f0a1b2c37d4e8f90a1b2c3d4e5f6"))
            .unwrap()
            .unwrap();
        assert_eq!(kept.modified_ms, 1_700_000_000_123);
        assert_eq!(kept.etag, None);
        for id in [
            None,
            Some("null"),
            Some("a/b"),
            Some("7bdae243adae-45de-9ccf-602e9882190d-"),
        ] {
            let err = replica(&headers(&good), id).unwrap_err();
            assert_eq!(*err.code(), s3s::S3ErrorCode::InvalidArgument, "{id:?}");
        }
        for (name, bad) in [
            (MTIME, "yesterday"),
            (ETAG, "abc"),
            (ETAG, "9b2cf535f27731c974343645a3985328-"),
            (ETAG, "9b2cf535f27731c974343645a3985328-x"),
        ] {
            let mut map = headers(&good);
            map.insert(name, HeaderValue::from_static(bad));
            let err = replica(&map, Some(MINIO_ID)).unwrap_err();
            assert_eq!(
                *err.code(),
                s3s::S3ErrorCode::InvalidArgument,
                "{name}: {bad}"
            );
        }
        let mut map = headers(&good);
        map.insert(
            ETAG,
            HeaderValue::from_static("\"9B2CF535F27731C974343645A3985328\""),
        );
        assert_eq!(
            replica(&map, Some(MINIO_ID))
                .unwrap()
                .unwrap()
                .etag
                .as_deref(),
            Some("9b2cf535f27731c974343645a3985328")
        );
    }

    #[test]
    fn a_marker_round_trips_and_needs_both_flags() {
        let replica = Replica {
            version_id: MINIO_ID.to_owned(),
            modified_ms: 1_700_000_000_123,
            etag: None,
        };
        let mut map = HeaderMap::new();
        for (name, value) in of_marker(&replica) {
            map.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        assert_eq!(marker(&map, Some(MINIO_ID)).unwrap(), Some(replica.clone()));
        map.remove(REQUEST);
        assert_eq!(marker(&map, Some(MINIO_ID)).unwrap(), None);
        let mut map = HeaderMap::new();
        for (name, value) in of(&replica) {
            map.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        assert_eq!(marker(&map, Some(MINIO_ID)).unwrap(), None);
    }

    #[test]
    fn a_removal_is_a_replication_request_without_the_marker_flag() {
        let mut map = HeaderMap::new();
        for (name, value) in of_removal() {
            map.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        assert_eq!(removal(&map, Some(MINIO_ID)).unwrap(), Some(MINIO_ID));
        for id in [None, Some("null"), Some("a/b")] {
            let err = removal(&map, id).unwrap_err();
            assert_eq!(*err.code(), s3s::S3ErrorCode::InvalidArgument, "{id:?}");
        }
        map.insert(DELETE_MARKER, HeaderValue::from_static("true"));
        assert_eq!(removal(&map, Some(MINIO_ID)).unwrap(), None);
        assert_eq!(removal(&HeaderMap::new(), Some(MINIO_ID)).unwrap(), None);
    }

    #[test]
    fn a_metadata_change_says_when_each_part_changed() {
        let replica = Replica {
            version_id: MINIO_ID.to_owned(),
            modified_ms: 1_700_000_000_123,
            etag: None,
        };
        let headers = of_metadata(&replica, 1_700_000_100_000);
        for name in [TAGGING_TIMESTAMP, RETENTION_TIMESTAMP, LEGAL_HOLD_TIMESTAMP] {
            assert!(
                headers
                    .iter()
                    .any(|(n, v)| *n == name && v == "2023-11-14T22:15:00Z"),
                "{name}: {headers:?}"
            );
        }
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        assert_eq!(super::replica(&map, Some(MINIO_ID)).unwrap(), Some(replica));
    }

    #[test]
    fn version_ids_are_teifs_or_minios() {
        assert!(is_version_id("0192f0a1b2c37d4e8f90a1b2c3d4e5f6"));
        assert!(is_version_id(MINIO_ID));
        for bad in [
            "",
            "null",
            "0192f0a1b2c37d4e8f90a1b2c3d4e5fz",
            "7bdae243-adae-45de-9ccf602e-9882190d",
        ] {
            assert!(!is_version_id(bad), "{bad}");
        }
    }
}
