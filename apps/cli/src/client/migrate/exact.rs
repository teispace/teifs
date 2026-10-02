//! Copies that keep everything S3 lets a client set: the object's headers and metadata,
//! its tags, its Object Lock retention and legal hold, and its ETag. A multipart
//! object is copied in parts with the same boundaries as the source's, so the
//! destination computes the same ETag, and a single-part one in one request of any size
//! (streamed, not held in memory). The ETag that comes back is checked against the
//! source's before the copy counts as done.

use std::ops::Range;

use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart, MetadataDirective, TaggingDirective,
};
use futures::{StreamExt, TryStreamExt, stream};
use md5::{Digest, Md5};

use super::super::{
    Error, Kind,
    attributes::{Attributes, with_attributes},
    sse::{copy_source_key, customer_key, encrypted},
    transfer::{Object, Transfers, copy_source, hex},
};

/// The number of parts an ETag says its object was uploaded in (`…-N`), if it's an
/// MD5-style multipart ETag.
pub fn parts_in(etag: &str) -> Option<u64> {
    let (hash, count) = etag.trim_matches('"').split_once('-')?;
    (hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| count.parse().ok())
        .flatten()
        .filter(|&n| n > 0)
}

/// Parts of `first` bytes each but the last, for an object of `size` in `count` parts;
/// `None` when they can't add up to it that way.
pub fn even_parts(size: u64, first: u64, count: u64) -> Option<Vec<Range<u64>>> {
    if count == 0 || first == 0 {
        return None;
    }
    let before_last = first.checked_mul(count - 1)?;
    if before_last >= size || size - before_last > first {
        return None;
    }
    Some(
        (0..count)
            .map(|i| i * first..((i + 1) * first).min(size))
            .collect(),
    )
}

/// The ETag S3 gives an object uploaded in parts with these ETags (MD5s, hex).
pub fn multipart_etag(parts: &[String]) -> Option<String> {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(teifs_types::unhex::<16>(part.trim_matches('"'))?);
    }
    Some(format!("\"{}-{}\"", hex(&hasher.finalize()), parts.len()))
}

/// Whether two ETags are the same, quotes aside.
pub fn same_etag(a: &str, b: &str) -> bool {
    a.trim_matches('"') == b.trim_matches('"')
}

/// The source's parts: from part 1's size when they can be even (as every tool uploads
/// them), else asked part by part (and then `true`).
async fn layout(
    transfers: &Transfers,
    from: &Object,
    size: u64,
    count: u64,
) -> Result<(Vec<Range<u64>>, bool), Error> {
    let first = part_size(transfers, from, 1).await?;
    if let Some(parts) = even_parts(size, first, count) {
        return Ok((parts, false));
    }
    Ok((exact_layout(transfers, from, count).await?, true))
}

/// Each part's range, asked one by one.
async fn exact_layout(
    transfers: &Transfers,
    from: &Object,
    count: u64,
) -> Result<Vec<Range<u64>>, Error> {
    let mut parts = Vec::new();
    let mut start = 0;
    for number in 1..=count {
        let len = part_size(transfers, from, number).await?;
        parts.push(start..start + len);
        start += len;
    }
    Ok(parts)
}

/// The size of part `number` of `from`.
async fn part_size(transfers: &Transfers, from: &Object, number: u64) -> Result<u64, Error> {
    let _permit = transfers.permit().await;
    let request = from
        .client
        .head_object()
        .bucket(&from.bucket)
        .key(&from.key)
        .set_version_id(from.version_id.clone())
        .part_number(i32::try_from(number).unwrap_or(i32::MAX));
    let head = customer_key!(request, from.sse())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read {}", from.name), &e))?;
    head.content_length()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| Error::general(format!("{}: its part {number} has no size", from.name)))
}

/// What to do when ETags can't be compared.
const ETAG_HINT: &str = "ETags aren't MD5s where objects are encrypted with KMS or customer \
                         keys: compare by size alone with --size-only";

/// What's copied: the source (a version of it), its size and ETag, and what the copy
/// sets.
pub struct Source<'a> {
    pub object: &'a Object,
    pub size: u64,
    pub etag: &'a str,
    pub attributes: &'a Attributes,
}

/// Copies `source` to `to` exactly; the new object's ETag. With `check`, an ETag that
/// isn't the source's fails the copy (a multipart upload is aborted before it's
/// completed).
pub async fn copy(
    transfers: &Transfers,
    source: &Source<'_>,
    to: &Object,
    check: bool,
) -> Result<String, Error> {
    let what = || format!("can't copy {} to {}", source.object.name, to.name);
    let etag = match parts_in(source.etag) {
        None => single(transfers, source, to).await,
        Some(count) => {
            let (ranges, asked) = layout(transfers, source.object, source.size, count).await?;
            match multipart(transfers, source, to, &ranges, check).await {
                // Even part sizes that don't give the source's ETag: maybe its parts
                // weren't even after all; ask for each.
                Err(Mismatch::Etag(found)) if !asked => {
                    let exact = exact_layout(transfers, source.object, count).await?;
                    if exact == ranges {
                        Err(Mismatch::Etag(found))
                    } else {
                        multipart(transfers, source, to, &exact, check).await
                    }
                }
                other => other,
            }
            .map_err(Mismatch::into_error)
        }
    }
    .map_err(|e| e.within(what()))?;
    if check && !same_etag(&etag, source.etag) {
        return Err(Error::general(format!(
            "{}: the copy's ETag is {etag}, the source's {}",
            what(),
            source.etag
        ))
        .with_hint(ETAG_HINT));
    }
    Ok(etag)
}

/// A multipart copy that failed, or whose ETag isn't the source's.
enum Mismatch {
    Etag(String),
    Failed(Error),
}

impl Mismatch {
    fn into_error(self) -> Error {
        match self {
            Self::Etag(etag) => {
                Error::general(format!("the parts give the ETag {etag}")).with_hint(ETAG_HINT)
            }
            Self::Failed(err) => err,
        }
    }
}

impl From<Error> for Mismatch {
    fn from(err: Error) -> Self {
        Self::Failed(err)
    }
}

/// A single-part object, in one request: copied by the server at one endpoint,
/// streamed through here otherwise.
async fn single(transfers: &Transfers, source: &Source<'_>, to: &Object) -> Result<String, Error> {
    let from = source.object;
    if from.endpoint == to.endpoint {
        let _permit = transfers.permit().await;
        let request = to
            .client
            .copy_object()
            .bucket(&to.bucket)
            .key(&to.key)
            .copy_source(copy_source(from))
            .copy_source_if_match(source.etag)
            .metadata_directive(MetadataDirective::Replace)
            .tagging_directive(TaggingDirective::Replace);
        let request = with_attributes!(copy_source_key!(request, from.sse()), source.attributes);
        let copied = encrypted!(request, to.sse())
            .send()
            .await
            .map_err(|e| Error::s3("copying it", &e))?;
        transfers.moved(source.size);
        return copied
            .copy_object_result
            .and_then(|r| r.e_tag)
            .ok_or_else(|| Error::general("the endpoint gave no ETag"));
    }
    let body = {
        let _permit = transfers.permit().await;
        let request = from
            .client
            .get_object()
            .bucket(&from.bucket)
            .key(&from.key)
            .set_version_id(from.version_id.clone())
            .if_match(source.etag);
        customer_key!(request, from.sse())
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't read {}", from.name), &e))?
            .body
    };
    let _permit = transfers.permit().await;
    let request = to
        .client
        .put_object()
        .bucket(&to.bucket)
        .key(&to.key)
        .content_length(i64::try_from(source.size).unwrap_or(i64::MAX))
        .body(body);
    let put = encrypted!(with_attributes!(request, source.attributes), to.sse())
        .send()
        .await
        .map_err(|e| Error::s3("writing it", &e))?;
    transfers.moved(source.size);
    put.e_tag
        .ok_or_else(|| Error::general("the endpoint gave no ETag"))
}

/// A multipart object, in parts with these boundaries. With `check`, the parts' ETags
/// must give the source's before the upload is completed.
async fn multipart(
    transfers: &Transfers,
    source: &Source<'_>,
    to: &Object,
    ranges: &[Range<u64>],
    check: bool,
) -> Result<String, Mismatch> {
    let upload_id = {
        let _permit = transfers.permit().await;
        let request = to
            .client
            .create_multipart_upload()
            .bucket(&to.bucket)
            .key(&to.key);
        encrypted!(with_attributes!(request, source.attributes), to.sse())
            .send()
            .await
            .map_err(|e| Error::s3("starting the upload", &e))?
            .upload_id
            .ok_or_else(|| Error::general("the endpoint gave no upload id"))?
    };
    let result = parts(transfers, source, to, &upload_id, ranges, check).await;
    if result.is_err() {
        let _ = to
            .client
            .abort_multipart_upload()
            .bucket(&to.bucket)
            .key(&to.key)
            .upload_id(&upload_id)
            .send()
            .await;
    }
    result
}

/// Sends every part and completes the upload.
async fn parts(
    transfers: &Transfers,
    source: &Source<'_>,
    to: &Object,
    upload_id: &str,
    ranges: &[Range<u64>],
    check: bool,
) -> Result<String, Mismatch> {
    let from = source.object;
    let server_side = from.endpoint == to.endpoint;
    let mut parts = stream::iter(ranges.iter().cloned().zip(1..))
        .map(|(range, number)| async move {
            let len = range.end - range.start;
            let header = format!("bytes={}-{}", range.start, range.end.saturating_sub(1));
            let etag = if server_side {
                let _permit = transfers.permit().await;
                let request = to
                    .client
                    .upload_part_copy()
                    .bucket(&to.bucket)
                    .key(&to.key)
                    .upload_id(upload_id)
                    .part_number(number)
                    .copy_source(copy_source(from))
                    .copy_source_range(header)
                    .copy_source_if_match(source.etag);
                let request = copy_source_key!(request, from.sse());
                customer_key!(request, to.sse())
                    .send()
                    .await
                    .map_err(|e| Error::s3("a part", &e))?
                    .copy_part_result
                    .and_then(|r| r.e_tag)
            } else {
                let body = {
                    let _permit = transfers.permit().await;
                    let request = from
                        .client
                        .get_object()
                        .bucket(&from.bucket)
                        .key(&from.key)
                        .set_version_id(from.version_id.clone())
                        .range(header)
                        .if_match(source.etag);
                    customer_key!(request, from.sse())
                        .send()
                        .await
                        .map_err(|e| Error::s3(format!("can't read {}", from.name), &e))?
                        .body
                };
                let _permit = transfers.permit().await;
                let request = to
                    .client
                    .upload_part()
                    .bucket(&to.bucket)
                    .key(&to.key)
                    .upload_id(upload_id)
                    .part_number(number)
                    .content_length(i64::try_from(len).unwrap_or(i64::MAX))
                    .body(body);
                customer_key!(request, to.sse())
                    .send()
                    .await
                    .map_err(|e| Error::s3("a part", &e))?
                    .e_tag
            };
            transfers.moved(len);
            Ok::<_, Error>(
                CompletedPart::builder()
                    .part_number(number)
                    .set_e_tag(etag)
                    .build(),
            )
        })
        .buffer_unordered(transfers.parallel())
        .try_collect::<Vec<_>>()
        .await?;
    parts.sort_by_key(CompletedPart::part_number);
    if check {
        let etags: Vec<String> = parts
            .iter()
            .map(|p| p.e_tag().unwrap_or_default().to_owned())
            .collect();
        match multipart_etag(&etags) {
            Some(etag) if !same_etag(&etag, source.etag) => return Err(Mismatch::Etag(etag)),
            _ => {}
        }
    }
    let _permit = transfers.permit().await;
    let request = to
        .client
        .complete_multipart_upload()
        .bucket(&to.bucket)
        .key(&to.key)
        .upload_id(upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        );
    let done = customer_key!(request, to.sse())
        .send()
        .await
        .map_err(|e| Error::s3("completing the upload", &e))?;
    done.e_tag
        .ok_or_else(|| Mismatch::Failed(Error::new(Kind::General, "the endpoint gave no ETag")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_etag_that_isnt_hex_is_refused_whatever_its_characters() {
        // 32 bytes, with `é` across the first byte pair: no ETag, and no panic.
        let etag = format!("a{}a", "\u{e9}".repeat(15));
        assert_eq!(etag.len(), 32);
        assert_eq!(multipart_etag(&[etag]), None);
        assert_eq!(multipart_etag(&["+f".repeat(16)]), None);
    }

    #[test]
    fn multipart_etags_are_read_and_made() {
        let md5 = "\"9b2cf535f27731c974343645a3985328-3\"";
        assert_eq!(parts_in(md5), Some(3));
        assert_eq!(parts_in("\"9b2cf535f27731c974343645a3985328\""), None);
        assert_eq!(parts_in("\"9b2cf535f27731c974343645a3985328-0\""), None);
        assert_eq!(parts_in("\"not-an-md5-3\""), None);
        // Two parts: md5(md5("a") ‖ md5("b")).
        let a = "0cc175b9c0f1b6a831c399e269772661".to_owned();
        let b = "92eb5ffee6ae2fec3ad71c777531578f".to_owned();
        let etag = multipart_etag(&[a, b]).unwrap();
        assert!(etag.ends_with("-2\""), "{etag}");
        assert_eq!(etag.len(), 32 + 4);
        assert_eq!(multipart_etag(&["\"nonsense\"".to_owned()]), None);
        assert!(same_etag("\"x-2\"", "x-2"));
        assert!(!same_etag("\"x-2\"", "x-3"));
    }

    #[test]
    fn even_parts_add_up_or_are_refused() {
        assert_eq!(even_parts(25, 10, 3), Some(vec![0..10, 10..20, 20..25]));
        assert_eq!(even_parts(30, 10, 3), Some(vec![0..10, 10..20, 20..30]));
        let one = even_parts(10, 10, 1).unwrap();
        assert_eq!((one.len(), one[0].clone()), (1, 0..10));
        // Too short or too long for 3 parts of 10.
        assert_eq!(even_parts(20, 10, 3), None);
        assert_eq!(even_parts(31, 10, 3), None);
        assert_eq!(even_parts(10, 0, 1), None);
        assert_eq!(even_parts(10, 10, 0), None);
    }
}
