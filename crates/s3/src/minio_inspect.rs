//! `MinIO`'s `inspect-data` (`mc support inspect`): what the drive keeps about the
//! objects a pattern names, zipped and encrypted, for support to read.
//!
//! `MinIO` hands over each drive's raw `xl.meta`; TeiFS hands over what it keeps about
//! each key, its index rows, as `<host>/<drive>/<bucket>/<key>/teifs.meta.json`
//! ([`Store::inspect_records`]), with `inspect-input.txt` (what was asked) and the
//! drive's `.teifs/format.json`. `file` is a pattern as `MinIO`'s drives glob it: `*`
//! and `?` within a name, `[…]` classes, `**` across names. A key matches through its
//! own name, `<key>/teifs.meta.json` or `<key>/xl.meta`, so `MinIO`'s usual
//! `bucket/key/xl.meta` asks for that key. Objects' bytes are never included.
//!
//! The zip is sealed under a random key sent first (format 1), or, when the caller sends
//! an RSA `public-key`, as an estream only its private key opens (format 2;
//! [`teifs_crypto::inspect`]).

use std::collections::BTreeSet;

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Request, S3Response, S3Result};
use teifs_store::{Store, StoreError, VersionsQuery};

use crate::{
    admin, minio_iam,
    minio_info::endpoint,
    minio_profile::archive,
    routes::{Routes, s3_refusal, signed_body},
};

/// The most keys one call includes.
const MAX_KEYS: usize = 1000;
/// The most versions one call reads through, looking for keys that match.
const MAX_SCANNED: usize = 100_000;
/// The largest form a `POST` sends.
const MAX_FORM_BYTES: usize = 64 << 10;
/// The longest volume or file `MinIO` takes.
const MAX_PATH: usize = 32 << 10;
/// What a key's records are called in the zip.
const RECORDS: &str = "teifs.meta.json";
/// What `MinIO` calls the file a drive keeps about an object.
const XL_META: &str = "xl.meta";
/// What the encrypted zip is called in format 2, as `MinIO` names it.
const ZIP_NAME: &str = "inspect.zip";
/// What a call that matched nothing says, as `MinIO` says it.
const NO_MATCH: &str = "GetRawData: No files matched the given pattern";

/// `GET` or `POST inspect-data`.
pub(crate) async fn inspect(
    routes: &Routes,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let mut form: Vec<(String, String)> =
        form_urlencoded::parse(req.uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    if req.method == http::Method::POST {
        let body = signed_body(&mut req, MAX_FORM_BYTES)
            .await
            .map_err(s3_refusal)?;
        form.extend(form_urlencoded::parse(&body).into_owned());
    }
    let field = |name: &str| {
        form.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    };
    let volume = field("volume");
    if volume.is_empty() {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            "The specified bucket is not valid.",
        ));
    }
    let file = field("file").replace('\\', "/");
    if file.is_empty() {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Invalid Request",
        ));
    }
    if has_bad_component(volume) || has_bad_component(&file) {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "XMinioInvalidResourceName",
            "Resource name contains bad components such as \"..\" or \".\".",
        ));
    }
    let key = match field("public-key") {
        "" => None,
        text => {
            let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text)
                .map_err(|_| minio_iam::invalid("The public key isn't base64."))?;
            Some(
                teifs_crypto::inspect::InspectKey::parse(&der)
                    .map_err(|err| minio_iam::invalid(err.to_string()))?,
            )
        }
    };

    let host = endpoint(routes, &req);
    let drive = drive_name(&routes.store);
    let mut files = vec![(
        "inspect-input.txt".to_owned(),
        format!(
            "Inspect path: {volume}/{file}\nServer command line args: {}\n",
            routes.store.root().display()
        )
        .into_bytes(),
    )];
    let found = raw_data(&routes.store, volume, &file).await?;
    let error = if found.files.is_empty() {
        Some(NO_MATCH)
    } else {
        for (name, bytes) in found.files {
            files.push((format!("{host}/{drive}/{name}"), bytes));
        }
        if let Some(note) = found.note {
            files.push(("GetRawData-err.txt".to_owned(), note.into_bytes()));
        }
        if !is_format_file(volume, &file) {
            match routes.store.format_file() {
                Ok(bytes) => files.push((format!("{host}/{drive}/.teifs/format.json"), bytes)),
                Err(err) => tracing::warn!(error = %err, "format.json couldn't be read"),
            }
        }
        None
    };
    let zip = archive(files.into_iter()).map_err(|err| {
        tracing::error!(error = %err, "the inspection couldn't be zipped");
        admin::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The inspection couldn't be zipped.",
        )
    })?;
    let body = match key {
        Some(key) => key.seal(ZIP_NAME, &zip, error),
        // `MinIO` says nothing more when nothing matched: the zip has only what was asked.
        None => teifs_crypto::inspect::seal_with_key(&zip),
    };
    let mut response = S3Response::new(Body::from(Bytes::from(body)));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

/// The files a pattern found, by name under the drive, and a note when it found too many.
#[derive(Debug, Default)]
struct Found {
    files: Vec<(String, Vec<u8>)>,
    note: Option<String>,
}

/// What `file` names in `volume`: keys' records in a bucket, or the drive's
/// `format.json` (in `.teifs`, or `MinIO`'s `.minio.sys`).
async fn raw_data(store: &Store, volume: &str, file: &str) -> S3Result<Found> {
    let mut found = Found::default();
    if volume == ".teifs" || volume == ".minio.sys" {
        if glob(file, "format.json")
            && let Ok(bytes) = store.format_file()
        {
            found.files.push((".teifs/format.json".to_owned(), bytes));
        }
        return Ok(found);
    }
    let (keys, note) = match matching_keys(store, volume, file).await {
        Ok(keys) => keys,
        Err(StoreError::NoSuchBucket) => return Ok(found),
        Err(err) => return Err(crate::errors::from_store(err)),
    };
    found.note = note;
    for key in keys {
        match store.inspect_records(volume, &key).await {
            Ok(Some(records)) => {
                let bytes = serde_json::to_vec_pretty(&records).expect("JSON values serialize");
                found
                    .files
                    .push((format!("{volume}/{key}/{RECORDS}"), bytes));
            }
            Ok(None) | Err(StoreError::NoSuchBucket) => {}
            Err(err) => return Err(crate::errors::from_store(err)),
        }
    }
    Ok(found)
}

/// The keys of `bucket` that `pattern` names, in order, at most [`MAX_KEYS`]; with a note
/// when there were more, or more versions to read through than [`MAX_SCANNED`].
async fn matching_keys(
    store: &Store,
    bucket: &str,
    pattern: &str,
) -> teifs_store::Result<(BTreeSet<String>, Option<String>)> {
    let literal = &pattern[..pattern.find(['*', '?', '[']).unwrap_or(pattern.len())];
    let mut keys = BTreeSet::new();
    // Keys the literal part goes past: `key/xl.meta` names `key`.
    for (at, _) in literal.match_indices('/') {
        if at > 0 && names(pattern, &literal[..at]) {
            keys.insert(literal[..at].to_owned());
        }
    }
    let mut query = VersionsQuery {
        prefix: literal.to_owned(),
        delimiter: None,
        key_marker: None,
        version_marker: None,
        max_keys: 1000,
    };
    let mut scanned = 0;
    loop {
        let page = store.list_versions(bucket, query.clone()).await?;
        scanned += page.versions.len();
        for version in &page.versions {
            let key = &version.info.key;
            if names(pattern, key) && !keys.contains(key) {
                if keys.len() == MAX_KEYS {
                    return Ok((
                        keys,
                        Some(format!(
                            "Only the first {MAX_KEYS} keys matching the pattern are included."
                        )),
                    ));
                }
                keys.insert(key.clone());
            }
        }
        match page.next {
            Some((key, version)) if page.truncated => {
                if scanned >= MAX_SCANNED {
                    return Ok((
                        keys,
                        Some(format!(
                            "Only the first {MAX_SCANNED} versions were read through; keys after {key} aren't included."
                        )),
                    ));
                }
                query.key_marker = Some(key);
                query.version_marker = version;
            }
            _ => return Ok((keys, None)),
        }
    }
}

/// Whether `pattern` names `key`: the key itself, its records or its `xl.meta`.
fn names(pattern: &str, key: &str) -> bool {
    glob(pattern, key)
        || glob(pattern, &format!("{key}/{RECORDS}"))
        || glob(pattern, &format!("{key}/{XL_META}"))
}

/// Whether the call asks for the drive's `format.json` itself.
fn is_format_file(volume: &str, file: &str) -> bool {
    (volume == ".teifs" || volume == ".minio.sys") && file == "format.json"
}

/// The drive's folder as the zip names it: its path without the leading `/`.
fn drive_name(store: &Store) -> String {
    let path = store.root().to_string_lossy().replace('\\', "/");
    path.trim_start_matches('/').to_owned()
}

/// Whether `path` has a `.` or `..` name (spaces around it ignored), or is too long:
/// `MinIO`'s `hasBadPathComponent`.
fn has_bad_component(path: &str) -> bool {
    path.len() > MAX_PATH
        || path
            .split(['/', '\\'])
            .any(|name| matches!(name.trim(), "." | ".."))
}

/// Whether `pattern` matches all of `text`, as `MinIO`'s drives glob: `*` any run of
/// characters within a name, `?` one character, `[…]` one of a class (`[!…]` or `[^…]`
/// none of it, `a-z` a range), `**` as a whole name any number of names; `\` escapes.
fn glob(pattern: &str, text: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let text: Vec<&str> = text.split('/').collect();
    names_match(&pattern, &text)
}

fn names_match(pattern: &[&str], text: &[&str]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((&"**", rest)) => (0..=text.len()).any(|skip| names_match(rest, &text[skip..])),
        Some((first, rest)) => text.split_first().is_some_and(|(name, more)| {
            name_matches(first.as_bytes(), name.as_bytes()) && names_match(rest, more)
        }),
    }
}

/// One name against one pattern name (bytes: names are compared as `MinIO` does,
/// `?` taking one byte).
fn name_matches(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|skip| name_matches(rest, &name[skip..])),
        Some((b'?', rest)) => !name.is_empty() && name_matches(rest, &name[1..]),
        Some((b'[', rest)) => match (class(rest), name.split_first()) {
            (Some((matches, after)), Some((first, more))) => {
                matches(*first) && name_matches(after, more)
            }
            // An unclosed `[` is itself.
            (None, Some((b'[', more))) => name_matches(rest, more),
            _ => false,
        },
        Some((b'\\', [escaped, rest @ ..])) => {
            name.first() == Some(escaped) && name_matches(rest, &name[1..])
        }
        Some((c, rest)) => name.first() == Some(c) && name_matches(rest, &name[1..]),
    }
}

/// A character class after its `[`: whether a byte is in it, and the pattern after its
/// `]`; `None` when it isn't closed.
fn class(pattern: &[u8]) -> Option<(impl Fn(u8) -> bool + '_, &[u8])> {
    let (negated, body) = match pattern.first() {
        Some(b'!' | b'^') => (true, &pattern[1..]),
        _ => (false, pattern),
    };
    // A `]` first is one of the class.
    let end = body
        .iter()
        .skip(1)
        .position(|b| *b == b']')
        .map(|at| at + 1)?;
    let (items, after) = (&body[..end], &body[end + 1..]);
    let contains = move |b: u8| {
        let mut i = 0;
        let mut found = false;
        while i < items.len() {
            if i + 2 < items.len() && items[i + 1] == b'-' {
                found |= (items[i]..=items[i + 2]).contains(&b);
                i += 3;
            } else {
                found |= items[i] == b;
                i += 1;
            }
        }
        found != negated
    };
    Some((contains, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_as_minio_s_drives_glob() {
        for (pattern, text) in [
            ("photos/a.jpg", "photos/a.jpg"),
            ("photos/*.jpg", "photos/a.jpg"),
            ("photos/?.jpg", "photos/a.jpg"),
            ("photos/[a-c].jpg", "photos/b.jpg"),
            ("photos/[!x].jpg", "photos/b.jpg"),
            ("photos/[]].jpg", "photos/].jpg"),
            ("**/a.jpg", "photos/2026/a.jpg"),
            ("**", "a/b/c"),
            ("photos/**/xl.meta", "photos/a/b/xl.meta"),
            ("x[y", "x[y"),
            ("\\*", "*"),
        ] {
            assert!(glob(pattern, text), "{pattern} {text}");
        }
        for (pattern, text) in [
            ("photos/*.jpg", "photos/a/b.jpg"),
            ("photos/?.jpg", "photos/ab.jpg"),
            ("photos/[a-c].jpg", "photos/d.jpg"),
            ("photos/[^b].jpg", "photos/b.jpg"),
            ("photos", "photos/a.jpg"),
            ("\\*", "a"),
        ] {
            assert!(!glob(pattern, text), "{pattern} {text}");
        }
    }

    #[test]
    fn a_key_is_named_by_itself_its_records_or_its_xl_meta() {
        assert!(names("a.jpg/xl.meta", "a.jpg"));
        assert!(names("a.jpg/*", "a.jpg"));
        assert!(names("a.jpg", "a.jpg"));
        assert!(names("dir/**", "dir/a.jpg"));
        assert!(!names("a.jpg/part.1", "a.jpg"));
    }

    #[test]
    fn dot_names_and_long_paths_are_refused() {
        for bad in [
            "..",
            "a/../b",
            "a/ . /b",
            "a\\..\\b",
            &"a".repeat(MAX_PATH + 1),
        ] {
            assert!(has_bad_component(bad), "{bad}");
        }
        for good in ["a", "/a/b", "a..b", ".a", "**"] {
            assert!(!has_bad_component(good), "{good}");
        }
    }
}
