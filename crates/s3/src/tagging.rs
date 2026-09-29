//! Object and bucket tags, checked as S3 checks them: at most 10 per object (50 per
//! bucket), unique keys of 1 to 128 characters, values of at most 256, S3's character set,
//! and no `aws:` keys. Lengths count UTF-16 units, as S3 does.

use std::collections::BTreeMap;

use s3s::{S3Result, dto, s3_error};

/// Tags by key: S3 returns a tag set sorted by key.
pub(crate) type Tags = BTreeMap<String, String>;

/// How many tags an object may have.
pub(crate) const MAX_OBJECT_TAGS: usize = 10;
/// How many tags a bucket may have.
pub(crate) const MAX_BUCKET_TAGS: usize = 50;

const MAX_KEY: usize = 128;
const MAX_VALUE: usize = 256;

/// Parses the `x-amz-tagging` header: URL query parameters (`k1=v1&k2`).
pub(crate) fn from_header(value: &str) -> S3Result<Vec<(String, String)>> {
    value
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((decode(key)?, decode(value)?))
        })
        .collect()
}

/// Parses a tag set as XML (`<Tagging><TagSet>…`), as a form's `tagging` field has it.
pub(crate) fn from_xml(xml: &[u8]) -> S3Result<Vec<(String, String)>> {
    use s3s::xml::Deserialize;
    let mut d = s3s::xml::Deserializer::new(xml);
    let tagging = dto::Tagging::deserialize(&mut d)
        .and_then(|tagging| d.expect_eof().map(|()| tagging))
        .map_err(|_| s3_error!(MalformedXML, "The tagging field isn't a tag set"))?;
    Ok(from_dto(tagging))
}

/// A tag set from a request body.
pub(crate) fn from_dto(tagging: dto::Tagging) -> Vec<(String, String)> {
    tagging
        .tag_set
        .into_iter()
        .map(|tag| (tag.key.unwrap_or_default(), tag.value.unwrap_or_default()))
        .collect()
}

/// The tags a new bucket is created with (its configuration's `Tags`), checked as a
/// bucket's; none when it has none.
pub(crate) fn of_new_bucket(
    configuration: Option<&dto::CreateBucketConfiguration>,
) -> S3Result<Option<Tags>> {
    let Some(tags) = configuration.and_then(|c| c.tags.as_ref()) else {
        return Ok(None);
    };
    let pairs = tags
        .iter()
        .map(|tag| {
            (
                tag.key.clone().unwrap_or_default(),
                tag.value.clone().unwrap_or_default(),
            )
        })
        .collect();
    Ok(Some(check(pairs, MAX_BUCKET_TAGS)?).filter(|tags| !tags.is_empty()))
}

/// A tag set for a response.
pub(crate) fn to_dto(tags: &Tags) -> dto::TagSet {
    tags.iter()
        .map(|(key, value)| dto::Tag {
            key: Some(key.clone()),
            value: Some(value.clone()),
        })
        .collect()
}

/// Checks tags against S3's rules; at most `max` of them.
pub(crate) fn check(pairs: Vec<(String, String)>, max: usize) -> S3Result<Tags> {
    if pairs.len() > max {
        return Err(s3_error!(
            InvalidTag,
            "The tag set can't have more than {max} tags"
        ));
    }
    let mut tags = Tags::new();
    for (key, value) in pairs {
        let key_len = key.encode_utf16().count();
        if key_len == 0 || key_len > MAX_KEY || !allowed(&key) {
            return Err(s3_error!(
                InvalidTag,
                "The TagKey you have provided is invalid"
            ));
        }
        if key.starts_with("aws:") {
            return Err(s3_error!(
                InvalidTag,
                "Your TagKey cannot be prefixed with aws:"
            ));
        }
        if value.encode_utf16().count() > MAX_VALUE || !allowed(&value) {
            return Err(s3_error!(
                InvalidTag,
                "The TagValue you have provided is invalid"
            ));
        }
        if tags.insert(key, value).is_some() {
            return Err(s3_error!(
                InvalidTag,
                "Cannot provide multiple Tags with the same key"
            ));
        }
    }
    Ok(tags)
}

/// S3's tag characters: letters, digits and spaces in any language, and `+ - = . _ : / @`.
fn allowed(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_alphanumeric() || c.is_whitespace() || "+-=._:/@".contains(c))
}

/// Decodes one part of a query string (`%XX`, and `+` as a space).
fn decode(part: &str) -> S3Result<String> {
    let bytes = part.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = part
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| s3_error!(InvalidArgument, "invalid x-amz-tagging header"))?;
                out.push(hex);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| s3_error!(InvalidArgument, "invalid x-amz-tagging header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(result: S3Result<Tags>) -> String {
        result.unwrap_err().code().as_str().to_owned()
    }

    #[test]
    fn headers_parse_like_query_strings() {
        let pairs = from_header("foo=bar&bar&a%20b=c+d").unwrap();
        assert_eq!(
            pairs,
            [
                ("foo".to_owned(), "bar".to_owned()),
                ("bar".to_owned(), String::new()),
                ("a b".to_owned(), "c d".to_owned()),
            ]
        );
        // Sorted by key, as S3 returns them.
        let tags = check(pairs, MAX_OBJECT_TAGS).unwrap();
        assert_eq!(tags.keys().collect::<Vec<_>>(), ["a b", "bar", "foo"]);
        assert!(from_header("k=%zz").is_err());
        assert!(from_header("").unwrap().is_empty());
    }

    #[test]
    fn s3_limits_are_enforced() {
        let tags = |n: usize| {
            (0..n)
                .map(|i| (i.to_string(), i.to_string()))
                .collect::<Vec<_>>()
        };
        assert!(check(tags(10), MAX_OBJECT_TAGS).is_ok());
        assert_eq!(code(check(tags(11), MAX_OBJECT_TAGS)), "InvalidTag");
        assert!(check(tags(50), MAX_BUCKET_TAGS).is_ok());

        let long = |n: usize| "k".repeat(n);
        assert!(check(vec![(long(128), long(256))], 10).is_ok());
        assert_eq!(
            code(check(vec![(long(129), String::new())], 10)),
            "InvalidTag"
        );
        assert_eq!(code(check(vec![("k".into(), long(257))], 10)), "InvalidTag");
        // UTF-16 units: an emoji takes two.
        assert_eq!(
            code(check(vec![("😀".repeat(65), String::new())], 10)),
            "InvalidTag"
        );
        assert!(check(vec![("ключ".into(), "значение".into())], 10).is_ok());

        for bad in [
            vec![(String::new(), "v".into())],
            vec![("aws:owner".into(), "v".into())],
            vec![("k".into(), "a".into()), ("k".into(), "b".into())],
            vec![("k#".into(), "v".into())],
            vec![("k".into(), "v&".into())],
        ] {
            assert_eq!(code(check(bad, 10)), "InvalidTag");
        }
        assert!(check(vec![("a+-=._:/@ b".into(), "1+-=._:/@ 2".into())], 10).is_ok());
    }
}
