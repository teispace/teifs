//! The filters of a bucket's reporting configurations (metrics, analytics,
//! Intelligent-Tiering), given with `--prefix` and `--tag`: S3 takes a prefix, a tag, or
//! an `And` of a prefix and tags.

use std::collections::BTreeMap;

use aws_sdk_s3::types::Tag;

use super::Error;

/// A `KEY=VALUE` tag, for clap.
pub(super) fn tag(given: &str) -> Result<(String, String), String> {
    match given.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_owned(), value.to_owned())),
        _ => Err(format!("{given} isn't a tag: give KEY=VALUE")),
    }
}

/// A filter in S3's shape, for each kind's own type.
#[derive(Debug, PartialEq)]
pub(super) enum Shape {
    Prefix(String),
    Tag(Tag),
    And(Option<String>, Vec<Tag>),
}

/// The filter a prefix and tags make: none without either, a lone prefix or tag as
/// itself, else an `And`.
pub(super) fn shape(
    prefix: Option<String>,
    tags: Vec<(String, String)>,
) -> Result<Option<Shape>, Error> {
    let mut tags = tags
        .into_iter()
        .map(|(key, value)| Tag::builder().key(key).value(value).build())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::usage(e.to_string()))?;
    Ok(match (prefix, tags.len()) {
        (None, 0) => None,
        (Some(prefix), 0) => Some(Shape::Prefix(prefix)),
        (None, 1) => tags.pop().map(Shape::Tag),
        (prefix, _) => Some(Shape::And(prefix, tags)),
    })
}

/// Tags by key.
pub(super) fn pairs(tags: &[Tag]) -> BTreeMap<&str, &str> {
    tags.iter().map(|t| (t.key(), t.value())).collect()
}

/// A filter in words, `docs/* and team=red`; `None` when it has neither.
pub(super) fn words(prefix: Option<&str>, tags: &BTreeMap<&str, &str>) -> Option<String> {
    let mut parts: Vec<String> = prefix.map(|p| format!("{p}*")).into_iter().collect();
    parts.extend(tags.iter().map(|(key, value)| format!("{key}={value}")));
    (!parts.is_empty()).then(|| parts.join(" and "))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    fn tags(given: &[(&str, &str)]) -> Vec<(String, String)> {
        given
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn tags_are_key_equals_value() {
        assert_eq!(
            tag("team=red").unwrap(),
            ("team".to_owned(), "red".to_owned())
        );
        assert_eq!(
            tag("note=a=b").unwrap(),
            ("note".to_owned(), "a=b".to_owned())
        );
        assert_eq!(tag("empty=").unwrap(), ("empty".to_owned(), String::new()));
        for wrong in ["team", "=red"] {
            assert!(
                tag(wrong).unwrap_err().contains("give KEY=VALUE"),
                "{wrong}"
            );
        }
    }

    #[test]
    fn filters_take_s3s_shape() {
        assert_eq!(shape(None, Vec::new()).unwrap(), None);
        assert_eq!(
            shape(Some("docs/".to_owned()), Vec::new()).unwrap(),
            Some(Shape::Prefix("docs/".to_owned()))
        );
        let Some(Shape::Tag(one)) = shape(None, tags(&[("team", "red")])).unwrap() else {
            panic!("one tag")
        };
        assert_eq!((one.key(), one.value()), ("team", "red"));
        let Some(Shape::And(None, two)) = shape(None, tags(&[("a", "1"), ("b", "2")])).unwrap()
        else {
            panic!("two tags")
        };
        assert_eq!(pairs(&two), BTreeMap::from([("a", "1"), ("b", "2")]));
        let Some(Shape::And(Some(prefix), one)) =
            shape(Some("docs/".to_owned()), tags(&[("a", "1")])).unwrap()
        else {
            panic!("a prefix and a tag")
        };
        assert_eq!((prefix.as_str(), one.len()), ("docs/", 1));
    }

    #[test]
    fn filters_read_as_words() {
        assert_eq!(words(None, &BTreeMap::new()), None);
        assert_eq!(
            words(Some("docs/"), &BTreeMap::new()).as_deref(),
            Some("docs/*")
        );
        let tags = BTreeMap::from([("team", "red"), ("env", "prod")]);
        assert_eq!(
            words(Some("docs/"), &tags).as_deref(),
            Some("docs/* and env=prod and team=red")
        );
    }
}
