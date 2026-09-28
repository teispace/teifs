//! AWS's rules for IAM names, paths, tags and documents, and its default quotas.

use crate::{IamError, Result};

/// Users per account.
pub(crate) const MAX_USERS: usize = 5000;
/// Groups per account.
pub(crate) const MAX_GROUPS: usize = 300;
/// Customer-managed policies per account.
pub(crate) const MAX_POLICIES: usize = 1500;
/// Groups a user can be in.
pub(crate) const MAX_GROUPS_PER_USER: usize = 10;
/// Managed policies attached to one user or group.
pub(crate) const MAX_ATTACHED: usize = 10;
/// Access keys per user.
pub(crate) const MAX_KEYS_PER_USER: usize = 2;
/// Versions a managed policy keeps.
pub(crate) const MAX_VERSIONS: usize = 5;
/// Tags on one user.
pub(crate) const MAX_TAGS: usize = 50;

/// The longest user name.
pub(crate) const USER_NAME: usize = 64;
/// The longest group, policy or inline policy name.
pub(crate) const OTHER_NAME: usize = 128;
/// The longest managed policy description.
pub(crate) const DESCRIPTION: usize = 1000;

/// Policy sizes count characters other than white space.
pub(crate) const USER_INLINE_TOTAL: usize = 2048;
/// All of a group's inline policies together.
pub(crate) const GROUP_INLINE_TOTAL: usize = 5120;
/// One managed policy version.
pub(crate) const MANAGED_SIZE: usize = 6144;
/// The longest document accepted at all, white space included.
const DOCUMENT_LENGTH: usize = 131_072;

/// A user, group, policy or inline policy name: 1 to `max` of `[A-Za-z0-9_+=,.@-]`.
pub(crate) fn name(what: &str, value: &str, max: usize) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "{what} `{value}` must be 1 to {max} letters, digits or `_+=,.@-`"
        )))
    }
}

/// A path: `/`, or segments of name characters each after a `/`, ending in `/`
/// (`/engineering/web/`), at most 512 characters. AWS also allows other printable ASCII
/// in user and group paths; TeiFS keeps to the policy-path rule for all, so a path never
/// holds `*`, `?` or `$` that a policy's `Resource` would read as a wildcard or variable.
pub(crate) fn path(value: &str) -> Result<()> {
    let ok = value.len() <= 512
        && value.starts_with('/')
        && value.ends_with('/')
        && value[1..].split_terminator('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
        });
    if ok {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "path `{value}` must be `/` or `/name/…/`, at most 512 characters"
        )))
    }
}

/// A path prefix to list by: any printable ASCII starting with `/`.
pub(crate) fn path_prefix(value: &str) -> Result<()> {
    if value.starts_with('/')
        && value.len() <= 512
        && value.bytes().all(|b| (0x21..0x7f).contains(&b))
    {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "path prefix `{value}` must start with `/`"
        )))
    }
}

/// A tag: a key of 1–128 and a value of 0–256 letters, digits, spaces or `_.:/=+-@`,
/// neither starting with `aws:`.
pub(crate) fn tag(key: &str, value: &str) -> Result<()> {
    let chars = |text: &str| {
        text.chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || "_.:/=+-@".contains(c))
    };
    let reserved = |text: &str| {
        text.get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("aws:"))
    };
    let key_ok = !key.is_empty() && key.chars().count() <= 128 && chars(key) && !reserved(key);
    let value_ok = value.chars().count() <= 256 && chars(value) && !reserved(value);
    if key_ok && value_ok {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "tag `{key}` = `{value}`: keys are 1–128 and values 0–256 letters, digits, spaces \
             or `_.:/=+-@`, and neither may start with `aws:`"
        )))
    }
}

/// A policy document's text: tab, newline, carriage return and U+0020–U+00FF only, 1 to
/// 131072 characters. Returns its size as IAM counts it (without white space).
pub(crate) fn document(text: &str) -> Result<usize> {
    let mut length = 0;
    let mut size = 0;
    for c in text.chars() {
        if !matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{ff}') {
            return Err(IamError::MalformedPolicyDocument(format!(
                "the policy has a character IAM doesn't allow ({c:?})"
            )));
        }
        length += 1;
        if !c.is_whitespace() {
            size += 1;
        }
    }
    if length == 0 || length > DOCUMENT_LENGTH {
        return Err(IamError::MalformedPolicyDocument(format!(
            "a policy is 1 to {DOCUMENT_LENGTH} characters"
        )));
    }
    Ok(size)
}

/// A policy version id: `v1`, `v2`, ….
pub(crate) fn version_id(text: &str) -> Result<u32> {
    text.strip_prefix('v')
        .filter(|digits| {
            !digits.is_empty()
                && !digits.starts_with('0')
                && digits.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|digits| digits.parse().ok())
        .ok_or_else(|| {
            IamError::InvalidInput(format!("`{text}` isn't a policy version (v1, v2, …)"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for good in ["a", "alice", "A_b+c=d,e.f@g-h", &"x".repeat(64)] {
            assert!(name("user", good, USER_NAME).is_ok(), "{good}");
        }
        for bad in ["", "a b", "a/b", "a*", "é", &"x".repeat(65)] {
            assert!(name("user", bad, USER_NAME).is_err(), "{bad}");
        }
        assert!(name("group", &"x".repeat(128), OTHER_NAME).is_ok());
    }

    #[test]
    fn paths() {
        for good in ["/", "/a/", "/eng/web/", "/a.b@c/"] {
            assert!(path(good).is_ok(), "{good}");
        }
        for bad in [
            "", "a/", "/a", "//", "/a//b/", "/a*/", "/a?/", "/${x}/", "/a b/",
        ] {
            assert!(path(bad).is_err(), "{bad}");
        }
        assert!(path(&format!("/{}/", "a".repeat(510))).is_ok());
        assert!(path(&format!("/{}/", "a".repeat(511))).is_err());
        assert!(path_prefix("/").is_ok());
        assert!(path_prefix("/eng").is_ok());
        assert!(path_prefix("eng").is_err());
    }

    #[test]
    fn tags() {
        assert!(tag("team", "").is_ok());
        assert!(tag("Cost Center", "a:b/c=d+e-f@g_h.i").is_ok());
        assert!(tag("équipe", "données").is_ok());
        for (k, v) in [
            ("", "x"),
            ("aws:x", "y"),
            ("AWS:x", "y"),
            ("k", "aws:v"),
            ("k*", "v"),
            ("k", "v\n"),
        ] {
            assert!(tag(k, v).is_err(), "{k}={v}");
        }
        assert!(tag(&"k".repeat(128), &"v".repeat(256)).is_ok());
        assert!(tag(&"k".repeat(129), "v").is_err());
        assert!(tag("k", &"v".repeat(257)).is_err());
    }

    #[test]
    fn documents_count_without_white_space() {
        assert_eq!(document("{ \"a\" :\n\t1 }").unwrap(), 7);
        assert_eq!(document("é").unwrap(), 1);
        assert!(document("").is_err());
        assert!(document("\u{100}").is_err());
        assert!(document("\u{0}").is_err());
        assert!(document(&" ".repeat(131_073)).is_err());
    }

    #[test]
    fn version_ids() {
        assert_eq!(version_id("v1").unwrap(), 1);
        assert_eq!(version_id("v42").unwrap(), 42);
        for bad in [
            "",
            "v",
            "1",
            "v0",
            "v01",
            "V1",
            "v-1",
            "v1x",
            "v99999999999",
        ] {
            assert!(version_id(bad).is_err(), "{bad}");
        }
    }
}
