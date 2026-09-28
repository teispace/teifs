//! ARNs: S3's, and matching them as IAM does (for `Resource` and the `Arn…` operators).
//!
//! An ARN is `arn:partition:service:region:account:resource`; the resource part may
//! itself hold colons (an S3 key can). Each of the first five parts is matched on its
//! own, so a wildcard there doesn't reach into the next part, except that a pattern
//! whose last part ends in `*` runs to the end (`arn:aws:s3:*` matches every S3 ARN).

use crate::pattern::{self, Atom};

/// The resource for actions on the account rather than a bucket (`s3:ListAllMyBuckets`).
/// `arn:aws:s3:::*` and `*` match it; a bucket's ARN doesn't.
pub const S3_ACCOUNT_RESOURCE: &str = "arn:aws:s3:::";

/// `arn:aws:s3:::BUCKET`.
#[must_use]
pub fn bucket_arn(bucket: &str) -> String {
    format!("{S3_ACCOUNT_RESOURCE}{bucket}")
}

/// `arn:aws:s3:::BUCKET/KEY`.
#[must_use]
pub fn object_arn(bucket: &str, key: &str) -> String {
    format!("{S3_ACCOUNT_RESOURCE}{bucket}/{key}")
}

/// The number of parts in an ARN: five fixed, then the resource.
const PARTS: usize = 6;

/// Whether `pattern` matches `arn`. `arn` must be an ARN (`arn:` and five colons)
/// unless the pattern is a lone `*`.
pub(crate) fn matches(pattern: &[Atom], arn: &str) -> bool {
    if pattern == [Atom::Star] {
        return true;
    }
    if !arn.starts_with("arn:") || arn.matches(':').count() < PARTS - 1 {
        return false;
    }
    let (mut pattern, mut arn) = (pattern, arn);
    for _ in 0..PARTS - 1 {
        let Some(colon) = pattern.iter().position(|atom| *atom == Atom::Char(':')) else {
            // A short pattern: its last part must end in `*`, and covers the rest.
            return pattern.last() == Some(&Atom::Star) && pattern::matches(pattern, arn, false);
        };
        let (part, rest) = arn.split_once(':').expect("an ARN has five colons");
        if !pattern::matches(&pattern[..colon], part, false) {
            return false;
        }
        (pattern, arn) = (&pattern[colon + 1..], rest);
    }
    pattern::matches(pattern, arn, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arn_like(pattern: &str, arn: &str) -> bool {
        matches(&pattern::atoms(pattern).collect::<Vec<_>>(), arn)
    }

    #[test]
    fn s3_resources() {
        assert_eq!(bucket_arn("photos"), "arn:aws:s3:::photos");
        assert_eq!(
            object_arn("photos", "a/b:c.jpg"),
            "arn:aws:s3:::photos/a/b:c.jpg"
        );
        for (pattern, arn, expected) in [
            ("*", "arn:aws:s3:::photos", true),
            ("*", "anything", true),
            ("arn:aws:s3:::photos", "arn:aws:s3:::photos", true),
            ("arn:aws:s3:::photos", "arn:aws:s3:::photos/a", false),
            ("arn:aws:s3:::photos/*", "arn:aws:s3:::photos/a/b.jpg", true),
            ("arn:aws:s3:::photos/*", "arn:aws:s3:::photos", false),
            ("arn:aws:s3:::photos*", "arn:aws:s3:::photos-old/x", true),
            (
                "arn:aws:s3:::photos/*.jpg",
                "arn:aws:s3:::photos/a:b.jpg",
                true,
            ),
            ("arn:aws:s3:::*", "arn:aws:s3:::", true),
            ("arn:aws:s3:::*", "arn:aws:s3:::photos/a", true),
            ("arn:aws:s3:::photos", S3_ACCOUNT_RESOURCE, false),
            ("arn:aws:s3:::p?otos", "arn:aws:s3:::photos", true),
            // Case matters in resources.
            ("arn:aws:s3:::Photos", "arn:aws:s3:::photos", false),
            // Parts are matched on their own.
            ("arn:aws:s3:*:*:photos", "arn:aws:s3:::photos", true),
            ("arn:aws:s3:?:*:photos", "arn:aws:s3:::photos", false),
            ("arn:aws:*:::photos", "arn:aws:s3:::photos", true),
            ("arn:*:photos", "arn:aws:s3:::photos", false),
            ("arn:aws:s3:*", "arn:aws:s3:::photos/a", true),
            ("arn:aws:s3", "arn:aws:s3:::photos", false),
            ("arn:aws:*", "arn:aws:s3:::photos", true),
            // A value that isn't an ARN matches nothing but `*`.
            ("arn:*", "photos", false),
            ("arn:aws:s3:::*", "arn:aws:s3:photos", false),
        ] {
            assert_eq!(arn_like(pattern, arn), expected, "{pattern:?} on {arn:?}");
        }
    }

    #[test]
    fn principals_and_keys() {
        assert!(arn_like(
            "arn:aws:iam::123456789012:user/*",
            "arn:aws:iam::123456789012:user/eng/alice"
        ));
        assert!(!arn_like(
            "arn:aws:iam::123456789012:user/*",
            "arn:aws:iam::210987654321:user/alice"
        ));
        assert!(arn_like(
            "arn:aws:iam::*:role/reader",
            "arn:aws:iam::123456789012:role/reader"
        ));
        assert!(arn_like(
            "arn:aws:kms:*:*:key/*",
            "arn:aws:kms:us-east-1:123456789012:key/k1"
        ));
    }
}
