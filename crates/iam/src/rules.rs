//! AWS's rules for IAM names, paths, tags and documents, and its default quotas.

use crate::{IamError, Result};

/// Users per account.
pub(crate) const MAX_USERS: usize = 5000;
/// Groups per account.
pub(crate) const MAX_GROUPS: usize = 300;
/// Customer-managed policies per account.
pub(crate) const MAX_POLICIES: usize = 1500;
/// Roles per account.
pub(crate) const MAX_ROLES: usize = 1000;
/// Groups a user can be in.
pub(crate) const MAX_GROUPS_PER_USER: usize = 10;
/// Managed policies attached to one user, group or role.
pub(crate) const MAX_ATTACHED: usize = 10;
/// Access keys per user.
pub(crate) const MAX_KEYS_PER_USER: usize = 2;
/// Versions a managed policy keeps.
pub(crate) const MAX_VERSIONS: usize = 5;
/// Tags on one user, role or policy.
pub(crate) const MAX_TAGS: usize = 50;
/// OpenID Connect providers per account.
pub(crate) const MAX_OIDC_PROVIDERS: usize = 100;
/// Audiences (client ids) of one OpenID Connect provider.
pub(crate) const MAX_CLIENT_IDS: usize = 100;
/// Certificate thumbprints of one OpenID Connect provider.
pub(crate) const MAX_THUMBPRINTS: usize = 5;

/// The longest user or role name.
pub(crate) const USER_NAME: usize = 64;
/// The longest group, policy or inline policy name.
pub(crate) const OTHER_NAME: usize = 128;
/// The longest managed policy or role description.
pub(crate) const DESCRIPTION: usize = 1000;

/// Policy sizes count characters other than white space.
pub(crate) const USER_INLINE_TOTAL: usize = 2048;
/// All of a group's inline policies together.
pub(crate) const GROUP_INLINE_TOTAL: usize = 5120;
/// All of a role's inline policies together.
pub(crate) const ROLE_INLINE_TOTAL: usize = 10_240;
/// One managed policy version.
pub(crate) const MANAGED_SIZE: usize = 6144;
/// A role's trust policy.
pub(crate) const TRUST_SIZE: usize = 2048;

/// The shortest and longest session a role may be set to allow, in seconds; a role
/// allows one hour unless set otherwise.
pub(crate) const ROLE_SESSION: std::ops::RangeInclusive<u32> = 3600..=43_200;
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

/// A managed policy's or role's description: at most 1000 of tab, line breaks and
/// U+0020–U+00FF, as AWS allows.
pub(crate) fn description(text: &str) -> Result<()> {
    let ok = text.chars().count() <= DESCRIPTION
        && text
            .chars()
            .all(|c| matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{FF}'));
    if ok {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "a description is at most {DESCRIPTION} characters, of tab, line breaks and \
             U+0020 to U+00FF"
        )))
    }
}

/// A role's longest session (`MaxSessionDuration`), in seconds.
pub(crate) fn max_session(seconds: u32) -> Result<u32> {
    if ROLE_SESSION.contains(&seconds) {
        Ok(seconds)
    } else {
        Err(IamError::InvalidInput(format!(
            "MaxSessionDuration is {} to {} seconds (1 to 12 hours), not {seconds}",
            ROLE_SESSION.start(),
            ROLE_SESSION.end()
        )))
    }
}

/// An OpenID Connect provider's URL: `https://` and a host, with an optional port and
/// path but no user, query or fragment, at most 255 characters. `http://` is allowed for
/// a loopback host only (an identity provider on the same machine), which AWS has no
/// use for. Returns the URL without its scheme: the last part of the provider's ARN.
pub(crate) fn oidc_url(url: &str) -> Result<&str> {
    let bad = |why: &str| {
        Err(IamError::InvalidInput(format!(
            "The URL `{url}` isn't an OpenID Connect provider's: {why}."
        )))
    };
    if url.is_empty() || url.len() > 255 {
        return bad("it must be 1 to 255 characters");
    }
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return bad("it must start with https://");
    };
    if !rest.bytes().all(|b| b.is_ascii_graphic()) || rest.contains(['?', '#', '@', '\\']) {
        return bad("it can't have spaces, a user, a query or a fragment");
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if path.contains("//") || path.split('/').any(|s| s == "." || s == "..") {
        return bad("its path must be plain");
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((address, port)) if address.parse::<std::net::Ipv6Addr>().is_ok() => {
                (&authority[..address.len() + 2], port)
            }
            _ => return bad("its host isn't an IPv6 address"),
        },
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    let host_ok = host.starts_with('[')
        || (!host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }));
    if !host_ok {
        return bad("its host isn't a domain name or an IP address");
    }
    if let Some(port) = port.strip_prefix(':') {
        if port.is_empty() || port.starts_with('0') || port.parse::<u16>().is_err() {
            return bad("its port isn't 1 to 65535");
        }
    } else if !port.is_empty() {
        return bad("its host isn't a domain name or an IP address");
    }
    if !secure && !is_loopback(host) {
        return bad("it must start with https:// (http:// is only for this machine)");
    }
    Ok(rest)
}

/// Whether a URL's host is this machine: `localhost` or a loopback address.
pub(crate) fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// An OpenID Connect provider's client id (audience): 1 to 255 characters.
pub(crate) fn client_id(id: &str) -> Result<()> {
    if (1..=255).contains(&id.chars().count()) {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "The client id `{id}` must be 1 to 255 characters."
        )))
    }
}

/// A certificate thumbprint: the SHA-1 of the certificate, as 40 hex digits.
pub(crate) fn thumbprint(thumbprint: &str) -> Result<()> {
    if thumbprint.len() == 40 && thumbprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(IamError::InvalidInput(format!(
            "The thumbprint `{thumbprint}` must be 40 hex digits."
        )))
    }
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
    fn descriptions() {
        for good in ["", "Reads photos.\r\n\tÿ é", &"x".repeat(1000)] {
            assert!(description(good).is_ok(), "{good:?}");
        }
        for bad in ["日本", "\u{0}", "\u{7F}x\u{100}", &"x".repeat(1001)] {
            assert!(description(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn max_sessions() {
        for good in [3600, 7200, 43_200] {
            assert_eq!(max_session(good).unwrap(), good);
        }
        for bad in [0, 900, 3599, 43_201] {
            assert!(max_session(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn oidc_urls() {
        for (url, name) in [
            ("https://idp.example.com", "idp.example.com"),
            ("https://idp.example.com/", "idp.example.com/"),
            (
                "https://idp.example.com:8443/realms/a",
                "idp.example.com:8443/realms/a",
            ),
            (
                "https://token.actions.githubusercontent.com",
                "token.actions.githubusercontent.com",
            ),
            ("https://10.0.0.1", "10.0.0.1"),
            ("https://[2001:db8::1]:443/x", "[2001:db8::1]:443/x"),
            ("http://localhost:5556/dex", "localhost:5556/dex"),
            ("http://127.0.0.1:9000", "127.0.0.1:9000"),
            ("http://[::1]", "[::1]"),
        ] {
            assert_eq!(oidc_url(url).unwrap(), name, "{url}");
        }
        assert!(oidc_url(&format!("https://{}.com", "a".repeat(63))).is_ok());
        assert!(
            oidc_url(&format!("https://{}.com", "a".repeat(64))).is_err(),
            "a label is at most 63"
        );
        let long = format!("https://a.com/{}", "p".repeat(241));
        assert_eq!(long.len(), 255);
        assert!(oidc_url(&long).is_ok());
        assert!(oidc_url(&format!("{long}p")).is_err());
        for bad in [
            "",
            "idp.example.com",
            "ftp://idp.example.com",
            "https://",
            "https:///x",
            "https://idp.example.com?x=1",
            "https://idp.example.com/p?x=1",
            "https://idp.example.com/p#x",
            "https://idp.example.com/u@x",
            "https://idp.example.com#x",
            "https://user@idp.example.com",
            "https://idp example.com",
            "https://idp..example.com",
            "https://-idp.example.com",
            "https://idp.example.com:",
            "https://idp.example.com:0",
            "https://idp.example.com:08443",
            "https://idp.example.com:65536",
            "https://idp.example.com:x",
            "https://[::1",
            "https://[nope]",
            "https://[::1]x",
            "https://idp.example.com//x",
            "https://idp.example.com/a/../b",
            "https://idp.example.com/\\x",
            "http://idp.example.com",
            "http://10.0.0.1",
            "https://idp.é.com",
        ] {
            assert!(oidc_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_ids_and_thumbprints() {
        assert!(client_id("sts.amazonaws.com").is_ok());
        assert!(client_id(&"é".repeat(255)).is_ok());
        assert!(client_id("").is_err());
        assert!(client_id(&"x".repeat(256)).is_err());
        assert!(thumbprint("6938fd4d98bab03faadb97b34396831e3780aea1").is_ok());
        assert!(thumbprint("6938FD4D98BAB03FAADB97B34396831E3780AEA1").is_ok());
        for bad in [
            "",
            "6938fd4d98bab03faadb97b34396831e3780aea",
            "6938fd4d98bab03faadb97b34396831e3780aea12",
            "6938fd4d98bab03faadb97b34396831e3780aeg1",
        ] {
            assert!(thumbprint(bad).is_err(), "{bad}");
        }
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
