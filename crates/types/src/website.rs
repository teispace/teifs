//! Static website hosting: how a bucket answers on its website endpoint, as S3's
//! `PutBucketWebsite` sets it.

use serde::{Deserialize, Serialize};

/// At most this many routing rules, as on S3.
pub const MAX_ROUTING_RULES: usize = 50;

/// A bucket's website configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebsiteConfig {
    /// Every request goes to another host (`RedirectAllRequestsTo`).
    RedirectAll {
        /// The host they go to.
        host_name: String,
        /// The request's own protocol when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<Protocol>,
    },
    /// The bucket's objects are the site.
    Site(Site),
}

/// A website served from the bucket's objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    /// What a request for a folder (`/`, `…/`) is answered with: the folder's key
    /// followed by it (`IndexDocument`'s `Suffix`).
    pub index_suffix: String,
    /// The object answered for an error, with the error's status (`ErrorDocument`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_key: Option<String>,
    /// The redirects, the first that matches applying.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing_rules: Vec<RoutingRule>,
}

/// A redirect and when it applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    /// Always, when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
    /// Where it sends the request.
    pub redirect: Redirect,
}

/// When a routing rule applies: all it names must hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// The requested key starts with it (`KeyPrefixEquals`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,
    /// The answer would have this error status (`HttpErrorCodeReturnedEquals`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u16>,
}

/// Where a routing rule sends a request: what it doesn't name stays as requested.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Redirect {
    /// The host it goes to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// The protocol it uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// 301 when `None`, as on S3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_redirect_code: Option<u16>,
    /// How it changes the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_key: Option<KeyReplacement>,
}

/// How a redirect changes the requested key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyReplacement {
    /// The condition's prefix is replaced with this (`ReplaceKeyPrefixWith`).
    Prefix(String),
    /// The whole key is replaced with this (`ReplaceKeyWith`).
    Key(String),
}

/// A redirect's protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

impl Protocol {
    /// Its name in a URL and in S3's XML.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// The protocol `name` names, exactly as S3 spells it.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

/// Whether S3 takes `code` as a routing rule's `HttpErrorCodeReturnedEquals`.
#[must_use]
pub const fn is_error_code(code: u16) -> bool {
    matches!(code, 400..=417 | 500..=505)
}

/// Whether S3 takes `code` as a redirect's `HttpRedirectCode`.
#[must_use]
pub const fn is_redirect_code(code: u16) -> bool {
    matches!(code, 301..=305 | 307 | 308)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    #[test]
    fn codes_are_those_s3_takes() {
        for code in [400, 404, 417, 500, 505] {
            assert!(is_error_code(code), "{code}");
        }
        for code in [399, 418, 451, 499, 506, 302] {
            assert!(!is_error_code(code), "{code}");
        }
        for code in [301, 302, 303, 304, 305, 307, 308] {
            assert!(is_redirect_code(code), "{code}");
        }
        for code in [300, 306, 309, 200, 404] {
            assert!(!is_redirect_code(code), "{code}");
        }
    }

    #[test]
    fn protocols_are_spelled_as_on_s3() {
        assert_eq!(Protocol::parse("https"), Some(Protocol::Https));
        assert_eq!(Protocol::parse("http").map(Protocol::name), Some("http"));
        assert_eq!(Protocol::parse("HTTP"), None);
        assert_eq!(Protocol::parse("ftp"), None);
    }

    #[test]
    fn configurations_round_trip_as_json() {
        let site = WebsiteConfig::Site(Site {
            index_suffix: "index.html".to_owned(),
            error_key: Some("404.html".to_owned()),
            routing_rules: vec![RoutingRule {
                condition: Some(Condition {
                    key_prefix: Some("docs/".to_owned()),
                    error_code: None,
                }),
                redirect: Redirect {
                    replace_key: Some(KeyReplacement::Prefix("documents/".to_owned())),
                    ..Redirect::default()
                },
            }],
        });
        let json = serde_json::to_string(&site).unwrap();
        assert_eq!(serde_json::from_str::<WebsiteConfig>(&json).unwrap(), site);
        let all = WebsiteConfig::RedirectAll {
            host_name: "example.com".to_owned(),
            protocol: Some(Protocol::Https),
        };
        let json = serde_json::to_string(&all).unwrap();
        assert_eq!(serde_json::from_str::<WebsiteConfig>(&json).unwrap(), all);
    }
}
