//! `PutBucketWebsite`, `GetBucketWebsite`: a bucket's website configuration, read from
//! S3's XML with S3's checks and messages, and answered as it was given.

mod serve;

pub(crate) use serve::{Domains, Endpoint, Website};

use s3s::{S3Error, S3Result, dto, s3_error};
use teifs_types::website::{
    Condition, KeyReplacement, MAX_ROUTING_RULES, Protocol, Redirect, RoutingRule, Site,
    WebsiteConfig, is_error_code, is_redirect_code,
};

/// The configuration a `WebsiteConfiguration` gives, checked as S3 checks it.
pub(crate) fn from_dto(config: dto::WebsiteConfiguration) -> S3Result<WebsiteConfig> {
    if let Some(all) = config.redirect_all_requests_to {
        let others = config.index_document.is_some()
            || config.error_document.is_some()
            || config.routing_rules.is_some();
        if others || all.host_name.is_empty() {
            return Err(malformed());
        }
        return Ok(WebsiteConfig::RedirectAll {
            host_name: all.host_name,
            protocol: all.protocol.as_ref().map(protocol).transpose()?,
        });
    }
    let Some(index) = config.index_document else {
        return Err(s3_error!(
            InvalidArgument,
            "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty"
        ));
    };
    if index.suffix.is_empty() || index.suffix.contains('/') {
        return Err(s3_error!(
            InvalidArgument,
            "The IndexDocument Suffix is not well formed"
        ));
    }
    let error_key = config.error_document.map(|document| document.key);
    if error_key.as_deref() == Some("") {
        return Err(s3_error!(
            InvalidArgument,
            "The ErrorDocument Key is not well formed"
        ));
    }
    let rules = config.routing_rules.unwrap_or_default();
    if rules.len() > MAX_ROUTING_RULES {
        return Err(S3Error::with_message(
            s3s::S3ErrorCode::InvalidRequest,
            format!(
                "{} routing rules provided, the number of routing rules in a website \
                 configuration is limited to {MAX_ROUTING_RULES}.",
                rules.len()
            ),
        ));
    }
    Ok(WebsiteConfig::Site(Site {
        index_suffix: index.suffix,
        error_key,
        routing_rules: rules
            .into_iter()
            .map(routing_rule)
            .collect::<S3Result<_>>()?,
    }))
}

fn routing_rule(rule: dto::RoutingRule) -> S3Result<RoutingRule> {
    // The redirect is checked before the condition, as S3 does.
    let redirect = redirect(rule.redirect)?;
    let condition = rule
        .condition
        .map(|condition| {
            let key_prefix = non_empty(condition.key_prefix_equals);
            let error_code = non_empty(condition.http_error_code_returned_equals)
                .map(|code| {
                    code.parse::<u16>()
                        .map_err(|_| malformed())
                        .and_then(|code| {
                            if is_error_code(code) {
                                Ok(code)
                            } else {
                                Err(invalid_request(format!(
                                    "The provided HTTP error code ({code}) is not valid. Valid \
                                     codes are 4XX or 5XX."
                                )))
                            }
                        })
                })
                .transpose()?;
            if key_prefix.is_none() && error_code.is_none() {
                return Err(malformed());
            }
            Ok(Condition {
                key_prefix,
                error_code,
            })
        })
        .transpose()?;
    Ok(RoutingRule {
        condition,
        redirect,
    })
}

fn redirect(redirect: dto::Redirect) -> S3Result<Redirect> {
    let host_name = non_empty(redirect.host_name);
    let prefix = non_empty(redirect.replace_key_prefix_with);
    let key = non_empty(redirect.replace_key_with);
    let code = non_empty(redirect.http_redirect_code);
    let named = host_name.is_some()
        || redirect.protocol.is_some()
        || prefix.is_some()
        || key.is_some()
        || code.is_some();
    if !named {
        return Err(malformed());
    }
    let replace_key = match (prefix, key) {
        (Some(_), Some(_)) => {
            return Err(invalid_request(
                "You can only define ReplaceKeyPrefix or ReplaceKey but not both.".to_owned(),
            ));
        }
        (Some(prefix), None) => Some(KeyReplacement::Prefix(prefix)),
        (None, Some(key)) => Some(KeyReplacement::Key(key)),
        (None, None) => None,
    };
    let protocol = redirect.protocol.as_ref().map(protocol).transpose()?;
    let http_redirect_code = code
        .map(|code| {
            let number = code.parse::<u16>().map_err(|_| malformed())?;
            if is_redirect_code(number) {
                Ok(number)
            } else {
                Err(invalid_request(format!(
                    "The provided HTTP redirect code ({number}) is not valid. Valid codes are \
                     3XX except 300."
                )))
            }
        })
        .transpose()?;
    Ok(Redirect {
        host_name,
        protocol,
        http_redirect_code,
        replace_key,
    })
}

fn protocol(protocol: &dto::Protocol) -> S3Result<Protocol> {
    Protocol::parse(protocol.as_str()).ok_or_else(|| {
        invalid_request(
            "Invalid protocol, protocol can be http or https. If not defined the protocol will \
             be selected automatically."
                .to_owned(),
        )
    })
}

/// A bucket's website configuration as `GetBucketWebsite` answers it.
pub(crate) fn to_dto(config: &WebsiteConfig) -> dto::GetBucketWebsiteOutput {
    let protocol = |p: Protocol| dto::Protocol::from_static(p.name());
    match config {
        WebsiteConfig::RedirectAll {
            host_name,
            protocol: p,
        } => dto::GetBucketWebsiteOutput {
            redirect_all_requests_to: Some(dto::RedirectAllRequestsTo {
                host_name: host_name.clone(),
                protocol: p.map(protocol),
            }),
            ..Default::default()
        },
        WebsiteConfig::Site(site) => dto::GetBucketWebsiteOutput {
            index_document: Some(dto::IndexDocument {
                suffix: site.index_suffix.clone(),
            }),
            error_document: site.error_key.clone().map(|key| dto::ErrorDocument { key }),
            routing_rules: (!site.routing_rules.is_empty()).then(|| {
                site.routing_rules
                    .iter()
                    .map(|rule| dto::RoutingRule {
                        condition: rule.condition.as_ref().map(|c| dto::Condition {
                            key_prefix_equals: c.key_prefix.clone(),
                            http_error_code_returned_equals: c
                                .error_code
                                .map(|code| code.to_string()),
                        }),
                        redirect: dto::Redirect {
                            host_name: rule.redirect.host_name.clone(),
                            protocol: rule.redirect.protocol.map(protocol),
                            http_redirect_code: rule
                                .redirect
                                .http_redirect_code
                                .map(|code| code.to_string()),
                            replace_key_prefix_with: match &rule.redirect.replace_key {
                                Some(KeyReplacement::Prefix(prefix)) => Some(prefix.clone()),
                                _ => None,
                            },
                            replace_key_with: match &rule.redirect.replace_key {
                                Some(KeyReplacement::Key(key)) => Some(key.clone()),
                                _ => None,
                            },
                        },
                    })
                    .collect()
            }),
            ..Default::default()
        },
    }
}

/// `config` checked again as `PutBucketWebsite` checks it (for an import).
pub(crate) fn check(config: &WebsiteConfig) -> S3Result<WebsiteConfig> {
    let answer = to_dto(config);
    from_dto(dto::WebsiteConfiguration {
        error_document: answer.error_document,
        index_document: answer.index_document,
        redirect_all_requests_to: answer.redirect_all_requests_to,
        routing_rules: answer.routing_rules,
    })
}

/// An object's `x-amz-website-redirect-location`, checked as S3 checks it: another
/// object of the bucket (`/key`) or a URL.
pub(crate) fn redirect_location(location: Option<String>) -> S3Result<Option<String>> {
    match location {
        Some(location)
            if !["/", "http://", "https://"]
                .iter()
                .any(|prefix| location.starts_with(prefix)) =>
        {
            let mut err = S3Error::with_message(
                s3s::S3ErrorCode::Custom("InvalidRedirectLocation".into()),
                "The website redirect location must have a prefix of 'http://' or 'https://' or \
                 '/'.",
            );
            err.set_status_code(http::StatusCode::BAD_REQUEST);
            Err(err)
        }
        location => Ok(location),
    }
}

/// `NoSuchWebsiteConfiguration`, for a bucket that isn't a website.
pub(crate) fn no_such_website() -> S3Error {
    s3_error!(
        NoSuchWebsiteConfiguration,
        "The specified bucket does not have a website configuration"
    )
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn malformed() -> S3Error {
    s3_error!(
        MalformedXML,
        "The XML you provided was not well-formed or did not validate against our published schema"
    )
}

fn invalid_request(message: String) -> S3Error {
    S3Error::with_message(s3s::S3ErrorCode::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    fn site(rules: Vec<dto::RoutingRule>) -> dto::WebsiteConfiguration {
        dto::WebsiteConfiguration {
            index_document: Some(dto::IndexDocument {
                suffix: "index.html".to_owned(),
            }),
            error_document: None,
            redirect_all_requests_to: None,
            routing_rules: Some(rules),
        }
    }

    fn rule(condition: Option<dto::Condition>, redirect: dto::Redirect) -> dto::RoutingRule {
        dto::RoutingRule {
            condition,
            redirect,
        }
    }

    fn refused(config: dto::WebsiteConfiguration) -> (String, String) {
        let err = from_dto(config).unwrap_err();
        (
            err.code().as_str().to_owned(),
            err.message().unwrap_or_default().to_owned(),
        )
    }

    fn to_host() -> dto::Redirect {
        dto::Redirect {
            host_name: Some("example.com".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn a_site_round_trips_as_given() {
        let given = dto::WebsiteConfiguration {
            index_document: Some(dto::IndexDocument {
                suffix: "index.html".to_owned(),
            }),
            error_document: Some(dto::ErrorDocument {
                key: "404.html".to_owned(),
            }),
            redirect_all_requests_to: None,
            routing_rules: Some(vec![
                rule(
                    Some(dto::Condition {
                        key_prefix_equals: Some("docs/".to_owned()),
                        http_error_code_returned_equals: None,
                    }),
                    dto::Redirect {
                        replace_key_prefix_with: Some("documents/".to_owned()),
                        ..Default::default()
                    },
                ),
                rule(
                    Some(dto::Condition {
                        key_prefix_equals: None,
                        http_error_code_returned_equals: Some("404".to_owned()),
                    }),
                    dto::Redirect {
                        host_name: Some("example.com".to_owned()),
                        protocol: Some(dto::Protocol::from_static("https")),
                        http_redirect_code: Some("302".to_owned()),
                        replace_key_with: Some("missing.html".to_owned()),
                        ..Default::default()
                    },
                ),
            ]),
        };
        let config = from_dto(given.clone()).unwrap();
        let answered = to_dto(&config);
        assert_eq!(answered.index_document, given.index_document);
        assert_eq!(answered.error_document, given.error_document);
        assert_eq!(answered.routing_rules, given.routing_rules);
        assert_eq!(answered.redirect_all_requests_to, None);
        let all = from_dto(dto::WebsiteConfiguration {
            redirect_all_requests_to: Some(dto::RedirectAllRequestsTo {
                host_name: "example.com".to_owned(),
                protocol: None,
            }),
            ..Default::default()
        })
        .unwrap();
        let answered = to_dto(&all);
        assert_eq!(
            answered.redirect_all_requests_to.unwrap().host_name,
            "example.com"
        );
        assert_eq!(answered.index_document, None);
    }

    #[test]
    fn documents_and_redirects_are_refused_as_s3_refuses_them() {
        let invalid_argument = |message: &str| ("InvalidArgument".to_owned(), message.to_owned());
        let invalid_request = |message: &str| ("InvalidRequest".to_owned(), message.to_owned());
        assert_eq!(
            refused(dto::WebsiteConfiguration::default()),
            invalid_argument(
                "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty"
            )
        );
        for suffix in ["", "a/index.html"] {
            let mut config = site(vec![]);
            config.index_document = Some(dto::IndexDocument {
                suffix: suffix.to_owned(),
            });
            assert_eq!(
                refused(config),
                invalid_argument("The IndexDocument Suffix is not well formed")
            );
        }
        let mut config = site(vec![]);
        config.error_document = Some(dto::ErrorDocument { key: String::new() });
        assert_eq!(
            refused(config),
            invalid_argument("The ErrorDocument Key is not well formed")
        );
        // RedirectAllRequestsTo goes alone, and names a host.
        let mut config = site(vec![]);
        config.redirect_all_requests_to = Some(dto::RedirectAllRequestsTo {
            host_name: "example.com".to_owned(),
            protocol: None,
        });
        assert_eq!(refused(config).0, "MalformedXML");
        let all = |host: &str, protocol: &str| dto::WebsiteConfiguration {
            redirect_all_requests_to: Some(dto::RedirectAllRequestsTo {
                host_name: host.to_owned(),
                protocol: Some(dto::Protocol::from(protocol.to_owned())),
            }),
            ..Default::default()
        };
        assert_eq!(refused(all("", "https")).0, "MalformedXML");
        let bad_protocol = invalid_request(
            "Invalid protocol, protocol can be http or https. If not defined the protocol will be \
             selected automatically.",
        );
        assert_eq!(refused(all("example.com", "ftp")), bad_protocol);
    }

    #[test]
    fn routing_rules_are_refused_as_s3_refuses_them() {
        let invalid_request = |message: &str| ("InvalidRequest".to_owned(), message.to_owned());
        let bad_protocol = invalid_request(
            "Invalid protocol, protocol can be http or https. If not defined the protocol will be \
             selected automatically.",
        );
        // Up to 50 rules.
        let rules = |n| (0..n).map(|_| rule(None, to_host())).collect::<Vec<_>>();
        from_dto(site(rules(50))).unwrap();
        assert_eq!(
            refused(site(rules(51))),
            invalid_request(
                "51 routing rules provided, the number of routing rules in a website \
                 configuration is limited to 50."
            )
        );
        // A redirect names something, one key replacement at most, S3's codes.
        assert_eq!(
            refused(site(vec![rule(None, dto::Redirect::default())])).0,
            "MalformedXML"
        );
        let both = dto::Redirect {
            replace_key_prefix_with: Some("a/".to_owned()),
            replace_key_with: Some("b".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            refused(site(vec![rule(None, both)])),
            invalid_request("You can only define ReplaceKeyPrefix or ReplaceKey but not both.")
        );
        let code = |code: &str| dto::Redirect {
            http_redirect_code: Some(code.to_owned()),
            ..Default::default()
        };
        from_dto(site(vec![rule(None, code("308"))])).unwrap();
        assert_eq!(
            refused(site(vec![rule(None, code("300"))])),
            invalid_request(
                "The provided HTTP redirect code (300) is not valid. Valid codes are 3XX except 300."
            )
        );
        assert_eq!(refused(site(vec![rule(None, code("x"))])).0, "MalformedXML");
        let ftp = dto::Redirect {
            protocol: Some(dto::Protocol::from("ftp".to_owned())),
            ..Default::default()
        };
        assert_eq!(refused(site(vec![rule(None, ftp)])), bad_protocol);
        // A condition names a prefix or an error code S3 takes.
        let condition = |prefix: Option<&str>, code: Option<&str>| {
            Some(dto::Condition {
                key_prefix_equals: prefix.map(str::to_owned),
                http_error_code_returned_equals: code.map(str::to_owned),
            })
        };
        assert_eq!(
            refused(site(vec![rule(condition(None, None), to_host())])).0,
            "MalformedXML"
        );
        assert_eq!(
            refused(site(vec![rule(condition(Some(""), None), to_host())])).0,
            "MalformedXML"
        );
        assert_eq!(
            refused(site(vec![rule(condition(None, Some("302")), to_host())])),
            invalid_request(
                "The provided HTTP error code (302) is not valid. Valid codes are 4XX or 5XX."
            )
        );
        assert_eq!(
            refused(site(vec![rule(condition(None, Some("4o4")), to_host())])).0,
            "MalformedXML"
        );
        from_dto(site(vec![rule(
            condition(Some("a/"), Some("404")),
            to_host(),
        )]))
        .unwrap();
        // The redirect is checked first.
        assert_eq!(
            refused(site(vec![rule(
                condition(None, Some("302")),
                dto::Redirect::default()
            )]))
            .0,
            "MalformedXML"
        );
    }
}
