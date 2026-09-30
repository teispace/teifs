//! Static website hosting: `teifs website set|info|rm` for how a bucket answers on its
//! website endpoint (S3's `PutBucketWebsite`).

use std::path::Path;

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::operation::get_bucket_website::GetBucketWebsiteOutput;
use aws_sdk_s3::types::{
    Condition, ErrorDocument, IndexDocument, Protocol, Redirect, RedirectAllRequestsTo,
    RoutingRule, WebsiteConfiguration,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Error, WebsiteAction, alias::Aliases, target::Target};
use crate::ui;

/// `teifs website …`.
pub(super) async fn website(action: WebsiteAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        WebsiteAction::Set {
            bucket,
            index,
            error,
            rules,
            redirect_all,
        } => {
            let remote = Target::parse(&bucket, aliases)?.remote("website")?;
            let config = match redirect_all {
                Some(to) => redirect_all_to(&to)?,
                None => site(&index, error.as_deref(), rules.as_deref())?,
            };
            let name = remote.display("");
            remote
                .alias
                .client()
                .put_bucket_website()
                .bucket(remote.bucket()?)
                .website_configuration(config.clone())
                .send()
                .await
                .map_err(|e| Error::s3(format!("can't make {name} a website"), &e))?;
            ui::done(format!("Website {name}: {}", summary(&config)), || {
                record(&name, Some(&config))
            });
            Ok(())
        }
        WebsiteAction::Info { bucket } => {
            let remote = Target::parse(&bucket, aliases)?.remote("website")?;
            let name = remote.display("");
            let answer = remote
                .alias
                .client()
                .get_bucket_website()
                .bucket(remote.bucket()?)
                .send()
                .await;
            let config = match answer {
                Ok(answer) => Some(from_answer(answer)),
                Err(e)
                    if e.as_service_error().and_then(ProvideErrorMetadata::code)
                        == Some("NoSuchWebsiteConfiguration") =>
                {
                    None
                }
                Err(e) => {
                    return Err(Error::s3(format!("can't read the website of {name}"), &e));
                }
            };
            let text = config.as_ref().map_or_else(|| "off".to_owned(), summary);
            ui::details(&[("Bucket", name.clone()), ("Website", text)], || {
                record(&name, config.as_ref())
            });
            Ok(())
        }
        WebsiteAction::Rm { bucket } => {
            let remote = Target::parse(&bucket, aliases)?.remote("website")?;
            let name = remote.display("");
            remote
                .alias
                .client()
                .delete_bucket_website()
                .bucket(remote.bucket()?)
                .send()
                .await
                .map_err(|e| Error::s3(format!("can't remove the website of {name}"), &e))?;
            ui::done(format!("Website {name}: off"), || record(&name, None));
            Ok(())
        }
    }
}

/// `--redirect-all`: a host, or a URL naming the protocol too.
fn redirect_all_to(to: &str) -> Result<WebsiteConfiguration, Error> {
    let (protocol, host) = match to.split_once("://") {
        Some(("http", host)) => (Some(Protocol::Http), host),
        Some(("https", host)) => (Some(Protocol::Https), host),
        Some(_) => {
            return Err(Error::usage(format!(
                "--redirect-all {to}: give a host, or an http:// or https:// URL"
            )));
        }
        None => (None, to),
    };
    let host = host.trim_end_matches('/');
    if host.is_empty() || host.contains('/') {
        return Err(Error::usage(format!(
            "--redirect-all {to}: give a host (like example.com), without a path"
        )));
    }
    let all = RedirectAllRequestsTo::builder()
        .host_name(host)
        .set_protocol(protocol)
        .build()
        .map_err(|e| Error::usage(e.to_string()))?;
    Ok(WebsiteConfiguration::builder()
        .redirect_all_requests_to(all)
        .build())
}

fn site(
    index: &str,
    error: Option<&str>,
    rules: Option<&Path>,
) -> Result<WebsiteConfiguration, Error> {
    let index = IndexDocument::builder()
        .suffix(index)
        .build()
        .map_err(|e| Error::usage(e.to_string()))?;
    let error = error
        .map(|key| ErrorDocument::builder().key(key).build())
        .transpose()
        .map_err(|e| Error::usage(e.to_string()))?;
    let rules = rules
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .map_err(|e| Error::usage(format!("can't read {}: {e}", path.display())))?;
            routing_rules(&text).map_err(|why| {
                Error::usage(format!(
                    "{} isn't a list of redirection rules ({why}): give JSON as the S3 \
                     console takes it",
                    path.display()
                ))
            })
        })
        .transpose()?;
    Ok(WebsiteConfiguration::builder()
        .index_document(index)
        .set_error_document(error)
        .set_routing_rules(rules)
        .build())
}

/// A routing rule as the S3 console and the AWS CLI write it.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RuleJson {
    #[serde(default)]
    condition: Option<ConditionJson>,
    redirect: RedirectJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ConditionJson {
    key_prefix_equals: Option<String>,
    http_error_code_returned_equals: Option<CodeJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RedirectJson {
    host_name: Option<String>,
    http_redirect_code: Option<CodeJson>,
    protocol: Option<String>,
    replace_key_prefix_with: Option<String>,
    replace_key_with: Option<String>,
}

/// A status code, which the console writes as text and people often as a number.
#[derive(Deserialize)]
#[serde(untagged)]
enum CodeJson {
    Text(String),
    Number(u16),
}

impl CodeJson {
    fn text(self) -> String {
        match self {
            Self::Text(text) => text,
            Self::Number(number) => number.to_string(),
        }
    }
}

/// The rules in `text`: a list, or `{"RoutingRules": [...]}`.
fn routing_rules(text: &str) -> Result<Vec<RoutingRule>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let list = match value {
        Value::Object(mut object) if object.contains_key("RoutingRules") => {
            object.remove("RoutingRules").expect("just checked")
        }
        other => other,
    };
    let rules: Vec<RuleJson> = serde_json::from_value(list).map_err(|e| e.to_string())?;
    Ok(rules
        .into_iter()
        .map(|rule| {
            let condition = rule.condition.map(|c| {
                Condition::builder()
                    .set_key_prefix_equals(c.key_prefix_equals)
                    .set_http_error_code_returned_equals(
                        c.http_error_code_returned_equals.map(CodeJson::text),
                    )
                    .build()
            });
            let r = rule.redirect;
            RoutingRule::builder()
                .set_condition(condition)
                .redirect(
                    Redirect::builder()
                        .set_host_name(r.host_name)
                        .set_http_redirect_code(r.http_redirect_code.map(CodeJson::text))
                        .set_protocol(r.protocol.as_deref().map(Protocol::from))
                        .set_replace_key_prefix_with(r.replace_key_prefix_with)
                        .set_replace_key_with(r.replace_key_with)
                        .build(),
                )
                .build()
        })
        .collect())
}

fn from_answer(answer: GetBucketWebsiteOutput) -> WebsiteConfiguration {
    WebsiteConfiguration::builder()
        .set_index_document(answer.index_document)
        .set_error_document(answer.error_document)
        .set_redirect_all_requests_to(answer.redirect_all_requests_to)
        .set_routing_rules(answer.routing_rules)
        .build()
}

/// A configuration in words.
fn summary(config: &WebsiteConfiguration) -> String {
    if let Some(all) = config.redirect_all_requests_to() {
        let protocol = all
            .protocol()
            .map_or_else(String::new, |p| format!("{}://", p.as_str()));
        return format!("every request to {protocol}{}", all.host_name());
    }
    let mut parts = vec![format!(
        "index {}",
        config.index_document().map_or("-", IndexDocument::suffix)
    )];
    if let Some(error) = config.error_document() {
        parts.push(format!("errors {}", error.key()));
    }
    match config.routing_rules().len() {
        0 => {}
        1 => parts.push("1 redirection rule".to_owned()),
        rules => parts.push(format!("{rules} redirection rules")),
    }
    parts.join(", ")
}

fn record(bucket: &str, config: Option<&WebsiteConfiguration>) -> Value {
    let all = config.and_then(WebsiteConfiguration::redirect_all_requests_to);
    json!({
        "type": "website",
        "bucket": bucket,
        "enabled": config.is_some(),
        "indexDocument": config.and_then(|c| c.index_document()).map(IndexDocument::suffix),
        "errorDocument": config.and_then(|c| c.error_document()).map(ErrorDocument::key),
        "routingRules": config.map_or(0, |c| c.routing_rules().len()),
        "redirectAllTo": all.map(RedirectAllRequestsTo::host_name),
        "redirectAllProtocol": all.and_then(RedirectAllRequestsTo::protocol).map(Protocol::as_str),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    #[test]
    fn rules_are_read_as_the_console_writes_them() {
        let rules = routing_rules(
            r#"[{"Condition": {"KeyPrefixEquals": "docs/"},
                 "Redirect": {"ReplaceKeyPrefixWith": "documents/"}},
                {"Condition": {"HttpErrorCodeReturnedEquals": 404},
                 "Redirect": {"HostName": "example.com", "Protocol": "https",
                              "HttpRedirectCode": "302"}}]"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0].condition().unwrap().key_prefix_equals(),
            Some("docs/")
        );
        assert_eq!(
            rules[1]
                .condition()
                .unwrap()
                .http_error_code_returned_equals(),
            Some("404")
        );
        assert_eq!(
            rules[1].redirect().unwrap().protocol(),
            Some(&Protocol::Https)
        );
        let wrapped = routing_rules(r#"{"RoutingRules": [{"Redirect": {"HostName": "a"}}]}"#);
        assert_eq!(wrapped.unwrap().len(), 1);
        assert!(routing_rules(r#"[{"Redirect": {"Hostname": "a"}}]"#).is_err());
        assert!(routing_rules("[{}]").is_err());
        assert!(routing_rules("{").is_err());
    }

    #[test]
    fn redirect_all_takes_a_host_or_a_url() {
        let host = |to: &str| {
            let config = redirect_all_to(to).unwrap();
            let all = config.redirect_all_requests_to().unwrap();
            (
                all.host_name().to_owned(),
                all.protocol().map(|p| p.as_str().to_owned()),
            )
        };
        assert_eq!(host("example.com"), ("example.com".to_owned(), None));
        assert_eq!(
            host("https://example.com/"),
            ("example.com".to_owned(), Some("https".to_owned()))
        );
        for bad in [
            "ftp://example.com",
            "https://example.com/path",
            "",
            "https://",
        ] {
            assert!(redirect_all_to(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn configurations_are_summed_up() {
        let config = site("index.html", Some("404.html"), None).unwrap();
        assert_eq!(summary(&config), "index index.html, errors 404.html");
        let all = redirect_all_to("https://example.com").unwrap();
        assert_eq!(summary(&all), "every request to https://example.com");
    }
}
