//! Runs `corpus.json`: policies from AWS's documentation and its known pitfalls, each
//! with requests and the decision AWS documents for them. Every case is checked, and
//! every failure is reported together.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use serde_json::{Map, Value as Json};
use teifs_policy::{
    Context, Date, Decision, Kind, Policies, Policy, Principal, Request, S3Key, TagKind, Value,
    evaluate,
};

fn corpus() -> Json {
    serde_json::from_str(include_str!("corpus.json")).expect("corpus.json is JSON")
}

fn policy(json: &Json, kind: Kind) -> Policy {
    Policy::parse(&json.to_string(), kind).unwrap_or_else(|e| panic!("{e}: {json}"))
}

/// `alice`, `alice@c-alice` (with a canonical id), `session`, `root`, `anonymous`.
fn principal(name: &str, account: &str) -> Principal {
    match name {
        "root" => Principal::root(account),
        "anonymous" => Principal::anonymous(),
        "session" => Principal::session(account, "/", "reader", "AROAREADER", "job"),
        _ => match name.split_once('@') {
            Some((user, canonical)) => user_named(account, user).with_canonical_id(canonical),
            None => user_named(account, name),
        },
    }
}

fn user_named(account: &str, name: &str) -> Principal {
    Principal::user(account, "/", name, &format!("AIDA{}", name.to_uppercase()))
}

/// The scenario's context with the case's changes on top (`s3` entries merge).
fn merged(base: &Json, changes: Option<&Json>) -> Map<String, Json> {
    let mut context = base.as_object().cloned().unwrap_or_default();
    if let Some(Json::Object(changes)) = changes {
        for (key, value) in changes {
            match (key.as_str(), context.get_mut("s3")) {
                ("s3", Some(Json::Object(s3))) => s3.extend(value.as_object().unwrap().clone()),
                _ => {
                    context.insert(key.clone(), value.clone());
                }
            }
        }
    }
    context
}

fn context(principal: Principal, fields: &Map<String, Json>) -> Context {
    let text = |name: &str| fields.get(name).and_then(Json::as_str);
    let time = Date::parse(text("time").expect("a time")).expect("a valid time");
    let mut context = Context::new(principal, time).with_secure_transport(
        fields
            .get("secureTransport")
            .and_then(Json::as_bool)
            .unwrap_or(false),
    );
    if let Some(ip) = text("sourceIp") {
        context = context.with_source_ip(ip.parse().expect("an address"));
    }
    if let Some(agent) = text("userAgent") {
        context = context.with_user_agent(agent);
    }
    if let Some(referer) = text("referer") {
        context = context.with_referer(referer);
    }
    for (name, value) in fields
        .get("s3")
        .and_then(Json::as_object)
        .into_iter()
        .flatten()
    {
        let key = *S3Key::ALL
            .iter()
            .find(|k| k.name() == name)
            .unwrap_or_else(|| panic!("no key {name}"));
        let value = match value {
            Json::String(s) => Value::from(s.as_str()),
            Json::Bool(b) => Value::from(*b),
            Json::Number(n) => {
                Value::from(teifs_policy::Number::parse(&n.to_string()).expect("a number"))
            }
            Json::Array(items) => Value::from(
                items
                    .iter()
                    .map(|i| i.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>(),
            ),
            other => panic!("{name}: {other}"),
        };
        context = context.with(key, value);
    }
    for tag in fields
        .get("tags")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        let [kind, key, value] = [0, 1, 2].map(|i| tag[i].as_str().unwrap());
        let kind = *TagKind::ALL
            .iter()
            .find(|k| k.name() == kind)
            .unwrap_or_else(|| panic!("no tag kind {kind}"));
        context = context.with_tag(kind, key, value);
    }
    context
}

#[test]
fn every_case_decides_as_documented() {
    let corpus = corpus();
    let account = corpus["account"].as_str().unwrap();
    let mut failures = Vec::new();
    let mut count = 0;
    for scenario in corpus["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let identity = |who: &str| -> Vec<Policy> {
            let named = |key: &str| {
                scenario["identity"][key]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            };
            let mut list = Vec::new();
            if !matches!(who, "root" | "anonymous") {
                list.extend(named("*"));
            }
            list.extend(named(who.split('@').next().unwrap()));
            list.iter().map(|p| policy(p, Kind::Identity)).collect()
        };
        let resource = scenario.get("resource").map(|p| policy(p, Kind::Resource));
        let session_policies: Option<Vec<Policy>> = scenario.get("sessionPolicies").map(|list| {
            list.as_array()
                .unwrap()
                .iter()
                .map(|p| policy(p, Kind::Identity))
                .collect()
        });
        for case in scenario["cases"].as_array().unwrap() {
            let who = case[0].as_str().unwrap();
            let (action, resource_arn, expected) = (
                case[1].as_str().unwrap(),
                case[2].as_str().unwrap(),
                case[3].as_str().unwrap(),
            );
            let context = context(
                principal(who, account),
                &merged(&corpus["context"], case.get(4)),
            );
            let identity = identity(who);
            let identity: Vec<&Policy> = identity.iter().collect();
            let boundary = scenario["boundary"]
                .get(who)
                .map(|p| policy(p, Kind::Identity));
            let session: Option<Vec<&Policy>> = (who == "session")
                .then(|| session_policies.as_ref().map(|list| list.iter().collect()))
                .flatten();
            let policies = Policies {
                identity: &identity,
                resource: resource.as_ref(),
                boundary: boundary.as_ref(),
                session: session.as_deref(),
            };
            let decision = evaluate(
                &policies,
                &Request {
                    action,
                    resource: resource_arn,
                    context: &context,
                },
            );
            let wanted = match expected {
                "Allow" => Decision::Allow,
                "ExplicitDeny" => Decision::ExplicitDeny,
                "ImplicitDeny" => Decision::ImplicitDeny,
                other => panic!("{other}"),
            };
            if decision != wanted {
                failures.push(format!("{name}: {case} gave {decision:?}"));
            }
            count += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {count} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(count >= 250, "{count} cases");
}

#[test]
fn the_corpus_names_only_known_keys() {
    // A mistyped key is never present, and would make a case pass for the wrong reason.
    let corpus = corpus();
    let mut policies = Vec::new();
    for scenario in corpus["scenarios"].as_array().unwrap() {
        for (kind, list) in [
            (
                Kind::Identity,
                scenario["identity"]
                    .as_object()
                    .into_iter()
                    .flat_map(|m| m.values())
                    .flat_map(|l| l.as_array().unwrap())
                    .collect::<Vec<_>>(),
            ),
            (
                Kind::Identity,
                scenario["boundary"]
                    .as_object()
                    .into_iter()
                    .flat_map(|m| m.values())
                    .collect(),
            ),
            (
                Kind::Identity,
                scenario["sessionPolicies"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .collect(),
            ),
            (
                Kind::Resource,
                scenario.get("resource").into_iter().collect(),
            ),
        ] {
            policies.extend(list.into_iter().map(|p| policy(p, kind)));
        }
    }
    assert!(policies.len() > 40, "{}", policies.len());
    for policy in &policies {
        let unknown: Vec<&str> = policy.unknown_condition_keys().collect();
        assert!(unknown.is_empty(), "{unknown:?}");
    }
    let typo = policy(
        &serde_json::json!({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransprot": "true"}}}}),
        Kind::Identity,
    );
    assert_eq!(
        typo.unknown_condition_keys().collect::<Vec<_>>(),
        ["aws:SecureTransprot"]
    );
}
