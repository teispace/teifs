//! Bucket, identity and trust policies (`Policy::parse`), and a policy that parses
//! evaluated against a request, which matches its patterns and conditions.
#![no_main]

use libfuzzer_sys::fuzz_target;
use teifs_policy::{Context, Date, Kind, Policies, Policy, Principal, Request, evaluate};

fuzz_target!(|text: &str| {
    let context = Context::new(
        Principal::user("123456789012", "/", "alice", "AIDAFUZZ"),
        Date::from_unix_seconds(1_800_000_000),
    );
    for kind in [Kind::Identity, Kind::Resource, Kind::Trust] {
        let Ok(policy) = Policy::parse(text, kind) else {
            continue;
        };
        let _ = policy.check_s3();
        let _ = policy.check_bucket("photos");
        let _ = policy.is_public();
        let identity = [&policy];
        let policies = match kind {
            Kind::Resource => Policies {
                resource: Some(&policy),
                ..Policies::default()
            },
            _ => Policies {
                identity: &identity,
                ..Policies::default()
            },
        };
        for (action, resource) in [
            ("s3:GetObject", "arn:aws:s3:::photos/2026/a b.jpg"),
            ("s3:ListBucket", "arn:aws:s3:::photos"),
            ("sts:AssumeRole", "arn:aws:iam::123456789012:role/r"),
        ] {
            let _ = evaluate(
                &policies,
                &Request {
                    action,
                    resource,
                    context: &context,
                },
            );
        }
    }
});
