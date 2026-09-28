//! Properties of the decision that hold for any policies: checked on thousands of
//! random ones built from pieces that overlap often (so allows, denies and conditions
//! collide). A seeded generator keeps failures reproducible without a dependency.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use serde_json::{Value as Json, json};
use teifs_policy::{
    Context, Date, Decision, Kind, Policies, Policy, Principal, Request, S3Key, TagKind, evaluate,
};

/// xorshift64*: small, fast, and the same everywhere.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

const ACTIONS: &[&str] = &[
    "s3:GetObject",
    "s3:PutObject",
    "s3:Get*",
    "s3:*",
    "*",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:?utObject",
];
const RESOURCES: &[&str] = &[
    "*",
    "arn:aws:s3:::a/*",
    "arn:aws:s3:::a/x",
    "arn:aws:s3:::b/*",
    "arn:aws:s3:::*",
    "arn:aws:s3:::a",
    "arn:aws:s3:::${aws:username}/*",
];
const REQUEST_ACTIONS: &[&str] = &[
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:GetObjectVersion",
];
const REQUEST_RESOURCES: &[&str] = &[
    "arn:aws:s3:::a/x",
    "arn:aws:s3:::a/y",
    "arn:aws:s3:::b/x",
    "arn:aws:s3:::a",
    "arn:aws:s3:::c/z",
    "arn:aws:s3:::alice/k",
];

fn condition(rng: &mut Rng) -> Option<Json> {
    Some(match rng.below(8) {
        0 => json!({"Bool": {"aws:SecureTransport": "true"}}),
        1 => json!({"StringLike": {"s3:prefix": "p*"}}),
        2 => json!({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}),
        3 => json!({"ForAllValues:StringEquals": {"aws:TagKeys": ["t"]}}),
        4 => json!({"StringNotEquals": {"s3:prefix": "x"}}),
        5 => json!({"ForAnyValue:StringNotLike": {"aws:TagKeys": "t*"}}),
        _ => return None,
    })
}

fn one_or_two(rng: &mut Rng, pool: &[&str]) -> Json {
    if rng.chance(70) {
        json!(rng.pick(pool))
    } else {
        json!([rng.pick(pool), rng.pick(pool)])
    }
}

fn statement(rng: &mut Rng, effect: &str) -> Json {
    let mut s = json!({"Effect": effect});
    let action = if rng.chance(85) {
        "Action"
    } else {
        "NotAction"
    };
    s[action] = one_or_two(rng, ACTIONS);
    let resource = if rng.chance(85) {
        "Resource"
    } else {
        "NotResource"
    };
    s[resource] = one_or_two(rng, RESOURCES);
    if let Some(condition) = condition(rng) {
        s["Condition"] = condition;
    }
    s
}

fn random_statements(rng: &mut Rng) -> Vec<Json> {
    (0..=rng.below(4))
        .map(|_| {
            let effect = if rng.chance(70) { "Allow" } else { "Deny" };
            statement(rng, effect)
        })
        .collect()
}

fn policy(statements: &[Json]) -> Policy {
    let text = json!({"Version": "2012-10-17", "Statement": statements}).to_string();
    Policy::parse(&text, Kind::Identity).unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn context(rng: &mut Rng) -> Context {
    let principal = if rng.chance(50) {
        Principal::user("123456789012", "/", "alice", "AIDAALICE")
    } else {
        Principal::session("123456789012", "/", "reader", "AROAREADER", "job")
    };
    let mut context = Context::new(principal, Date::from_unix_seconds(1_790_000_000))
        .with_secure_transport(rng.chance(50));
    if rng.chance(60) {
        context = context.with_source_ip(
            if rng.chance(50) {
                "10.1.2.3"
            } else {
                "192.0.2.1"
            }
            .parse()
            .unwrap(),
        );
    }
    if rng.chance(60) {
        context = context.with(S3Key::Prefix, *rng.pick(&["p1", "x", "q"]));
    }
    for _ in 0..rng.below(3) {
        context = context.with_tag(TagKind::Request, rng.pick(&["t", "tx", "u"]), "v");
    }
    context
}

fn decide(
    identity: &[&Policy],
    boundary: Option<&Policy>,
    session: Option<&[&Policy]>,
    request: &Request<'_>,
) -> Decision {
    evaluate(
        &Policies {
            identity,
            resource: None,
            boundary,
            session,
        },
        request,
    )
}

const TRIALS: usize = 4_000;

#[test]
fn decisions_obey_the_laws_of_policy_evaluation() {
    let mut rng = Rng(0x7E1F_5EED_0000_0001);
    let mut seen = [0_usize; 3];
    for trial in 0..TRIALS {
        let statements = random_statements(&mut rng);
        let whole = policy(&statements);
        let context = context(&mut rng);
        let request = Request {
            action: rng.pick(REQUEST_ACTIONS),
            resource: rng.pick(REQUEST_RESOURCES),
            context: &context,
        };
        let decision = decide(&[&whole], None, None, &request);
        seen[decision as usize] += 1;
        let at = || {
            format!(
                "trial {trial}: {statements:?} on {} {}",
                request.action, request.resource
            )
        };

        // Statement order doesn't matter.
        let mut reversed = statements.clone();
        reversed.reverse();
        assert_eq!(
            decide(&[&policy(&reversed)], None, None, &request),
            decision,
            "order: {}",
            at()
        );

        // One policy or one per statement: the same.
        let split: Vec<Policy> = statements
            .iter()
            .map(|s| policy(std::slice::from_ref(s)))
            .collect();
        let split: Vec<&Policy> = split.iter().collect();
        assert_eq!(
            decide(&split, None, None, &request),
            decision,
            "split: {}",
            at()
        );

        // A Deny wins wherever it is, and only a Deny that applies on its own denies.
        let denied_alone = split
            .iter()
            .any(|p| decide(&[p], None, None, &request) == Decision::ExplicitDeny);
        assert_eq!(
            decision == Decision::ExplicitDeny,
            denied_alone,
            "deny: {}",
            at()
        );

        // Adding an Allow never takes access away; adding a Deny never gives it.
        let mut more = statements.clone();
        more.push(statement(&mut rng, "Allow"));
        let with_allow = decide(&[&policy(&more)], None, None, &request);
        if decision != Decision::ImplicitDeny {
            assert_eq!(with_allow, decision, "allow: {}", at());
        }
        more.pop();
        more.push(statement(&mut rng, "Deny"));
        let with_deny = decide(&[&policy(&more)], None, None, &request);
        assert!(
            with_deny == decision || with_deny == Decision::ExplicitDeny,
            "deny added: {}",
            at()
        );

        // A boundary or session policy only narrows; the same policy as a boundary
        // changes nothing.
        let limit = policy(&random_statements(&mut rng));
        for limited in [
            decide(&[&whole], Some(&limit), None, &request),
            decide(&[&whole], None, Some(&[&limit]), &request),
            decide(&[&whole], Some(&limit), Some(&[&limit]), &request),
        ] {
            if limited == Decision::Allow {
                assert_eq!(decision, Decision::Allow, "narrow: {}", at());
            }
            if decision == Decision::ExplicitDeny {
                assert_eq!(limited, Decision::ExplicitDeny, "narrow: {}", at());
            }
        }
        assert_eq!(
            decide(&[&whole], Some(&whole), Some(&[&whole]), &request),
            decision,
            "same: {}",
            at()
        );
        // An empty list of session policies allows nothing.
        assert_ne!(
            decide(&[&whole], None, Some(&[]), &request),
            Decision::Allow,
            "empty session: {}",
            at()
        );
    }
    // Every outcome turned up often enough for the checks to mean something.
    assert!(seen.iter().all(|&n| n > TRIALS / 20), "{seen:?}");
}

#[test]
fn the_root_user_is_denied_only_explicitly() {
    let mut rng = Rng(0x0000_0000_BADC_0FFE);
    for _ in 0..TRIALS / 4 {
        let statements: Vec<Json> = random_statements(&mut rng)
            .into_iter()
            .map(|mut s| {
                s["Principal"] = json!("*");
                s
            })
            .collect();
        let text = json!({"Version": "2012-10-17", "Statement": statements}).to_string();
        let bucket = Policy::parse(&text, Kind::Resource).unwrap();
        let context = Context::new(Principal::root("123456789012"), Date::from_unix_seconds(0));
        let request = Request {
            action: rng.pick(REQUEST_ACTIONS),
            resource: rng.pick(REQUEST_RESOURCES),
            context: &context,
        };
        let decision = evaluate(
            &Policies {
                resource: Some(&bucket),
                ..Policies::default()
            },
            &request,
        );
        assert_ne!(decision, Decision::ImplicitDeny, "{text}");
    }
}
