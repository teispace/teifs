//! `MinIO`'s admin and KMS actions in policies: statements without a `Resource`, admin
//! actions that ignore one, and TeiFS's admin actions granted by their `MinIO` names.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use teifs_policy::{Context, Date, Decision, Kind, Policies, Policy, Principal, Request, evaluate};

fn policy(statements: &str) -> Policy {
    let text = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
    Policy::parse(&text, Kind::Identity).unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn decide(policy: &Policy, action: &str, resource: &str) -> Decision {
    let context = Context::new(
        Principal::user("123456789012", "/", "alice", "AIDAALICE"),
        Date::from_unix_seconds(1_790_000_000),
    );
    evaluate(
        &Policies {
            identity: &[policy],
            ..Policies::default()
        },
        &Request {
            action,
            resource,
            context: &context,
        },
    )
}

#[test]
fn minio_admin_policies_grant_teifs_admin_actions() {
    // MinIO's diagnostics policy, as MinIO writes it.
    let diagnostics = policy(
        r#"{"Effect":"Allow","Action":["admin:ServerInfo","admin:ServerTrace","admin:Prometheus"],"Resource":["arn:aws:s3:::*"]}"#,
    );
    for action in [
        "teifs:GetServerInfo",
        "teifs:ServerTrace",
        "teifs:GetMetrics",
        "admin:ServerInfo",
    ] {
        assert_eq!(
            decide(&diagnostics, action, "*"),
            Decision::Allow,
            "{action}"
        );
    }
    for action in ["teifs:ExportIAM", "teifs:TakeSnapshot", "s3:GetObject"] {
        assert_eq!(
            decide(&diagnostics, action, "*"),
            Decision::ImplicitDeny,
            "{action}"
        );
    }
    // consoleAdmin: admin and KMS statements need no Resource.
    let console = policy(
        r#"{"Effect":"Allow","Action":["admin:*"]},{"Effect":"Allow","Action":["kms:*"]},{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}"#,
    );
    for action in [
        "teifs:GetServerConfig",
        "teifs:ExportBucketMetadata",
        "teifs:AttachLDAPPolicy",
        "teifs:ListLDAPPolicies",
        "admin:ServerInfo",
        "kms:Status",
    ] {
        assert_eq!(decide(&console, action, "*"), Decision::Allow, "{action}");
    }
    assert_eq!(
        decide(&console, "admin:SetBucketQuota", "arn:aws:s3:::photos"),
        Decision::Allow
    );
    // Any one of the names MinIO takes.
    let users = policy(r#"{"Effect":"Allow","Action":"admin:ListUsers"}"#);
    assert_eq!(
        decide(&users, "teifs:ListLDAPPolicies", "*"),
        Decision::Allow
    );
    // A Deny by the MinIO name denies too.
    let denied = policy(
        r#"{"Effect":"Allow","Action":"teifs:*","Resource":"*"},{"Effect":"Deny","Action":"admin:ServerTrace"}"#,
    );
    assert_eq!(
        decide(&denied, "teifs:ServerTrace", "*"),
        Decision::ExplicitDeny
    );
    assert_eq!(decide(&denied, "teifs:GetServerInfo", "*"), Decision::Allow);
    let not_action = policy(
        r#"{"Effect":"Deny","NotAction":"admin:ServerInfo","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*"}"#,
    );
    assert_eq!(
        decide(&not_action, "teifs:GetServerInfo", "*"),
        Decision::Allow
    );
    assert_eq!(
        decide(&not_action, "teifs:ServerTrace", "*"),
        Decision::ExplicitDeny
    );
}

#[test]
fn kms_statements_that_name_keys_are_decided_on_the_key() {
    let key = teifs_policy::minio::kms_key_arn;
    let some = policy(
        r#"{"Effect":"Allow","Action":["kms:CreateKey","kms:KeyStatus"],"Resource":["arn:minio:kms:::app-*"]}"#,
    );
    assert_eq!(decide(&some, "kms:CreateKey", &key("app-1")), Decision::Allow);
    assert_eq!(
        decide(&some, "kms:KeyStatus", &key("other")),
        Decision::ImplicitDeny
    );
    // A call on no key (the first of MinIO's two checks) ignores them.
    assert_eq!(decide(&some, "kms:CreateKey", "*"), Decision::Allow);
    // Statements naming no key, or other resources, decide on the action alone.
    for statement in [
        r#"{"Effect":"Allow","Action":"kms:CreateKey"}"#,
        r#"{"Effect":"Allow","Action":"kms:*","Resource":"arn:aws:s3:::*"}"#,
        r#"{"Effect":"Allow","Action":"kms:*","Resource":"*"}"#,
    ] {
        assert_eq!(
            decide(&policy(statement), "kms:CreateKey", &key("any")),
            Decision::Allow,
            "{statement}"
        );
    }
    // A Deny of some keys denies those alone.
    let but = policy(
        r#"{"Effect":"Allow","Action":"kms:*"},{"Effect":"Deny","Action":"kms:KeyStatus","Resource":"arn:minio:kms:::secret*"}"#,
    );
    assert_eq!(
        decide(&but, "kms:KeyStatus", &key("secret-1")),
        Decision::ExplicitDeny
    );
    assert_eq!(decide(&but, "kms:KeyStatus", &key("public")), Decision::Allow);
}

#[test]
fn resources_still_bound_what_isnt_minio_admin() {
    // A bucket's admin action matches its Resource.
    let quota = policy(
        r#"{"Effect":"Allow","Action":"admin:GetBucketQuota","Resource":"arn:aws:s3:::photos"}"#,
    );
    assert_eq!(
        decide(&quota, "admin:GetBucketQuota", "arn:aws:s3:::photos"),
        Decision::Allow
    );
    assert_eq!(
        decide(&quota, "admin:GetBucketQuota", "arn:aws:s3:::other"),
        Decision::ImplicitDeny
    );
    // Everything on one bucket isn't the server's admin: only admin:/kms: statements
    // ignore their Resource.
    let one_bucket =
        policy(r#"{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::photos/*"}"#);
    for action in ["teifs:GetServerInfo", "admin:ServerInfo"] {
        assert_eq!(
            decide(&one_bucket, action, "*"),
            Decision::ImplicitDeny,
            "{action}"
        );
    }
    let teifs = policy(
        r#"{"Effect":"Allow","Action":"teifs:GetServerInfo","Resource":"arn:aws:s3:::photos"}"#,
    );
    assert_eq!(
        decide(&teifs, "teifs:GetServerInfo", "*"),
        Decision::ImplicitDeny
    );
    // Only MinIO's admin and KMS statements may leave out the Resource, and only in an
    // identity policy.
    for statements in [
        r#"{"Effect":"Allow","Action":"s3:GetObject"}"#,
        r#"{"Effect":"Allow","Action":["admin:ServerInfo","s3:GetObject"]}"#,
        r#"{"Effect":"Allow","Action":"*"}"#,
        r#"{"Effect":"Allow","NotAction":"admin:ServerInfo"}"#,
    ] {
        let text = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        let err = Policy::parse(&text, Kind::Identity).unwrap_err();
        assert!(
            err.to_string().contains("needs a Resource"),
            "{statements}: {err}"
        );
    }
    let text = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"admin:ServerInfo"}]}"#;
    assert!(Policy::parse(text, Kind::Resource).is_err());
}
