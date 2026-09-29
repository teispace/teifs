//! Class 10: CORS headers come only from a bucket's CORS rules, and never echo an origin
//! with credentials allowed unless a rule names it.
//!
//! Also proved elsewhere: rules answer preflights and requests, `*` without credentials,
//! refusals for headers and methods no rule allows (`sdk.rs`, `cors_rules_answer_browsers`).

use crate::common::{SECRET_KEY, client, start};

/// CVE-2026-46685 (RustFS: any `Origin` was echoed with credentials allowed, so any site
/// could read a signed-in browser's answers): where no rule allows an origin, nothing
/// tells a browser it may read the answer: not the account's bucket list, a bucket
/// without CORS rules, the admin, IAM or STS APIs, nor a preflight.
#[tokio::test]
async fn no_origin_is_echoed_that_no_rule_names() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("plain").send().await.unwrap();
    let evil = "https://evil.example";
    let http = reqwest::Client::new();
    for (method, path) in [
        ("GET", "/"),
        ("GET", "/plain"),
        ("GET", "/plain/anything"),
        ("GET", "/.teifs/admin/v1/info"),
        ("POST", "/?Action=GetCallerIdentity&Version=2011-06-15"),
        ("OPTIONS", "/"),
        ("OPTIONS", "/plain/anything"),
        ("OPTIONS", "/.teifs/admin/v1/info"),
    ] {
        let response = http
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", server.endpoint),
            )
            .header("origin", evil)
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "authorization")
            .send()
            .await
            .unwrap();
        let headers = response.headers();
        for header in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-headers",
            "access-control-expose-headers",
        ] {
            assert!(
                !headers.contains_key(header),
                "{method} {path}: {header}: {:?}",
                headers.get(header)
            );
        }
        if method == "OPTIONS" {
            assert!(response.status().is_client_error(), "{method} {path}");
        }
    }
}
