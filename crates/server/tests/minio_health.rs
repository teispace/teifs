//! `MinIO`'s health report (`mc support diag`): `GET healthinfo` streams the report as
//! it's gathered, each part the query asks for added in turn.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, start, user};
use serde_json::Value;
use signing::{signed, signed_response};

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);
const EVERY_PART: &str = "minioinfo=true&minioconfig=true&syscpu=true&sysdrivehw=true\
    &sysosinfo=true&sysmem=true&sysnet=true&sysprocess=true&syserrors=true\
    &sysservices=true&sysconfig=true&replication=false";

/// The reports a call streamed, in order.
async fn reports(server: &Server, path: &str) -> Vec<Value> {
    let response = signed_response(server, ROOT, "GET", path, &[], &[]).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let text = response.text().await.unwrap();
    serde_json::Deserializer::from_str(&text)
        .into_iter::<Value>()
        .map(Result::unwrap)
        .collect()
}

#[tokio::test]
async fn mc_support_diag_gets_the_report_part_by_part() {
    let server = start().await;
    let path =
        format!("/minio/admin/v3/healthinfo?{EVERY_PART}&deadline=1h0m0s&anonymize=standard");
    let reports = reports(&server, &path).await;
    // The first says only the version, which madmin reads on its own.
    let first = &reports[0];
    assert_eq!(first["version"], "3");
    assert!(first["sys"].get("cpus").is_none(), "{first}");
    let deployment = first["minio"]["info"]["deploymentID"].as_str().unwrap();
    assert!(!deployment.is_empty());
    // Then once more for each part, the last with all of them.
    assert_eq!(reports.len(), 12, "{reports:?}");
    let last = reports.last().unwrap();
    let sys = &last["sys"];
    let node = server.endpoint.trim_start_matches("http://");
    assert_eq!(sys["cpus"][0]["addr"], node);
    assert!(sys["cpus"][0]["cpus"][0]["cores"].as_u64().unwrap() > 0);
    assert!(
        !sys["partitions"][0]["partitions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(sys["meminfo"][0]["total"].as_u64().unwrap() > 0);
    assert_eq!(sys["procinfo"][0]["pid"], std::process::id());
    assert!(
        !sys["osinfo"][0]["info"]["hostname"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    assert_eq!(sys["services"][0]["services"][0]["name"], "selinux");
    assert!(sys["config"][0]["config"]["time-info"]["current_time"].is_string());
    assert_eq!(sys["netinfo"][0]["addr"], node);
    assert_eq!(sys["errors"][0]["addr"], node);
    // The configuration, every sub-system.
    let config = &last["minio"]["config"]["config"];
    assert!(config["identity_ldap"]["_"].is_array(), "{config}");
    // And the server, as `mc admin info` has it, with how it's reached.
    let info = &last["minio"]["info"];
    assert_eq!(info["deploymentID"], deployment);
    assert_eq!(info["servers"][0]["endpoint"], node);
    assert!(info["servers"][0]["num_cpu"].as_u64().unwrap() > 0);
    assert_eq!(info["tls"]["tls_enabled"], false);
    assert!(info["is_docker"].is_boolean());

    // Only what's asked, and the older name.
    let reports = self::reports(&server, "/minio/admin/v3/obdinfo?sysmem=true").await;
    assert_eq!(reports.len(), 2);
    let sys = &reports[1]["sys"];
    assert!(
        sys.get("meminfo").is_some() && sys.get("cpus").is_none(),
        "{sys}"
    );
    assert!(reports[1]["minio"].get("config").is_none());
}

#[tokio::test]
async fn a_strict_report_names_the_server_server1() {
    let server = start().await;
    let path = format!("/minio/admin/v3/healthinfo?{EVERY_PART}&deadline=1h0m0s&anonymize=strict");
    let reports = reports(&server, &path).await;
    let last = reports.last().unwrap();
    let node = server.endpoint.trim_start_matches("http://");
    let text = last.to_string();
    assert!(!text.contains(node), "{text}");
    assert_eq!(last["sys"]["cpus"][0]["addr"], "server1");
    assert_eq!(last["sys"]["osinfo"][0]["info"]["hostname"], "server1");
    assert_eq!(last["minio"]["info"]["servers"][0]["endpoint"], "server1");
}

#[tokio::test]
async fn a_bad_deadline_and_callers_without_the_action_are_refused() {
    let server = start().await;
    let (status, text) = signed(
        &server,
        ROOT,
        "GET",
        "/minio/admin/v3/healthinfo?deadline=soon",
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 400, "{text}");
    let reader = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"admin:ServerInfo","Resource":"*"}]}"#;
    user(&server, "alice", Some(reader));
    let key = server.iam.create_access_key("alice").unwrap();
    let alice = (key.info.id.as_str(), key.secret.as_str());
    let path = "/minio/admin/v3/healthinfo?sysmem=true";
    assert_eq!(signed(&server, alice, "GET", path, &[], &[]).await.0, 403);
}
