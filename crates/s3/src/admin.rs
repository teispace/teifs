//! TeiFS's admin API: what AWS has no API for, as JSON under
//! [`ADMIN_PREFIX`](teifs_types::admin::ADMIN_PREFIX), signed as S3 requests are (so
//! `curl --aws-sigv4` and awscurl call it too). [`crate::routes`] decides who may call
//! it; the messages are in [`teifs_types::admin`].

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, HeaderValue, StatusCode, header};
use s3s::{Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result};
use teifs_iam::{Iam, IamError};
use teifs_store::{JobStatus, Store};
use teifs_types::admin::{AdminError, IamExport, JobInfo, ServerConfig, ServerInfo};

use crate::routes::{s3_refusal, signed_body};

/// The largest IAM import accepted: AWS's quotas filled with the largest documents
/// (1 500 policies of five 6 KiB versions) fit, with room for users and groups.
pub(crate) const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

/// An admin API error, as JSON.
pub(crate) fn error_response(err: &S3Error) -> S3Response<Body> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let status = err
        .status_code()
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AdminError {
        code: err.code().as_str().to_owned(),
        message: err.message().unwrap_or_default().to_owned(),
        request_id: request_id.clone(),
    };
    let mut response = json(&body);
    response.status = Some(status);
    if let Ok(id) = HeaderValue::from_str(&request_id) {
        response.headers.insert("x-amz-request-id", id);
    }
    response
}

/// An answer with `value` as its JSON body.
fn json(value: &impl serde::Serialize) -> S3Response<Body> {
    let bytes = serde_json::to_vec(value).expect("the admin API's messages serialize");
    let mut response = S3Response::new(Body::from(bytes));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// An error with its own code and status.
fn error(status: StatusCode, code: &str, message: impl Into<String>) -> S3Error {
    let mut err =
        S3Error::with_message(S3ErrorCode::Custom(code.to_owned().into()), message.into());
    err.set_status_code(status);
    err
}

/// An IAM error, with IAM's code and status.
fn iam_error(err: IamError) -> S3Error {
    let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status.is_server_error() {
        tracing::error!(error = %err, "an IAM import failed");
        return S3Error::internal_error(err);
    }
    error(status, err.code(), err.to_string())
}

/// A path the admin API doesn't serve.
pub(crate) fn not_found() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("NotFound".into()),
        "The admin API has nothing at this method and path.",
    );
    err.set_status_code(StatusCode::NOT_FOUND);
    err
}

/// Whether `headers` name a virtual-hosted-style host (`bucket.domain`) of one of
/// `domains`: then the path is a key in that bucket, not the admin API.
pub(crate) fn is_virtual_hosted(headers: &HeaderMap, domains: &[String]) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    // An IPv6 literal's colons aren't a port; no domain matches one anyway.
    let host = host.rsplit_once(':').map_or(host, |(name, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) && !name.ends_with(':') {
            name
        } else {
            host
        }
    });
    domains.iter().any(|domain| {
        host.len() > domain.len() + 1
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
    })
}

fn millis(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn job_info(status: &JobStatus) -> JobInfo {
    JobInfo {
        steps: status.steps,
        items: status.items,
        last_progress_ms: status.last_progress.map(millis),
        last_error: status.last_error.clone(),
    }
}

/// `GET info`.
pub(crate) fn info(store: &Store, iam: &Iam, started: SystemTime) -> S3Response<Body> {
    json(&ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        drive: store.format().drive.clone(),
        account: iam.account(),
        started_ms: millis(started),
        uptime_seconds: started.elapsed().unwrap_or(Duration::ZERO).as_secs(),
        jobs: store
            .job_status()
            .iter()
            .map(|(name, status)| ((*name).to_owned(), job_info(status)))
            .collect(),
    })
}

/// `GET config`.
pub(crate) fn config(config: Option<&ServerConfig>) -> S3Result<S3Response<Body>> {
    let config = config.ok_or_else(|| {
        let mut err = S3Error::with_message(
            S3ErrorCode::Custom("NotFound".into()),
            "This server doesn't report its configuration.",
        );
        err.set_status_code(StatusCode::NOT_FOUND);
        err
    })?;
    Ok(json(config))
}

/// `GET iam` and `GET iam/secrets`: never cached, since one of them holds secrets.
pub(crate) fn export(iam: &Iam, secrets: bool) -> S3Response<Body> {
    let mut response = json(&iam.export(secrets));
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Whether `PUT iam` adopts the export's account: `?account=adopt` or `keep` (the
/// default); anything else is refused rather than guessed.
fn adopt_account(query: Option<&str>) -> S3Result<bool> {
    let mut adopt = false;
    for (name, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        adopt = match (name.as_ref(), value.as_ref()) {
            ("account", "adopt") => true,
            ("account", "keep") => false,
            _ => {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "The only parameter is account=adopt or account=keep.",
                ));
            }
        };
    }
    Ok(adopt)
}

/// `PUT iam`. Bucket rules cached before stay right: principals are matched when each
/// request is decided, and whether a policy is public doesn't depend on the account.
pub(crate) async fn import(iam: &Arc<Iam>, mut req: S3Request<Body>) -> S3Result<S3Response<Body>> {
    let adopt = adopt_account(req.uri.query())?;
    let body = signed_body(&mut req, MAX_IMPORT_BYTES)
        .await
        .map_err(s3_refusal)?;
    let export: IamExport = serde_json::from_slice(&body).map_err(|e| {
        error(
            StatusCode::BAD_REQUEST,
            "MalformedJSON",
            format!("The body isn't an IAM export: {e}"),
        )
    })?;
    let iam = Arc::clone(iam);
    let report = tokio::task::spawn_blocking(move || iam.import(&export, adopt))
        .await
        .map_err(S3Error::internal_error)?
        .map_err(iam_error)?;
    Ok(json(&report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn virtual_hosted_requests_are_told_apart() {
        let domains = ["s3.example.com".to_owned(), "localhost".to_owned()];
        for yes in [
            "bucket.s3.example.com",
            "bucket.S3.Example.com:9000",
            "a.b.localhost:9000",
            "bucket.localhost",
        ] {
            assert!(is_virtual_hosted(&host(yes), &domains), "{yes}");
        }
        for no in [
            "s3.example.com",
            "s3.example.com:9000",
            "localhost:9000",
            "xs3.example.com",
            ".s3.example.com",
            "127.0.0.1:9000",
            "[::1]:9000",
            "example.com",
        ] {
            assert!(!is_virtual_hosted(&host(no), &domains), "{no}");
        }
        assert!(!is_virtual_hosted(&HeaderMap::new(), &domains));
        assert!(!is_virtual_hosted(&host("bucket.localhost"), &[]));
    }

    #[test]
    fn only_account_adopt_or_keep_is_a_parameter() {
        assert!(!adopt_account(None).unwrap());
        assert!(!adopt_account(Some("account=keep")).unwrap());
        assert!(adopt_account(Some("account=adopt")).unwrap());
        for bad in ["account=yes", "adopt", "account=adopt&x=1", "Account=adopt"] {
            assert!(adopt_account(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn errors_are_json_with_their_status() {
        let response = error_response(&not_found());
        assert_eq!(response.status, Some(StatusCode::NOT_FOUND));
        assert_eq!(
            response.headers[header::CONTENT_TYPE],
            HeaderValue::from_static("application/json")
        );
        assert!(response.headers.contains_key("x-amz-request-id"));
    }
}
