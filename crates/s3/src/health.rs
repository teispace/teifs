//! Health checks, answered without a signature for load balancers, orchestrators and
//! container health checks. None of them tells anything about the drive but a status,
//! and none is answered on a virtual-hosted bucket's host, where the path is an object's
//! key.
//!
//! - `GET /.teifs/health`: `200 OK` while the server answers. It can't hide a bucket
//!   (bucket names never start with a dot).
//! - `MinIO`'s, so probes set up for `MinIO` work: `/minio/health/live` (answering),
//!   `/minio/health/ready` (the drive can serve), `/minio/health/cluster` (it can take
//!   writes) and `/minio/health/cluster/read` (it can serve reads), with `MinIO`'s
//!   headers, as a single-drive `MinIO` answers them. Only unsigned requests are health
//!   checks there: a signed one reaches a bucket named `minio` as any other request does.

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use s3s::HttpResponse;
use teifs_store::Store;

/// The health check's path.
pub const HEALTH_PATH: &str = "/.teifs/health";

/// A health check a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// `/.teifs/health`.
    Teifs,
    /// `MinIO`'s liveness: the server answers.
    Live,
    /// `MinIO`'s readiness: the drive can serve.
    Ready,
    /// `MinIO`'s write health (`cluster`).
    Write,
    /// `MinIO`'s read health (`cluster/read`).
    Read,
}

/// The health check a request (with no virtual-hosted bucket) asks for, if it's one.
pub(crate) fn probe(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Option<Probe> {
    if method != Method::GET && method != Method::HEAD {
        return None;
    }
    if path == HEALTH_PATH {
        return Some(Probe::Teifs);
    }
    let probe = match path.strip_prefix("/minio/health/")? {
        "live" => Probe::Live,
        "ready" => Probe::Ready,
        "cluster" => Probe::Write,
        "cluster/read" => Probe::Read,
        _ => return None,
    };
    (!signed(headers, query)).then_some(probe)
}

/// Whether a request carries a signature, in its headers or its query.
fn signed(headers: &HeaderMap, query: Option<&str>) -> bool {
    headers.contains_key(header::AUTHORIZATION)
        || form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .any(|(name, _)| name == "X-Amz-Signature" || name == "Signature")
}

/// The answer to a health check.
pub(crate) async fn answer(
    probe: Probe,
    method: &Method,
    query: Option<&str>,
    store: &Store,
) -> HttpResponse {
    if probe == Probe::Teifs {
        let body = if method == Method::HEAD { "" } else { "OK\n" };
        let mut response = respond(StatusCode::OK, body);
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return response;
    }
    if probe == Probe::Live {
        return respond(StatusCode::OK, "");
    }
    let health = store.health().await;
    let healthy = match probe {
        Probe::Write => health.writable,
        Probe::Ready | Probe::Read => health.readable,
        Probe::Teifs | Probe::Live => true,
    };
    // Taking the only node down for maintenance would take the drive with it.
    let maintenance = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .any(|(name, value)| name == "maintenance" && value == "true");
    let status = match probe {
        Probe::Write | Probe::Read if maintenance => StatusCode::PRECONDITION_FAILED,
        _ if healthy => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    let mut response = respond(status, "");
    let headers = response.headers_mut();
    match probe {
        Probe::Write => {
            headers.insert("minio-writequorum", HeaderValue::from_static("1"));
            headers.insert(
                "minio-storageclassdefaults",
                HeaderValue::from_static("true"),
            );
        }
        Probe::Read => {
            headers.insert("minio-readquorum", HeaderValue::from_static("1"));
            headers.insert(
                "minio-storageclassdefaults",
                HeaderValue::from_static("true"),
            );
        }
        Probe::Ready if !healthy => {
            headers.insert("minio-serverstatus", HeaderValue::from_static("offline"));
        }
        Probe::Ready | Probe::Teifs | Probe::Live => {}
    }
    response
}

/// An answer that's never cached.
fn respond(status: StatusCode, body: &str) -> HttpResponse {
    let mut response = HttpResponse::new(s3s::Body::from(body.to_owned()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_checks_are_told_from_objects() {
        let none = HeaderMap::new();
        let probe = |method: &Method, path| super::probe(method, path, &none, None);
        assert_eq!(probe(&Method::GET, HEALTH_PATH), Some(Probe::Teifs));
        assert_eq!(
            probe(&Method::HEAD, "/minio/health/live"),
            Some(Probe::Live)
        );
        assert_eq!(
            probe(&Method::GET, "/minio/health/ready"),
            Some(Probe::Ready)
        );
        assert_eq!(
            probe(&Method::GET, "/minio/health/cluster"),
            Some(Probe::Write)
        );
        assert_eq!(
            probe(&Method::GET, "/minio/health/cluster/read"),
            Some(Probe::Read)
        );
        for (method, path) in [
            (Method::PUT, HEALTH_PATH),
            (Method::POST, "/minio/health/live"),
            (Method::GET, "/minio/health/other"),
            (Method::GET, "/minio/health/live/"),
            (Method::GET, "/minio/health"),
            (Method::GET, "/bucket/minio/health/live"),
        ] {
            assert_eq!(probe(&method, path), None, "{method} {path}");
        }
        // Signed: a bucket named `minio`'s object.
        let mut signed = HeaderMap::new();
        signed.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=x"),
        );
        assert_eq!(
            super::probe(&Method::GET, "/minio/health/live", &signed, None),
            None
        );
        for query in [
            "X-Amz-Signature=abc&X-Amz-Date=1",
            "AWSAccessKeyId=a&Signature=b",
        ] {
            let found = super::probe(&Method::GET, "/minio/health/live", &none, Some(query));
            assert_eq!(found, None, "{query}");
        }
        // Ours never names a bucket, so it needs no such care.
        assert_eq!(
            super::probe(&Method::GET, HEALTH_PATH, &signed, None),
            Some(Probe::Teifs)
        );
    }
}
