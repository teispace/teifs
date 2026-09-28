//! The health check: `GET /.teifs/health` answers `200 OK` without a signature, for load
//! balancers, orchestrators and container health checks. It can't hide a bucket (bucket
//! names never start with a dot), tells nothing about the drive, and isn't answered on a
//! virtual-hosted bucket's host, where the path is an object's key.

use http::{HeaderValue, Method, StatusCode, header};
use s3s::HttpResponse;

/// The health check's path.
pub const HEALTH_PATH: &str = "/.teifs/health";

/// Whether a request with this method and path (and no virtual-hosted bucket) is the
/// health check.
pub(crate) fn is_health_check(method: &Method, path: &str) -> bool {
    path == HEALTH_PATH && (method == Method::GET || method == Method::HEAD)
}

/// `200 OK`, never cached.
pub(crate) fn response(method: &Method) -> HttpResponse {
    let body = if method == Method::HEAD { "" } else { "OK\n" };
    let mut response = HttpResponse::new(s3s::Body::from(body.to_owned()));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
