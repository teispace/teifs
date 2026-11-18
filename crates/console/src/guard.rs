//! What keeps other sites and objects' content from acting as the console: the headers
//! every answer carries, and the checks that a call comes from the console's own page.

use http::{HeaderMap, HeaderValue, StatusCode, header};
use s3s::HttpResponse;

/// The header the console's page sends with every call to `/api/`. A form or a link on
/// another site can't send it, and a script there can't without a CORS preflight, which
/// the console never grants.
pub const CONSOLE_HEADER: &str = "x-teifs-console";

/// The page's Content Security Policy: its own scripts and styles only, nothing inline,
/// never framed.
pub const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data: blob:; connect-src 'self'; manifest-src 'self'; \
    form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/// What every `/api/` answer carries: whatever bytes an object holds, they're never a
/// document that runs on the console's origin.
pub const API_CSP: &str = "default-src 'none'; sandbox; frame-ancestors 'none'";

/// Adds the headers every answer carries; `api` for `/api/`'s, `secure` over HTTPS.
pub(crate) fn harden(mut response: HttpResponse, api: bool, secure: bool) -> HttpResponse {
    let headers = response.headers_mut();
    let csp = if api { API_CSP } else { APP_CSP };
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    if api {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if secure {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    response
}

fn value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The refusal of a call that isn't from the console's own page: without [`CONSOLE_HEADER`], or
/// from another site by `Sec-Fetch-Site` or `Origin`.
pub(crate) fn same_origin(headers: &HeaderMap) -> Option<HttpResponse> {
    if value(headers, CONSOLE_HEADER) != Some("1") {
        return Some(forbidden());
    }
    same_site(headers)
}

/// The refusal of a request another site started, by the `Sec-Fetch-Site` and `Origin`
/// browsers send.
pub(crate) fn same_site(headers: &HeaderMap) -> Option<HttpResponse> {
    if let Some(site) = value(headers, "sec-fetch-site")
        && site != "same-origin"
    {
        return Some(forbidden());
    }
    if let Some(origin) = value(headers, header::ORIGIN.as_str()) {
        let host = value(headers, header::HOST.as_str());
        let from = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"));
        match (from, host) {
            (Some(from), Some(host)) if from.eq_ignore_ascii_case(host) => {}
            _ => return Some(forbidden()),
        }
    }
    None
}

fn forbidden() -> HttpResponse {
    crate::error(
        StatusCode::FORBIDDEN,
        "NotFromConsole",
        "Only the console's own page may call this.",
    )
}

/// The value of the cookie `name`, if the request sent it.
pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn calls_need_the_console_header() {
        assert!(same_origin(&headers(&[])).is_some());
        assert!(same_origin(&headers(&[(CONSOLE_HEADER, "0")])).is_some());
        assert!(same_origin(&headers(&[(CONSOLE_HEADER, "1")])).is_none());
    }

    #[test]
    fn calls_from_other_sites_are_refused() {
        let ok = [
            (CONSOLE_HEADER, "1"),
            ("host", "console.example.com:9001"),
            ("origin", "https://console.example.com:9001"),
            ("sec-fetch-site", "same-origin"),
        ];
        assert!(same_origin(&headers(&ok)).is_none());
        for (name, value) in [
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-site", "same-site"),
            ("origin", "https://evil.example"),
            ("origin", "https://console.example.com:9002"),
            ("origin", "null"),
        ] {
            let mut sent = headers(&ok);
            sent.insert(name, HeaderValue::from_static(value));
            assert!(same_origin(&sent).is_some(), "{name}: {value}");
        }
        // An origin without a host to compare it with is refused too.
        let sent = headers(&[(CONSOLE_HEADER, "1"), ("origin", "http://a.example")]);
        assert!(same_origin(&sent).is_some());
    }

    #[test]
    fn cookies_are_found_by_exact_name() {
        let sent = headers(&[
            ("cookie", "other=1; teifs-console-x=no"),
            ("cookie", "teifs-console=tok; z=2"),
        ]);
        assert_eq!(cookie(&sent, "teifs-console"), Some("tok"));
        assert_eq!(cookie(&sent, "__Host-teifs-console"), None);
        assert_eq!(
            cookie(&headers(&[("cookie", "teifs-console=")]), "teifs-console"),
            None
        );
    }

    #[test]
    fn answers_carry_the_policies() {
        let page = harden(HttpResponse::new(s3s::Body::empty()), false, true);
        assert_eq!(page.headers()["content-security-policy"], APP_CSP);
        assert_eq!(page.headers()["x-frame-options"], "DENY");
        assert!(page.headers().contains_key("strict-transport-security"));
        let api = harden(HttpResponse::new(s3s::Body::empty()), true, false);
        assert_eq!(api.headers()["content-security-policy"], API_CSP);
        assert_eq!(api.headers()["cache-control"], "no-store");
        assert_eq!(api.headers()["x-content-type-options"], "nosniff");
        assert!(!api.headers().contains_key("strict-transport-security"));
    }
}
