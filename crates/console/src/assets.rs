//! The page's files, built into the binary from `crates/console/web/`: plain HTML, CSS
//! and JavaScript modules, with no build step.

use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode, header};
use s3s::HttpResponse;

/// One of the page's files.
#[derive(Debug, Clone, Copy)]
pub struct File {
    /// Its path under `web/`, as the page asks for it.
    pub path: &'static str,
    /// Its `Content-Type`.
    pub content_type: &'static str,
    /// Its bytes.
    pub bytes: &'static [u8],
}

macro_rules! files {
    ($($path:literal => $type:expr),* $(,)?) => {
        /// Every file the page is made of.
        pub const FILES: &[File] = &[$(File {
            path: $path,
            content_type: $type,
            bytes: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/", $path)),
        }),*];
    };
}

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const SVG: &str = "image/svg+xml";

files! {
    "index.html" => HTML,
    "style.css" => CSS,
    "favicon.svg" => SVG,
    "app.js" => JS,
    "lib/api.js" => JS,
    "lib/dom.js" => JS,
    "lib/format.js" => JS,
    "lib/s3.js" => JS,
    "lib/settings.js" => JS,
    "lib/upload.js" => JS,
    "lib/xml.js" => JS,
    "views/buckets.js" => JS,
    "views/objects.js" => JS,
    "views/settings.js" => JS,
    "views/signin.js" => JS,
}

/// Whether `path` (under `web/`) is one of [`FILES`].
#[must_use]
pub fn is_embedded(path: &str) -> bool {
    FILES.iter().any(|file| file.path == path)
}

/// Answers a request for the page or one of its files.
pub(crate) fn serve(method: &Method, path: &str) -> HttpResponse {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return crate::method_not_allowed();
    }
    let wanted = match path.trim_start_matches('/') {
        "" => "index.html",
        other => other,
    };
    let Some(file) = FILES.iter().find(|file| file.path == wanted) else {
        return crate::error(StatusCode::NOT_FOUND, "NotFound", "There's no such page.");
    };
    let body = if *method == Method::HEAD {
        s3s::Body::empty()
    } else {
        s3s::Body::from(Bytes::from_static(file.bytes))
    };
    let mut response = HttpResponse::new(body);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(file.content_type),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(file.bytes.len()));
    // A new server version's files are fetched again: they're small.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every file in `web/` (but the tests) is built in, with a type that fits it.
    #[test]
    fn every_file_of_the_page_is_built_in() {
        fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.file_name().unwrap() != "test" {
                        walk(&path, base, out);
                    }
                } else if path.file_name().unwrap() != ".DS_Store" {
                    let relative = path.strip_prefix(base).unwrap();
                    out.push(relative.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("web");
        let mut found = Vec::new();
        walk(&base, &base, &mut found);
        found.sort();
        let mut listed: Vec<String> = FILES.iter().map(|f| f.path.to_owned()).collect();
        listed.sort();
        assert_eq!(found, listed, "list each file of web/ in assets.rs");
        for file in FILES {
            let expected = match file.path.rsplit('.').next() {
                Some("html") => HTML,
                Some("js") => JS,
                Some("css") => CSS,
                Some("svg") => SVG,
                other => panic!("no type for {other:?}"),
            };
            assert_eq!(file.content_type, expected, "{}", file.path);
        }
    }

    #[test]
    fn the_page_and_its_files_are_served() {
        let page = serve(&Method::GET, "/");
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()["content-type"], HTML);
        assert_eq!(serve(&Method::GET, "/app.js").headers()["content-type"], JS);
        assert_eq!(
            serve(&Method::GET, "/nope.js").status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            serve(&Method::GET, "/../Cargo.toml").status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            serve(&Method::POST, "/").status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn the_page_has_no_inline_script_or_style() {
        let index = std::str::from_utf8(FILES[0].bytes).unwrap();
        assert!(
            !index.contains("<script>"),
            "scripts are files: the CSP allows only 'self'"
        );
        assert!(!index.contains("style="), "styles are in style.css");
        assert!(!index.contains("<style"), "styles are in style.css");
        for file in FILES.iter().filter(|f| {
            std::path::Path::new(f.path)
                .extension()
                .is_some_and(|e| e == "js")
        }) {
            let source = std::str::from_utf8(file.bytes).unwrap();
            for banned in [
                "innerHTML",
                "outerHTML",
                "insertAdjacentHTML",
                "eval(",
                "new Function",
                "document.write",
            ] {
                assert!(
                    !source.contains(banned),
                    "{} uses {banned}: build nodes with h()",
                    file.path
                );
            }
        }
    }
}
