//! Static serving for the proxy-manager web UI.
//!
//! The UI is a small single-page application built from `pm/ui`. Its bundle is embedded into the
//! binary by `build.rs`, so `caddy-rs-pm serve` answers `/` with the real UI without any extra files
//! on disk and without a second listener. The management API keeps its own `/api/v1` prefix and its
//! own JSON error contract; this module is the router fallback, so it only ever sees paths the API
//! did not claim.
//!
//! Two rules keep the split honest:
//!
//! * Anything under `/api/` is never answered with HTML. A missing API route gets a JSON `404` from
//!   the API router's own fallback, not from here.
//! * Unknown *page* paths fall back to `index.html` so client-side routes survive a reload, but
//!   unknown *asset* paths (a path whose last segment contains a dot) return a real `404`. Silently
//!   serving HTML for a missing `.js` file turns a broken deploy into a syntax error in the browser.

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

/// Content-Security-Policy for the admin UI.
///
/// The bundle is same-origin and has no inline script, so `script-src 'self'` needs no exception.
/// `style-src` must allow inline styles because the build inlines the stylesheet into the document.
/// `frame-ancestors 'none'` keeps the console out of a hostile iframe.
const CSP: &str = "default-src 'self'; \
script-src 'self'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
font-src 'self'; \
connect-src 'self'; \
base-uri 'none'; \
form-action 'self'; \
frame-ancestors 'none'; \
object-src 'none'";

/// Router fallback: serve the embedded UI, or explain that it was not built.
pub async fn serve_ui(method: Method, uri: Uri) -> Response {
    if !EMBEDDED {
        return not_built();
    }

    let mut response = match method {
        Method::GET | Method::HEAD => serve_path(uri.path(), method == Method::HEAD),
        _ => {
            let mut response = (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, HeaderValue::from_static("GET, HEAD"))],
                "method not allowed\n",
            )
                .into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        }
    };

    apply_security_headers(response.headers_mut());
    if method == Method::HEAD {
        *response.body_mut() = Body::empty();
    }
    response
}

fn serve_path(path: &str, _head: bool) -> Response {
    let normalized = normalize(path);

    if let Some((_, bytes, content_type)) = lookup(&normalized) {
        return asset(bytes, content_type, cache_control(&normalized));
    }

    // Client-side route (e.g. `/hosts`, `/login`): hand back the shell so a refresh works.
    if !looks_like_asset(&normalized) {
        if let Some((_, bytes, content_type)) = lookup("/") {
            return asset(bytes, content_type, "no-cache");
        }
    }

    let mut response = (StatusCode::NOT_FOUND, "not found\n").into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn asset(bytes: &'static [u8], content_type: &'static str, cache: &'static str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", fnv1a(bytes))) {
        headers.insert(header::ETAG, value);
    }
    response
}

fn lookup(path: &str) -> Option<(&'static str, &'static [u8], &'static str)> {
    ASSETS
        .iter()
        .find(|(route, _, _)| *route == path)
        .map(|(route, bytes, content_type)| (*route, *bytes, *content_type))
}

/// `/` stays `/`; everything else loses trailing slashes so `/hosts/` matches `/hosts`.
fn normalize(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn looks_like_asset(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|segment| segment.contains('.'))
}

fn cache_control(path: &str) -> &'static str {
    // Vite emits content-hashed filenames under `/assets/`, so those are safe to cache forever.
    // The shell must always be revalidated or a deploy would pin the old bundle.
    if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn apply_security_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
}

fn not_built() -> Response {
    const BODY: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>caddy-rs PM</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1.5rem;line-height:1.6;color:#1f2328;background:#fff}code{background:#f0f1f3;padding:.15rem .35rem;border-radius:4px}pre{background:#f0f1f3;padding:1rem;border-radius:8px;overflow:auto}</style>
</head><body>
<h1>Management API is running</h1>
<p>This build of <code>caddy-rs-pm</code> has no web UI embedded. The REST API is fully available
under <a href="/api/v1/health"><code>/api/v1</code></a>.</p>
<p>To embed the UI, build it once and rebuild the daemon:</p>
<pre>cd pm/ui
npm install
npm run build
cd ../..
cargo build -p caddy-rs-pm-cli</pre>
</body></html>
"#;

    let mut response = Response::new(Body::from(BODY));
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// Tiny non-cryptographic hash, used only to derive a stable `ETag` for immutable bytes.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_keeps_the_root_and_strips_trailing_slashes() {
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize(""), "/");
        assert_eq!(normalize("/hosts"), "/hosts");
        assert_eq!(normalize("/hosts/"), "/hosts");
        assert_eq!(normalize("/a/b///"), "/a/b");
    }

    #[test]
    fn asset_paths_are_recognised_by_their_last_segment() {
        assert!(looks_like_asset("/assets/index-abc123.js"));
        assert!(looks_like_asset("/favicon.ico"));
        assert!(!looks_like_asset("/hosts"));
        assert!(!looks_like_asset("/certificates/1/edit"));
        assert!(!looks_like_asset("/"));
    }

    #[test]
    fn only_hashed_assets_are_cached_forever() {
        assert_eq!(
            cache_control("/assets/index-abc.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control("/"), "no-cache");
        assert_eq!(cache_control("/favicon.ico"), "no-cache");
    }

    #[test]
    fn the_not_built_page_explains_how_to_embed_the_ui() {
        let response = not_built();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/html; charset=utf-8"))
        );
    }

    #[test]
    fn etags_are_stable_for_the_same_bytes_and_differ_between_them() {
        assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
        assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
    }

    #[tokio::test]
    async fn a_get_for_an_unknown_page_falls_back_to_the_shell_only_when_one_is_embedded() {
        let response = serve_ui(Method::GET, "/some/deep/route".parse().expect("uri")).await;
        if EMBEDDED {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn a_missing_asset_never_falls_back_to_html() {
        let response = serve_ui(
            Method::GET,
            "/assets/definitely-missing.js".parse().expect("uri"),
        )
        .await;
        if EMBEDDED {
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE),
                Some(&HeaderValue::from_static("text/plain; charset=utf-8"))
            );
        }
    }
}
