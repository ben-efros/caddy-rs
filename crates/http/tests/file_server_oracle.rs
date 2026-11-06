//! Differential oracle test for `file_server` static-file semantics.
//!
//! Every expectation below was captured from real Caddy v2.11.7 (`net/http.ServeContent` through
//! `modules/caddyhttp/fileserver/staticfiles.go`) serving the same fixture files with fixed
//! modification times. Both implementations are compared on status, body (except HEAD and the
//! random multipart boundary) and the static-file response headers.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use caddy_rs_http::file_server::FileServerHandler;
use caddy_rs_http::{Handler, Outcome, Request};
use http::Method;

const MTIME: i64 = 1_735_787_045; // Thu, 02 Jan 2025 03:04:05 GMT
const ETAG_FILE: &str = "\"d6r95k3vlgjk-a\"";
const ETAG_GZIP: &str = "\"d6r95k3vlgjk-b\"";
const ETAG_BR: &str = "\"d6r95k3vlgjk-9\"";
const ETAG_INDEX: &str = "\"d6r95k3vlgjk-d\"";
const ETAG_EMPTY: &str = "\"d6r95k3vlgjk-0\"";
const LAST_MODIFIED: &str = "Thu, 02 Jan 2025 03:04:05 GMT";

fn write_fixture_file(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).expect("write fixture");
    let file = std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open fixture");
    file.set_modified(UNIX_EPOCH + Duration::from_secs(MTIME as u64))
        .expect("set mtime");
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_fixture_file(&dir.path().join("file.txt"), b"0123456789");
    write_fixture_file(&dir.path().join("empty.txt"), b"");
    write_fixture_file(&dir.path().join("plain.txt"), b"0123456789");
    write_fixture_file(&dir.path().join("side.txt"), b"0123456789");
    write_fixture_file(&dir.path().join("side.txt.gz"), b"GZIPBYTES01");
    write_fixture_file(&dir.path().join("side.txt.br"), b"BRBYTES01");
    write_fixture_file(&dir.path().join("alpha.dat"), b"ABCDEFGHIJ");
    write_fixture_file(&dir.path().join("alpha.dat.gz"), b"MNOPQRSTUV");
    std::fs::create_dir(dir.path().join("sub")).expect("subdir");
    write_fixture_file(&dir.path().join("sub/index.html"), b"index-content");
    dir
}

fn handler(root: &Path) -> FileServerHandler {
    FileServerHandler::from_json(
        &serde_json::json!({
            "handler": "file_server",
            "root": root,
            "precompressed": {"gzip": {}, "br": {}},
            "precompressed_order": ["gzip", "br"],
            "hide": []
        }),
        "handler",
    )
    .expect("handler")
}

fn request(method: Method, path: &str, headers: &[(&str, &str)]) -> Request {
    let mut request = Request::new(method, path.parse().expect("uri"));
    for (name, value) in headers {
        request.headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            value.parse().expect("header value"),
        );
    }
    request
}

const SELECTED_HEADERS: &[&str] = &[
    "accept-ranges",
    "allow",
    "content-encoding",
    "content-length",
    "content-range",
    "content-type",
    "etag",
    "last-modified",
    "location",
    "vary",
    "x-content-type-options",
];

fn selected_headers(
    response: &caddy_rs_http::Response,
) -> std::collections::BTreeMap<String, String> {
    let mut headers = std::collections::BTreeMap::new();
    for name in SELECTED_HEADERS {
        if let Some(value) = response.headers.get(*name) {
            headers.insert(
                (*name).to_string(),
                value.to_str().expect("header value").to_string(),
            );
        }
    }
    headers
}

struct Case {
    name: &'static str,
    method: Method,
    path: &'static str,
    request_headers: &'static [(&'static str, &'static str)],
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: &'static str,
}

fn cases() -> Vec<Case> {
    macro_rules! case {
        ($name:literal, $method:expr, $path:literal, $req:expr, $status:literal, [$(($hn:literal, $hv:expr)),* $(,)?], $body:literal) => {
            Case {
                name: $name,
                method: $method,
                path: $path,
                request_headers: $req,
                status: $status,
                headers: vec![$(($hn, ($hv).to_string())),*],
                body: $body,
            }
        };
    }
    vec![
        case!(
            "plain",
            Method::GET,
            "/file.txt",
            &[],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "head",
            Method::HEAD,
            "/file.txt",
            &[],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "range",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=2-5")],
            206,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "4"),
                ("content-range", "bytes 2-5/10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "2345"
        ),
        case!(
            "range-suffix",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=-3")],
            206,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "3"),
                ("content-range", "bytes 7-9/10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "789"
        ),
        case!(
            "range-open",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=7-")],
            206,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "3"),
                ("content-range", "bytes 7-9/10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "789"
        ),
        case!(
            "range-invalid",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=abc")],
            416,
            [
                ("content-length", "14"),
                ("content-type", "text/plain; charset=utf-8"),
                ("vary", "Accept-Encoding"),
                ("x-content-type-options", "nosniff")
            ],
            "invalid range\n"
        ),
        case!(
            "range-unsat",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=99-100")],
            416,
            [
                ("content-length", "33"),
                ("content-range", "bytes */10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("vary", "Accept-Encoding"),
                ("x-content-type-options", "nosniff")
            ],
            "invalid range: failed to overlap\n"
        ),
        case!(
            "range-empty",
            Method::GET,
            "/empty.txt",
            &[("Range", "bytes=0-0")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "0"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_EMPTY),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "inm",
            Method::GET,
            "/file.txt",
            &[("If-None-Match", "*")],
            304,
            [("etag", ETAG_FILE), ("vary", "Accept-Encoding")],
            ""
        ),
        case!(
            "ims",
            Method::GET,
            "/file.txt",
            &[("If-Modified-Since", LAST_MODIFIED)],
            304,
            [("etag", ETAG_FILE), ("vary", "Accept-Encoding")],
            ""
        ),
        case!(
            "ims-old",
            Method::GET,
            "/file.txt",
            &[("If-Modified-Since", "Wed, 01 Jan 2025 03:04:05 GMT")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "im",
            Method::GET,
            "/file.txt",
            &[("If-Match", "\"bogus\"")],
            412,
            [
                ("content-length", "0"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "ius",
            Method::GET,
            "/file.txt",
            &[("If-Unmodified-Since", "Wed, 01 Jan 2025 03:04:05 GMT")],
            412,
            [
                ("content-length", "0"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "post",
            Method::POST,
            "/file.txt",
            &[],
            405,
            [
                ("allow", "GET, HEAD"),
                ("content-length", "0"),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "precomp-gzip",
            Method::GET,
            "/side.txt",
            &[("Accept-Encoding", "gzip")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-encoding", "gzip"),
                ("content-length", "11"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_GZIP),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "GZIPBYTES01"
        ),
        case!(
            "precomp-order",
            Method::GET,
            "/side.txt",
            &[("Accept-Encoding", "gzip;q=0.5, br;q=0.9")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-encoding", "br"),
                ("content-length", "9"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_BR),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "BRBYTES01"
        ),
        case!(
            "precomp-none",
            Method::GET,
            "/plain.txt",
            &[("Accept-Encoding", "gzip")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "precomp-range",
            Method::GET,
            "/side.txt",
            &[("Accept-Encoding", "gzip"), ("Range", "bytes=1-3")],
            206,
            [
                ("accept-ranges", "bytes"),
                ("content-encoding", "gzip"),
                ("content-length", "3"),
                ("content-range", "bytes 1-3/11"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_GZIP),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "ZIP"
        ),
        case!(
            "range-sum",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=0-9,0-9")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "unknown-ext",
            Method::GET,
            "/alpha.dat",
            &[("Accept-Encoding", "gzip")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-encoding", "gzip"),
                ("content-length", "10"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "MNOPQRSTUV"
        ),
        case!(
            "q-zero",
            Method::GET,
            "/side.txt",
            &[("Accept-Encoding", "gzip;q=0, br;q=0")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "index",
            Method::GET,
            "/sub/index.html",
            &[],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "13"),
                ("content-type", "text/html; charset=utf-8"),
                ("etag", ETAG_INDEX),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "index-content"
        ),
        case!(
            "dir-redirect",
            Method::GET,
            "/sub",
            &[],
            308,
            [
                ("content-length", "41"),
                ("content-type", "text/html; charset=utf-8"),
                ("location", "/sub/")
            ],
            "<a href=\"/sub/\">Permanent Redirect</a>.\n\n"
        ),
        case!(
            "ifmatch-star",
            Method::GET,
            "/file.txt",
            &[("If-Match", "*")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "post-ifnone",
            Method::POST,
            "/file.txt",
            &[("If-None-Match", ETAG_FILE)],
            405,
            [
                ("allow", "GET, HEAD"),
                ("content-length", "0"),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "precomp-412",
            Method::GET,
            "/side.txt",
            &[("Accept-Encoding", "gzip"), ("If-Match", "\"bogus\"")],
            412,
            [
                ("content-encoding", "gzip"),
                ("content-length", "11"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_GZIP),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "precomp-304",
            Method::GET,
            "/side.txt",
            &[("Accept-Encoding", "gzip"), ("If-None-Match", "*")],
            304,
            [("etag", ETAG_GZIP), ("vary", "Accept-Encoding")],
            ""
        ),
        case!(
            "precomp-post",
            Method::POST,
            "/side.txt",
            &[("Accept-Encoding", "gzip")],
            405,
            [
                ("allow", "GET, HEAD"),
                ("content-encoding", "gzip"),
                ("content-length", "11"),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "precomp-head",
            Method::HEAD,
            "/side.txt",
            &[("Accept-Encoding", "gzip")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-encoding", "gzip"),
                ("content-length", "11"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_GZIP),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            ""
        ),
        case!(
            "ifrange-match",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=0-3"), ("If-Range", ETAG_FILE)],
            206,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "4"),
                ("content-range", "bytes 0-3/10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123"
        ),
        case!(
            "ifrange-mismatch",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=0-3"), ("If-Range", "\"bogus\"")],
            200,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123456789"
        ),
        case!(
            "ifrange-date",
            Method::GET,
            "/file.txt",
            &[("Range", "bytes=0-3"), ("If-Range", LAST_MODIFIED)],
            206,
            [
                ("accept-ranges", "bytes"),
                ("content-length", "4"),
                ("content-range", "bytes 0-3/10"),
                ("content-type", "text/plain; charset=utf-8"),
                ("etag", ETAG_FILE),
                ("last-modified", LAST_MODIFIED),
                ("vary", "Accept-Encoding")
            ],
            "0123"
        ),
        case!(
            "inm-etag",
            Method::GET,
            "/file.txt",
            &[("If-None-Match", ETAG_FILE)],
            304,
            [("etag", ETAG_FILE), ("vary", "Accept-Encoding")],
            ""
        ),
        case!(
            "inm-weak",
            Method::GET,
            "/file.txt",
            &[("If-None-Match", "W/\"d6r95k3vlgjk-a\"")],
            304,
            [("etag", ETAG_FILE), ("vary", "Accept-Encoding")],
            ""
        ),
        case!(
            "inm-list",
            Method::GET,
            "/file.txt",
            &[("If-None-Match", "\"x\", \"d6r95k3vlgjk-a\"")],
            304,
            [("etag", ETAG_FILE), ("vary", "Accept-Encoding")],
            ""
        ),
    ]
}

#[test]
fn matches_real_caddy_for_conditional_and_range_requests() {
    let directory = fixture();
    let handler = handler(directory.path());
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    for case in cases() {
        let response = runtime
            .block_on(async {
                handler
                    .handle(request(
                        case.method.clone(),
                        case.path,
                        case.request_headers,
                    ))
                    .await
            })
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        let Outcome::Respond(response) = response else {
            panic!("{}: expected a response", case.name);
        };
        assert_eq!(
            response.status.as_u16(),
            case.status,
            "{}: status",
            case.name
        );
        let expected: std::collections::BTreeMap<String, String> = case
            .headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect();
        assert_eq!(
            selected_headers(&response),
            expected,
            "{}: headers",
            case.name
        );
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            case.body,
            "{}: body",
            case.name
        );
    }
}

#[test]
fn matches_real_caddy_for_multipart_ranges() {
    let directory = fixture();
    let handler = handler(directory.path());
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    for (range, expected_length, expected_ranges) in [
        ("bytes=0-1,4-5", 346, vec!["bytes 0-1/10", "bytes 4-5/10"]),
        (
            "bytes=0-1,4-5,8-9",
            486,
            vec!["bytes 0-1/10", "bytes 4-5/10", "bytes 8-9/10"],
        ),
    ] {
        let response = runtime
            .block_on(async {
                handler
                    .handle(request(Method::GET, "/file.txt", &[("Range", range)]))
                    .await
            })
            .expect("serves");
        let Outcome::Respond(response) = response else {
            panic!("expected a response");
        };
        assert_eq!(response.status, 206);
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .expect("multipart content type");
        let boundary = content_type
            .strip_prefix("multipart/byteranges; boundary=")
            .expect("multipart boundary");
        assert_eq!(boundary.len(), 60, "Go's boundary is 60 hex digits");
        assert_eq!(
            response
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(expected_length.to_string().as_str()),
            "Go computes the exact multipart length"
        );
        let body = String::from_utf8_lossy(&response.body).to_string();
        for content_range in expected_ranges {
            assert!(
                body.contains(&format!(
                    "--{boundary}\r\nContent-Range: {content_range}\r\n"
                )),
                "missing part {content_range} in {body}"
            );
        }
        assert!(body.ends_with(&format!("--{boundary}--\r\n")));
    }
}
