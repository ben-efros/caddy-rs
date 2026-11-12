//! End-to-end `encode` handler tests through the router (T-ROUTE-022).
//!
//! Expected header/body behaviour was captured from real Caddy v2.11.7 with the Caddyfile
//! `:18140 { root * <dir>; encode gzip zstd; file_server }` (see the task report for evidence
//! paths); the adapted JSON check uses the real Caddy `caddy adapt` output for the encode handler.

#![cfg(feature = "compression")]

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use caddy_rs_http::{
    Body, Handler, Outcome, Request, ResponseOutcome, RouterBuilder, SharedHandler, StreamingBody,
    StreamingOutcome, StreamingResponse,
};
use http::{header, HeaderMap, Method, StatusCode};
use http_body_util::BodyExt;

fn request(accept_encoding: &str, path: &str) -> Request {
    let mut request = Request::new(Method::GET, path.parse().unwrap());
    if !accept_encoding.is_empty() {
        request
            .headers
            .insert(header::ACCEPT_ENCODING, accept_encoding.parse().unwrap());
    }
    request
}

async fn serve(router: &caddy_rs_http::Router, request: Request) -> caddy_rs_http::Response {
    match router.handle_upgradable(request).await.expect("serves") {
        ResponseOutcome::Response(response) => response.into_buffered().await.expect("body"),
        ResponseOutcome::Upgrade(_) => panic!("unexpected upgrade"),
    }
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("large.txt");
    std::fs::write(&file, "c".repeat(1024)).unwrap();
    let mtime = UNIX_EPOCH + Duration::from_secs(1_735_787_045);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let small = dir.path().join("small.txt");
    std::fs::write(&small, "d".repeat(100)).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&small)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    dir
}

fn encode_file_server_routes(
    root: &std::path::Path,
    encode: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!([{
        "handle": [
            encode,
            {"handler": "file_server", "root": root.to_string_lossy(), "hide": []}
        ]
    }])
}

fn encode_handler(extra: serde_json::Value) -> serde_json::Value {
    let mut handler = serde_json::json!({
        "handler": "encode",
        "encodings": {"gzip": {}, "zstd": {}},
        "prefer": ["gzip", "zstd"]
    });
    if let (Some(handler), Some(extra)) = (handler.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            handler.insert(key.clone(), value.clone());
        }
    }
    handler
}

fn build_router(routes: &serde_json::Value) -> caddy_rs_http::Router {
    RouterBuilder::new()
        .build(routes.as_array().unwrap())
        .expect("routes build")
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).expect("valid gzip");
    output
}

fn metadata_etag(path: &std::path::Path) -> String {
    // Caddy/file_server ETag: "<base36 mtime-unix-nanos>-<base36 size>".
    let metadata = std::fs::metadata(path).unwrap();
    let modified = metadata
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    let nanos = modified.as_secs() as i64 * 1_000_000_000 + i64::from(modified.subsec_nanos());
    fn base36(mut value: i64) -> String {
        const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut digits = Vec::new();
        while value > 0 {
            digits.push(DIGITS[(value % 36) as usize]);
            value /= 36;
        }
        digits.reverse();
        String::from_utf8(digits).unwrap()
    }
    format!("\"{}-{}\"", base36(nanos), base36(metadata.len() as i64))
}

#[tokio::test]
async fn compresses_file_server_responses_like_caddy() {
    let directory = fixture();
    let file = directory.path().join("large.txt");
    let router = build_router(&encode_file_server_routes(
        directory.path(),
        encode_handler(serde_json::json!({})),
    ));

    // No Accept-Encoding: uncompressed; file_server's own Vary/Accept-Ranges/ETag are preserved.
    let response = serve(&router, request("", "/large.txt")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert_eq!(response.headers[header::CONTENT_LENGTH], "1024");
    assert_eq!(response.headers[header::ACCEPT_RANGES], "bytes");
    assert_eq!(response.headers[header::ETAG], metadata_etag(&file));

    // gzip: Content-Encoding, no Content-Length/Accept-Ranges, strong ETag suffix, Vary.
    let response = serve(&router, request("gzip", "/large.txt")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
    assert!(!response.headers.contains_key(header::CONTENT_LENGTH));
    assert!(!response.headers.contains_key(header::ACCEPT_RANGES));
    assert_eq!(
        response.headers[header::ETAG],
        format!("{}-gzip\"", metadata_etag(&file).trim_end_matches('"'))
    );
    assert_eq!(response.headers[header::VARY], "Accept-Encoding");
    assert_eq!(gunzip(&response.body), "c".repeat(1024).into_bytes());

    // zstd when the client prefers it by q-value.
    let response = serve(&router, request("gzip;q=0.5, zstd;q=1", "/large.txt")).await;
    assert_eq!(response.headers[header::CONTENT_ENCODING], "zstd");
    assert_eq!(
        zstd::stream::decode_all(response.body.as_ref()).expect("valid zstd"),
        "c".repeat(1024).into_bytes()
    );

    // Below the default `minimum_length` (512): no compression.
    let response = serve(&router, request("gzip", "/small.txt")).await;
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert_eq!(response.headers[header::CONTENT_LENGTH], "100");
}

#[tokio::test]
async fn negotiation_matches_caddy_through_the_router() {
    let directory = fixture();
    let router = build_router(&encode_file_server_routes(
        directory.path(),
        encode_handler(serde_json::json!({})),
    ));
    for (accept, expected) in [
        ("gzip", Some("gzip")),
        ("zstd", Some("zstd")),
        ("zstd, gzip", Some("gzip")),
        ("gzip;q=0.5, zstd;q=1", Some("zstd")),
        ("gzip;q=0", None),
        ("*", None),
        ("identity;q=0", None),
        ("br, gzip", Some("gzip")),
    ] {
        let response = serve(&router, request(accept, "/large.txt")).await;
        assert_eq!(
            response
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            expected,
            "Accept-Encoding: {accept}"
        );
    }
}

#[tokio::test]
async fn conditional_304_is_not_encoded_but_keeps_vary() {
    let directory = fixture();
    let file = directory.path().join("large.txt");
    let base_etag = metadata_etag(&file);
    let router = build_router(&encode_file_server_routes(
        directory.path(),
        encode_handler(serde_json::json!({})),
    ));
    // The client sends back the encoded ETag; encode strips `-gzip` so file_server can honour it.
    let mut conditional = request("gzip", "/large.txt");
    conditional.headers.insert(
        header::IF_NONE_MATCH,
        format!("{}-gzip\"", base_etag.trim_end_matches('"'))
            .parse()
            .unwrap(),
    );
    let response = serve(&router, conditional).await;
    assert_eq!(response.status, StatusCode::NOT_MODIFIED);
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert_eq!(response.headers[header::ETAG], base_etag);
    assert_eq!(response.headers[header::VARY], "Accept-Encoding");
}

#[tokio::test]
async fn missing_content_type_is_sniffed_before_the_matcher() {
    // A handler that does not set Content-Type: Caddy sniffs the first write chunk, so a text body
    // is compressed by the default text/* matcher (and the sniffed Content-Type is observable).
    let routes = serde_json::json!([{
        "handle": [
            encode_handler(serde_json::json!({})),
            {"handler": "static_response", "headers": {"Content-Type": [""]}, "body": "text ".repeat(500)}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, request("gzip", "/")).await;
    assert_eq!(
        response.headers[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
    assert_eq!(gunzip(&response.body), "text ".repeat(500).into_bytes());

    // Binary bodies are sniffed as application/octet-stream, which the default matcher excludes.
    let mut binary = Vec::new();
    for byte in 0u16..2048 {
        binary.push((byte % 256) as u8);
    }
    let routes = serde_json::json!([{
        "handle": [
            encode_handler(serde_json::json!({})),
            {"handler": "test_binary"}
        ]
    }]);
    let factory: caddy_rs_http::CustomHandlerFactory = Arc::new(move |value, _path, _context| {
        if value.get("handler").and_then(|value| value.as_str()) == Some("test_binary") {
            let body = binary.clone();
            Ok(Some(Arc::new(BinaryHandler(body)) as SharedHandler))
        } else {
            Ok(None)
        }
    });
    let router = RouterBuilder::new()
        .with_custom_handler(factory)
        .build(routes.as_array().unwrap())
        .expect("routes");
    let response = serve(&router, request("gzip", "/")).await;
    assert_eq!(
        response.headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
}

struct BinaryHandler(Vec<u8>);

#[async_trait]
impl Handler for BinaryHandler {
    fn name(&self) -> &'static str {
        "test_binary"
    }

    async fn handle(&self, _request: Request) -> caddy_rs_http::Result<Outcome> {
        Ok(Outcome::Respond(caddy_rs_http::Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from(self.0.clone()),
        }))
    }
}

#[tokio::test]
async fn partial_content_is_never_re_encoded() {
    // Caddy's encode WriteHeader disables encoding for 206 responses (partial representations
    // must not be dynamically re-encoded); file_server's own Vary stays.
    let directory = fixture();
    let router = build_router(&encode_file_server_routes(
        directory.path(),
        encode_handler(serde_json::json!({})),
    ));
    let mut range = request("gzip", "/large.txt");
    range
        .headers
        .insert(header::RANGE, "bytes=0-599".parse().unwrap());
    let response = serve(&router, range).await;
    assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert_eq!(response.headers[header::CONTENT_RANGE], "bytes 0-599/1024");
    assert_eq!(response.headers[header::VARY], "Accept-Encoding");
    assert_eq!(response.body, "c".repeat(600).into_bytes());
}

#[tokio::test]
async fn already_encoded_and_204_responses_are_untouched() {
    // A earlier handler already set Content-Encoding: encode must not re-encode.
    let routes = serde_json::json!([{
        "handle": [
            {"handler": "headers", "response": {"set": {"Content-Encoding": ["br"]}}},
            encode_handler(serde_json::json!({"minimum_length": 1})),
            {"handler": "static_response", "body": "x".repeat(2048)}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, request("gzip", "/")).await;
    assert_eq!(response.headers[header::CONTENT_ENCODING], "br");
    assert!(!response.headers.contains_key(header::VARY));

    // 204 responses never enter the encoder.
    let routes = serde_json::json!([{
        "handle": [
            encode_handler(serde_json::json!({"minimum_length": 1})),
            {"handler": "static_response", "status_code": 204, "body": ""}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, request("gzip", "/")).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert!(!response.headers.contains_key(header::VARY));
}

#[tokio::test]
async fn handler_errors_disable_encoding() {
    // encode before an `error` handler: Caddy disables the encoding wrapper when the handler chain
    // errors, so the error-route response is uncompressed even though gzip was negotiated.
    let routes = serde_json::json!([{
        "handle": [
            encode_handler(serde_json::json!({"minimum_length": 1})),
            {"handler": "error", "status_code": 404, "error": "missing"}
        ]
    }]);
    let router = RouterBuilder::new()
        .with_error_routes(
            Some(&serde_json::json!({"routes": [{
                "handle": [{"handler": "static_response", "body": "x".repeat(2048)}]
            }]})),
            "errors",
        )
        .expect("error routes")
        .build(routes.as_array().unwrap())
        .expect("routes");
    let response = serve(&router, request("gzip", "/")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    assert_eq!(response.body.len(), 2048);
}

/// A handler that streams two chunks with a delay between them, to prove compression happens
/// incrementally (the first compressed frame must arrive before the producer finishes).
struct StreamingHandler;

#[async_trait]
impl Handler for StreamingHandler {
    fn name(&self) -> &'static str {
        "test_stream"
    }

    async fn handle(&self, _request: Request) -> caddy_rs_http::Result<Outcome> {
        unreachable!("streaming handler is invoked through handle_streaming")
    }

    async fn handle_streaming(&self, _request: Request) -> caddy_rs_http::Result<StreamingOutcome> {
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let first = Bytes::from("a".repeat(600));
            sender.send(Ok(first)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            let second = Bytes::from("b".repeat(600));
            sender.send(Ok(second)).await.unwrap();
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "text/plain; charset=utf-8".parse().unwrap(),
        );
        Ok(StreamingOutcome::Respond(StreamingResponse::new(
            StatusCode::OK,
            headers,
            Body::from_stream(StreamingBody::from_chunks(receiver)),
        )))
    }
}

#[tokio::test]
async fn streaming_responses_are_compressed_incrementally() {
    let routes = serde_json::json!([{
        "handle": [
            encode_handler(serde_json::json!({})),
            {"handler": "test_stream"}
        ]
    }]);
    let factory: caddy_rs_http::CustomHandlerFactory = Arc::new(|value, _path, _context| {
        if value.get("handler").and_then(|value| value.as_str()) == Some("test_stream") {
            Ok(Some(Arc::new(StreamingHandler) as SharedHandler))
        } else {
            Ok(None)
        }
    });
    let router = RouterBuilder::new()
        .with_custom_handler(factory)
        .build(routes.as_array().unwrap())
        .expect("routes");
    let started = Instant::now();
    let response = match router
        .handle_upgradable(request("gzip", "/"))
        .await
        .expect("serves")
    {
        ResponseOutcome::Response(response) => response,
        ResponseOutcome::Upgrade(_) => panic!("unexpected upgrade"),
    };
    assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
    assert!(!response.headers.contains_key(header::CONTENT_LENGTH));
    // The first compressed frame must be available before the producer's 300 ms delay finishes:
    // this is only possible when the body is compressed as a stream, not buffered whole.
    let mut body = response.body;
    let first = tokio::time::timeout(Duration::from_millis(200), body.frame())
        .await
        .expect("first frame arrives before the producer finishes")
        .expect("frame")
        .expect("data frame");
    assert!(first.is_data());
    assert!(started.elapsed() < Duration::from_millis(250));
    let mut collected = first.into_data().expect("data").to_vec();
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame");
        if let Ok(data) = frame.into_data() {
            collected.extend_from_slice(&data);
        }
    }
    assert_eq!(
        gunzip(&collected),
        format!("{}{}", "a".repeat(600), "b".repeat(600)).into_bytes()
    );
}

#[test]
fn caddyfile_adaptation_matches_real_caddy() {
    let adapted =
        caddy_rs_config::adapt(":18140 {\n\troot * /srv\n\tencode gzip zstd\n\tfile_server\n}\n")
            .expect("adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"]
        .as_array()
        .expect("routes");
    let handlers = routes[0]["handle"].as_array().expect("handlers");
    let encode = handlers
        .iter()
        .find(|handler| handler.get("handler").and_then(|value| value.as_str()) == Some("encode"))
        .expect("encode handler present");
    // Exact JSON emitted by real Caddy v2.11.7 for the same Caddyfile.
    assert_eq!(
        encode,
        &serde_json::json!({
            "encodings": {"gzip": {}, "zstd": {}},
            "handler": "encode",
            "prefer": ["gzip", "zstd"]
        })
    );
}
