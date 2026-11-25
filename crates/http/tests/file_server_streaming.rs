//! SEC-MEDIUM-HTTP B2: a large static file reaches the server layer as a streaming body, through
//! the same router entry point the server uses, including inside a `subroute`, instead of being
//! read into memory first.

use caddy_rs_http::{Body, Request, ResponseOutcome, RouterBuilder};
use http::{header, Method, StatusCode};

fn router(root: &std::path::Path, nested: bool) -> caddy_rs_http::Router {
    let file_server = serde_json::json!({
        "handler": "file_server", "root": root.to_string_lossy(), "hide": []
    });
    let routes = if nested {
        serde_json::json!([{
            "handle": [{
                "handler": "subroute",
                "routes": [{"handle": [file_server]}]
            }]
        }])
    } else {
        serde_json::json!([{ "handle": [file_server] }])
    };
    RouterBuilder::new()
        .build(routes.as_array().unwrap())
        .expect("routes build")
}

async fn get(
    router: &caddy_rs_http::Router,
    path: &str,
    range: Option<&str>,
) -> (StatusCode, bool, Vec<u8>) {
    let mut request = Request::new(Method::GET, path.parse().unwrap());
    if let Some(range) = range {
        request
            .headers
            .insert(header::RANGE, range.parse().unwrap());
    }
    let ResponseOutcome::Response(response) = router.handle_upgradable(request).await.unwrap()
    else {
        panic!("unexpected upgrade");
    };
    let streamed = matches!(response.body, Body::Stream(_));
    let status = response.status;
    let body = response.body.into_bytes().await.unwrap();
    (status, streamed, body.to_vec())
}

#[tokio::test]
async fn large_files_stream_through_the_router_and_subroutes() {
    let dir = tempfile::tempdir().unwrap();
    let content: Vec<u8> = (0..600_000usize).map(|index| (index % 253) as u8).collect();
    std::fs::write(dir.path().join("big.txt"), &content).unwrap();
    std::fs::write(dir.path().join("small.txt"), b"tiny").unwrap();

    for nested in [false, true] {
        let router = router(dir.path(), nested);

        let (status, streamed, body) = get(&router, "/big.txt", None).await;
        assert_eq!(status, StatusCode::OK, "nested={nested}");
        assert!(streamed, "full GET must stream (nested={nested})");
        assert_eq!(body, content);

        let (status, streamed, body) = get(&router, "/big.txt", Some("bytes=10-499999")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert!(streamed, "large range must stream (nested={nested})");
        assert_eq!(body, content[10..500_000]);

        let (status, streamed, body) = get(&router, "/big.txt", Some("bytes=-5")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert!(!streamed, "tiny range is read inline");
        assert_eq!(body, content[599_995..]);

        let (status, streamed, body) = get(&router, "/small.txt", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!streamed);
        assert_eq!(body, b"tiny");
    }
}
