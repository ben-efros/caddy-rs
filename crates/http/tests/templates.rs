//! Real-router tests for the caddy-rs `templates` handler subset (T-ROUTE-026).

#![cfg(feature = "templates")]

use caddy_rs_http::{Outcome, Request, Router, RouterBuilder};
use http::{header, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};

fn build_router(routes: &Value) -> Router {
    RouterBuilder::new()
        .build(routes.as_array().expect("routes array"))
        .expect("routes build")
}

fn make_request(path: &str) -> Request {
    Request::new(Method::GET, path.parse().unwrap())
}

async fn serve(router: &Router, request: Request) -> caddy_rs_http::Response {
    match router.handle_outcome(request).await.expect("serves") {
        Outcome::Respond(response) => response,
        Outcome::Continue(_) => panic!("router returned Continue"),
    }
}

fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in files {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }
    dir
}

#[tokio::test]
async fn renders_file_server_html_with_placeholders_and_control_flow() {
    let dir = fixture(&[(
        "index.html",
        "<h1>{{placeholder \"http.request.method\"}} {{.Req.URL.Path}}</h1>\
         {{if eq (ph \"http.request.method\") \"GET\"}}get{{else}}other{{end}}\
         {{range index .Req.Header \"x-tags\"}}[{{.}}]{{end}}",
    )]);
    let root = dir.path().to_string_lossy().to_string();
    let routes = json!([{
        "handle": [
            {"handler": "vars", "root": root},
            {"handler": "templates"},
            {"handler": "file_server", "hide": []}
        ]
    }]);
    let router = build_router(&routes);
    let mut request = make_request("/index.html");
    request
        .headers
        .insert("x-tags", HeaderValue::from_static("a"));
    request
        .headers
        .append("x-tags", HeaderValue::from_static("b"));
    let response = serve(&router, request).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_eq!(response.body, "<h1>GET /index.html</h1>get[a][b]");
    assert_eq!(response.headers[header::CONTENT_LENGTH], "33");
    assert!(!response.headers.contains_key(header::ETAG));
    assert!(!response.headers.contains_key(header::ACCEPT_RANGES));
}

#[tokio::test]
async fn custom_delimiters_and_include_are_confined_to_the_root() {
    let dir = fixture(&[
        ("page.html", "<<include \"partial.html\">>"),
        (
            "partial.html",
            "partial:<<placeholder \"http.request.method\">>",
        ),
        ("secret.txt", "TOP SECRET"),
    ]);
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), "OUTSIDE SECRET").unwrap();
    let root = dir.path().to_string_lossy().to_string();
    let routes = json!([{
        "handle": [
            {"handler": "vars", "root": root},
            {"handler": "templates", "delimiters": ["<<", ">>"]},
            {"handler": "file_server", "hide": []}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, make_request("/page.html")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "partial:GET");
}

#[tokio::test]
async fn include_and_read_file_cannot_escape_the_root() {
    let dir = fixture(&[
        ("page.html", "{{include \"../secret.txt\"}}"),
        ("read.html", "{{readFile \"/secret.txt\"}}"),
    ]);
    let parent = dir.path().parent().unwrap();
    std::fs::write(parent.join("secret.txt"), "PARENT SECRET").unwrap();
    let root = dir.path().to_string_lossy().to_string();
    let routes = json!([{
        "handle": [
            {"handler": "vars", "root": root},
            {"handler": "templates"},
            {"handler": "file_server", "hide": []}
        ]
    }]);
    let router = build_router(&routes);
    // `../secret.txt` is clamped to <root>/secret.txt, not the parent directory; the missing file
    // is a template error (500), and the parent's content is never exposed.
    let response = serve(&router, make_request("/page.html")).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!String::from_utf8_lossy(&response.body).contains("PARENT SECRET"));
    // A leading slash is root-relative (Caddy http.Dir), not host-absolute; again no leak.
    let response = serve(&router, make_request("/read.html")).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!String::from_utf8_lossy(&response.body).contains("PARENT SECRET"));
}

#[tokio::test]
async fn non_matching_mime_types_pass_through_and_errors_are_loud() {
    let routes = json!([{
        "handle": [
            {"handler": "templates"},
            {"handler": "headers", "response": {"set": {"Content-Type": ["image/png"]}}},
            {"handler": "static_response", "body": "{{placeholder \"http.request.method\"}}"}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, make_request("/")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "{{placeholder \"http.request.method\"}}");

    // A malformed template in a matching body produces a 500 (Caddy's handler has no template
    // source in config, so this cannot be a load-time parse; the report documents the difference).
    let routes = json!([{
        "handle": [
            {"handler": "templates", "mime_types": ["text/plain"]},
            {"handler": "static_response", "body": "{{if true}}missing end"}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, make_request("/")).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(response.body.is_empty());

    // httpError propagates its status and keeps the response body empty.
    let routes = json!([{
        "handle": [
            {"handler": "templates", "mime_types": ["text/plain"]},
            {"handler": "static_response", "body": "{{httpError 404}}"}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, make_request("/")).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn matches_the_caddy_oracle_template_fixture() {
    // The file content and expected output are copied from the real Caddy probe in
    // `.scratch/logs/w19-templates-map/templates-caddy-output.txt`.
    let dir = fixture(&[(
        "index.html",
        "Hello {{placeholder \"http.request.method\"}} {{.Req.URL.Path}}\n\
         {{if eq (ph \"http.request.method\") \"GET\"}}GET{{else}}OTHER{{end}}\n\
         {{range index .Req.Header \"X-Tag\"}}[{{.}}]{{end}}\n",
    )]);
    let root = dir.path().to_string_lossy().to_string();
    let routes = json!([{
        "handle": [
            {"handler": "vars", "root": root},
            {"handler": "templates"},
            {"handler": "file_server", "hide": []}
        ]
    }]);
    let router = build_router(&routes);
    let mut request = make_request("/index.html");
    request
        .headers
        .insert("x-tag", HeaderValue::from_static("a"));
    request
        .headers
        .append("x-tag", HeaderValue::from_static("b"));
    let response = serve(&router, request).await;
    assert_eq!(response.body, "Hello GET /index.html\nGET\n[a][b]\n");
}

#[tokio::test]
async fn head_requests_pass_through_without_template_execution() {
    let dir = fixture(&[("index.html", "{{placeholder \"http.request.method\"}}")]);
    let root = dir.path().to_string_lossy().to_string();
    let routes = json!([{
        "handle": [
            {"handler": "vars", "root": root},
            {"handler": "templates"},
            {"handler": "file_server", "hide": []}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(
        &router,
        Request::new(Method::HEAD, "/index.html".parse().unwrap()),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers[header::CONTENT_LENGTH], "37");
}

#[tokio::test]
async fn response_header_mutation_and_file_exists_work() {
    let routes = json!([{
        "handle": [
            {"handler": "templates", "mime_types": ["text/plain"]},
            {"handler": "static_response", "body": "{{if fileExists \".\"}}exists{{end}}{{.RespHeader.Set \"X-Template\" \"yes\"}}"}
        ]
    }]);
    let router = build_router(&routes);
    let response = serve(&router, make_request("/")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "exists");
    assert_eq!(response.headers["x-template"], "yes");
}
