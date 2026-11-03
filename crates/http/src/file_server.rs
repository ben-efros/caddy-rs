//! Static file serving (`file_server`).

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use http::{StatusCode, Uri};
use tokio::fs;

use crate::matchers::{glob_match, percent_decode};
use crate::types::{Error, Handler, Outcome, Request, Response, Result};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Serve files from a root directory.
pub struct FileServerHandler {
    root: String,
    hide: Vec<String>,
    index_names: Vec<String>,
    browse: bool,
    pass_thru: bool,
    status_code: Option<StatusCode>,
    canonical_uris: bool,
}

impl FileServerHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "file_server must be an object"))?;
        // Caddy's file_server defaults its root to `{http.vars.root}`; the adapter sets that
        // variable from the `root` directive. Placeholders are expanded per request in `handle`.
        let root = object
            .get("root")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("{http.vars.root}")
            .to_string();
        let hide = object
            .get("hide")
            .map(|hide| {
                hide.as_array()
                    .ok_or_else(|| invalid(path, "`hide` must be an array of strings"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| invalid(path, "`hide` entries must be strings"))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_else(|| vec!["./Caddyfile".to_string()]);
        let index_names = object
            .get("index_names")
            .map(|names| {
                names
                    .as_array()
                    .ok_or_else(|| invalid(path, "`index_names` must be an array"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| invalid(path, "`index_names` entries must be strings"))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_else(|| vec!["index.html".to_string(), "index.txt".to_string()]);
        let browse = object
            .get("browse")
            .map(|browse| browse.as_bool().unwrap_or(browse.is_object()))
            .unwrap_or(false);
        let pass_thru = object
            .get("pass_thru")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let status_code = object
            .get("status_code")
            .and_then(serde_json::Value::as_u64)
            .and_then(|code| u16::try_from(code).ok())
            .and_then(|code| StatusCode::from_u16(code).ok());
        let canonical_uris = object
            .get("canonical_uris")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        Ok(Self {
            root,
            hide,
            index_names,
            browse,
            pass_thru,
            status_code,
            canonical_uris,
        })
    }

    fn not_found(&self, request: Request) -> Result<Outcome> {
        if self.pass_thru {
            Ok(Outcome::Continue(request))
        } else {
            Ok(Outcome::Respond(Response::not_found()))
        }
    }

    fn hidden(&self, relative: &str) -> bool {
        let name = Path::new(relative)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(relative);
        self.hide.iter().any(|pattern| {
            let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
            glob_match(pattern, relative, false) || glob_match(pattern, name, false)
        })
    }

    async fn serve_file(&self, full_path: &Path) -> Result<Response> {
        let body = fs::read(full_path).await?;
        let mime = mime_type(full_path);
        let status = self.status_code.unwrap_or(StatusCode::OK);
        Ok(Response::bytes(status, mime, Bytes::from(body)))
    }
}

#[async_trait]
impl Handler for FileServerHandler {
    fn name(&self) -> &'static str {
        "file_server"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        let decoded_path = percent_decode(request.path());
        if decoded_path.contains("..") || decoded_path.contains('\0') {
            return Ok(Outcome::Respond(Response::text(
                StatusCode::FORBIDDEN,
                "403 Forbidden",
            )));
        }
        let relative = decoded_path.trim_start_matches('/');
        if self.hidden(relative) {
            return self.not_found(request);
        }
        // Expand `{http.vars.root}` and friends (Caddy's file_server root supports placeholders).
        let expanded_root = request.replace_all(&self.root);
        let root = if expanded_root.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(expanded_root)
        };
        let full_path = root.join(relative);

        let metadata = match fs::metadata(&full_path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return self.not_found(request)
            }
            Err(error) => return Err(Error::Io(error)),
        };

        if metadata.is_dir() {
            if self.canonical_uris && !request.uri.path().ends_with('/') {
                let location = format!("{}/", request.uri.path());
                let mut response = Response::ok();
                response.status = StatusCode::PERMANENT_REDIRECT;
                response
                    .headers
                    .insert(http::header::LOCATION, location.parse().unwrap());
                return Ok(Outcome::Respond(response));
            }
            for index in &self.index_names {
                let candidate = full_path.join(index);
                if fs::metadata(&candidate)
                    .await
                    .map(|metadata| metadata.is_file())
                    .unwrap_or(false)
                {
                    return Ok(Outcome::Respond(self.serve_file(&candidate).await?));
                }
            }
            if self.browse {
                let body = browse_html(&full_path, request.uri.clone(), relative).await?;
                return Ok(Outcome::Respond(Response::bytes(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    body,
                )));
            }
            return self.not_found(request);
        }

        if metadata.is_file() {
            return Ok(Outcome::Respond(self.serve_file(&full_path).await?));
        }
        self.not_found(request)
    }
}

async fn browse_html(root: &Path, uri: Uri, relative: &str) -> Result<Vec<u8>> {
    let mut entries = fs::read_dir(root).await?;
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry
            .file_type()
            .await
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false);
        names.push((name, is_dir));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body><h1>Index of ");
    html.push_str(&html_escape(uri.path()));
    html.push_str("</h1><ul>");
    if !relative.is_empty() {
        html.push_str("<li><a href=\"../\">../</a></li>");
    }
    for (name, is_dir) in names {
        let suffix = if is_dir { "/" } else { "" };
        html.push_str("<li><a href=\"");
        html.push_str(&percent_encode_path_segment(&name));
        html.push_str(suffix);
        html.push_str("\">");
        html.push_str(&html_escape(&name));
        html.push_str(suffix);
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>");
    Ok(html.into_bytes())
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn percent_encode_path_segment(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            other => output.push_str(&format!("%{other:02X}")),
        }
    }
    output
}

fn mime_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Request;
    use http::Method;

    async fn handler(root: &Path) -> FileServerHandler {
        FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": root}),
            "handler",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn serves_existing_file_with_mime_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hi").unwrap();
        let handler = handler(dir.path()).await;
        let request = Request::new(Method::GET, "/hello.txt".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected file response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"hi"));
        assert_eq!(
            response.headers["content-type"],
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn serves_directory_index() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/index.html"), b"<h1>docs</h1>").unwrap();
        let handler = handler(dir.path()).await;
        let request = Request::new(Method::GET, "/docs/".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected index response");
        };
        assert_eq!(response.body, Bytes::from_static(b"<h1>docs</h1>"));
    }

    #[tokio::test]
    async fn pass_thru_continues_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": dir.path(), "pass_thru": true}),
            "handler",
        )
        .unwrap();
        let request = Request::new(Method::GET, "/missing".parse().unwrap());
        assert!(matches!(
            handler.handle(request).await.unwrap(),
            Outcome::Continue(_)
        ));
    }

    #[tokio::test]
    async fn rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path()).await;
        let request = Request::new(Method::GET, "/../etc/passwd".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected rejection");
        };
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }
}
