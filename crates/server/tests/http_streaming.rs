//! End-to-end streaming tests: real listeners, real hyper clients, real upstream servers.
//!
//! These tests exercise the server connection boundary, not handler internals:
//!
//! * a streamed response is written to the client as chunks arrive, before the upstream finishes
//!   (no buffering anywhere between the upstream `Incoming` body and the downstream connection);
//! * SSE-style streams arrive incrementally over HTTP/1.1 and h2c;
//! * known-length bodies keep a matching `Content-Length`, unknown-length bodies are chunked
//!   (HTTP/1.1) or DATA-framed (HTTP/2);
//! * a mid-stream upstream body error aborts the downstream connection after the headers, never a
//!   late 5xx;
//! * dropping the client connection cancels the upstream transfer;
//! * ordinary buffered responses keep exact `Content-Length` framing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_http::{BodyError, StreamingBody};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

/// A mock auth/app upstream: one HTTP/1.1 listener whose responses stream.
type UpstreamResponder =
    dyn Fn(hyper::Request<hyper::body::Incoming>) -> hyper::Response<StreamingBody> + Send + Sync;

/// Start a mock upstream on an ephemeral port; returns its `host:port` dial address.
async fn spawn_upstream(responder: Arc<UpstreamResponder>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            let responder = Arc::clone(&responder);
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let responder = Arc::clone(&responder);
                    async move { Ok::<_, Infallible>(responder(request)) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address.to_string()
}

/// A configuration that proxies every request to `upstream`.
fn proxy_config(upstream: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream}]
            }]}]
        }}}}
    }))
    .expect("streaming proxy config decodes")
}

/// Start a runtime serving `config`; returns the runtime (keep it alive) and the bound address.
async fn start_runtime(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

/// A raw HTTP/1.1 response reader that keeps already-read bytes, so assertions can observe chunks
/// as they arrive rather than waiting for the response to finish.
struct RawResponse {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl RawResponse {
    async fn open(address: SocketAddr, path: &str) -> Self {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to server");
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    fn contains(&self, needle: &[u8]) -> bool {
        self.buffer
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Read until `needle` appears (or the deadline expires). Returns whether it was found.
    async fn read_until(&mut self, needle: &[u8], duration: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            if self.contains(needle) {
                return true;
            }
            let mut chunk = [0_u8; 4096];
            match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return self.contains(needle),
                Ok(Ok(read)) => self.buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    /// One read attempt. `None` means no bytes arrived within `duration` (i.e. the stream is
    /// waiting), `Some(0)` means EOF, `Some(n)` bytes were read.
    async fn read_once(&mut self, duration: Duration) -> Option<usize> {
        let mut chunk = [0_u8; 4096];
        match tokio::time::timeout(duration, self.stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => Some(0),
            Ok(Ok(read)) => {
                self.buffer.extend_from_slice(&chunk[..read]);
                Some(read)
            }
            Err(_) => None,
        }
    }

    /// Read to EOF (or the overall deadline), returning every byte received.
    async fn read_to_end(mut self, duration: Duration) -> Vec<u8> {
        let _ = self.read_once(duration).await;
        let deadline = tokio::time::Instant::now() + duration;
        let mut chunk = [0_u8; 4096];
        loop {
            match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return self.buffer,
                Ok(Ok(read)) => self.buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    fn head(&self) -> String {
        let end = self
            .buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or(self.buffer.len());
        String::from_utf8_lossy(&self.buffer[..end]).to_ascii_lowercase()
    }
}

/// Read the next non-empty data frame from an HTTP/2 client body.
async fn h2_next_data(
    body: &mut hyper::body::Incoming,
    duration: Duration,
) -> Result<Option<Bytes>, String> {
    loop {
        match tokio::time::timeout(duration, body.frame()).await {
            Err(_) => return Err("timed out waiting for a body frame".to_string()),
            Ok(None) => return Ok(None),
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() {
                        return Ok(Some(data));
                    }
                }
            }
            Ok(Some(Err(error))) => return Err(error.to_string()),
        }
    }
}

/// Open an h2c connection to the cleartext server and return a request sender.
async fn h2c_client(address: SocketAddr) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let stream = TcpStream::connect(address).await.expect("connect h2c");
    let (send_request, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2c handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request
}

#[tokio::test]
async fn first_byte_arrives_before_upstream_finishes() {
    let finish = Arc::new(Notify::new());
    let finish_for_responder = Arc::clone(&finish);
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let finish = Arc::clone(&finish_for_responder);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"first-chunk")))
                .await
                .expect("first send");
            finish.notified().await;
            sender
                .send(Ok(Bytes::from_static(b"second-chunk")))
                .await
                .expect("second send");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_chunks(receiver))
            .expect("upstream response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut response = RawResponse::open(address, "/stream").await;
    assert!(
        response
            .read_until(b"first-chunk", Duration::from_secs(3))
            .await,
        "first chunk must arrive while the upstream is still open; got {:?}",
        String::from_utf8_lossy(&response.buffer)
    );
    assert!(response.head().contains("200"));
    // The upstream has not sent the last chunk, so nothing else may arrive yet. This is the
    // assertion that would fail if the server buffered the response body.
    assert_eq!(
        response.read_once(Duration::from_millis(300)).await,
        None,
        "server must not buffer until the upstream finishes"
    );

    finish.notify_one();
    assert!(
        response
            .read_until(b"second-chunk", Duration::from_secs(3))
            .await
    );
    let body = response.read_to_end(Duration::from_secs(3)).await;
    assert!(!contains(&body, b"500 Internal Server Error"));
    runtime.shutdown().await;
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn sse_streams_incrementally_over_http1() {
    let second = Arc::new(Notify::new());
    let second_for_responder = Arc::clone(&second);
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let second = Arc::clone(&second_for_responder);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"data: one\n\n")))
                .await
                .expect("send event one");
            second.notified().await;
            sender
                .send(Ok(Bytes::from_static(b"data: two\n\n")))
                .await
                .expect("send event two");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(StreamingBody::from_chunks(receiver))
            .expect("SSE response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut response = RawResponse::open(address, "/events").await;
    assert!(
        response
            .read_until(b"data: one", Duration::from_secs(3))
            .await
    );
    assert!(response.head().contains("text/event-stream"));
    assert_eq!(
        response.read_once(Duration::from_millis(300)).await,
        None,
        "event two must not be produced before the test lets the upstream proceed"
    );

    second.notify_one();
    assert!(
        response
            .read_until(b"data: two", Duration::from_secs(3))
            .await
    );
    let body = response.read_to_end(Duration::from_secs(3)).await;
    assert!(contains(&body, b"data: one") && contains(&body, b"data: two"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn sse_streams_incrementally_over_h2c() {
    let second = Arc::new(Notify::new());
    let second_for_responder = Arc::clone(&second);
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let second = Arc::clone(&second_for_responder);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"data: first\n\n")))
                .await
                .expect("send event one");
            second.notified().await;
            sender
                .send(Ok(Bytes::from_static(b"data: second\n\n")))
                .await
                .expect("send event two");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(StreamingBody::from_chunks(receiver))
            .expect("SSE response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut client = h2c_client(address).await;
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/events"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("h2 request");
    let response = client.send_request(request).await.expect("h2 response");
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();

    assert_eq!(
        h2_next_data(&mut body, Duration::from_secs(3))
            .await
            .expect("first event"),
        Some(Bytes::from_static(b"data: first\n\n"))
    );
    assert!(
        h2_next_data(&mut body, Duration::from_millis(300))
            .await
            .is_err(),
        "second event must not be produced before the test allows it"
    );

    second.notify_one();
    assert_eq!(
        h2_next_data(&mut body, Duration::from_secs(3))
            .await
            .expect("second event"),
        Some(Bytes::from_static(b"data: second\n\n"))
    );
    assert_eq!(
        h2_next_data(&mut body, Duration::from_secs(3))
            .await
            .expect("end of stream"),
        None
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn known_length_stream_keeps_content_length() {
    // `from_bytes` has an exact size hint, so hyper's upstream listener sends Content-Length; the
    // proxy forwards it and the downstream server keeps it because it matches the body size.
    let payload = Bytes::from_static(b"hello streaming world");
    let payload_for_responder = payload.clone();
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_bytes(payload_for_responder.clone()))
            .expect("known-length response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    // HTTP/1.1: exact Content-Length, no chunked framing.
    let mut response = RawResponse::open(address, "/known").await;
    assert!(
        response
            .read_until(b"hello streaming world", Duration::from_secs(3))
            .await,
        "known-length body must arrive"
    );
    let head = response.head();
    assert!(
        head.contains(&format!("content-length: {}", payload.len())),
        "expected exact content-length, got: {head}"
    );
    assert!(!head.contains("transfer-encoding: chunked"), "got: {head}");
    let body = response.read_to_end(Duration::from_secs(3)).await;
    assert!(contains(&body, &payload));
    runtime.shutdown().await;
}

#[tokio::test]
async fn known_length_header_is_preserved_over_http2() {
    let payload = Bytes::from_static(b"h2 known length");
    let payload_for_responder = payload.clone();
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_bytes(payload_for_responder.clone()))
            .expect("known-length response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut client = h2c_client(address).await;
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/known"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("h2 request");
    let response = client.send_request(request).await.expect("h2 response");
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(payload.len().to_string().as_str()),
        "matching Content-Length must be preserved over h2"
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(body, payload);
    runtime.shutdown().await;
}

#[tokio::test]
async fn unknown_length_stream_uses_chunked_framing() {
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"chunk-one")))
                .await
                .expect("chunk one");
            sender
                .send(Ok(Bytes::from_static(b"chunk-two")))
                .await
                .expect("chunk two");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_chunks(receiver))
            .expect("unknown-length response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut response = RawResponse::open(address, "/unknown").await;
    assert!(
        response
            .read_until(b"chunk-two", Duration::from_secs(3))
            .await
    );
    let head = response.head();
    assert!(
        head.contains("transfer-encoding: chunked"),
        "unknown-length h1 body must be chunked, got: {head}"
    );
    assert!(
        !head.contains("content-length"),
        "a stale/absent exact size must not leave Content-Length behind, got: {head}"
    );
    let body = response.read_to_end(Duration::from_secs(3)).await;
    assert!(contains(&body, b"chunk-one") && contains(&body, b"chunk-two"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn unknown_length_h2_stream_has_no_content_length() {
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"streamed-a")))
                .await
                .expect("first chunk");
            sender
                .send(Ok(Bytes::from_static(b"streamed-b")))
                .await
                .expect("second chunk");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_chunks(receiver))
            .expect("unknown-length response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut client = h2c_client(address).await;
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/unknown"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("h2 request");
    let response = client.send_request(request).await.expect("h2 response");
    assert!(response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .is_none());
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"streamed-astreamed-b"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn mid_stream_upstream_error_aborts_after_headers() {
    let explode = Arc::new(Notify::new());
    let explode_for_responder = Arc::clone(&explode);
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let explode = Arc::clone(&explode_for_responder);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"partial-body")))
                .await
                .expect("first chunk");
            // Only fail once the test has observed the first chunk, so this exercises a truly
            // mid-stream error rather than an error that precedes the first flush.
            explode.notified().await;
            sender
                .send(Err(BodyError::upstream(std::io::Error::other(
                    "upstream exploded",
                ))))
                .await
                .expect("error chunk");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_chunks(receiver))
            .expect("streaming response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut response = RawResponse::open(address, "/broken").await;
    assert!(
        response
            .read_until(b"partial-body", Duration::from_secs(3))
            .await,
        "chunks before the error must reach the client"
    );
    explode.notify_one();
    // The connection must be aborted mid-stream: no terminating chunk and definitely no late
    // 5xx response (the status line was already sent).
    let body = response.read_to_end(Duration::from_secs(5)).await;
    assert!(contains(&body, b"partial-body"));
    assert!(
        !contains(&body, b"500 Internal Server Error"),
        "a mid-stream body error must not be replaced by a late 5xx"
    );
    assert!(
        !body.ends_with(b"0\r\n\r\n"),
        "the aborted stream must not be terminated as a complete chunked body"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn mid_stream_upstream_error_resets_the_h2_stream() {
    let explode = Arc::new(Notify::new());
    let explode_for_responder = Arc::clone(&explode);
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let explode = Arc::clone(&explode_for_responder);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"partial-body")))
                .await
                .expect("first chunk");
            explode.notified().await;
            sender
                .send(Err(BodyError::upstream(std::io::Error::other(
                    "upstream exploded",
                ))))
                .await
                .expect("error chunk");
            drop(sender);
        });
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_chunks(receiver))
            .expect("streaming response")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut client = h2c_client(address).await;
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/broken"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("h2 request");
    let response = client.send_request(request).await.expect("h2 response");
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(
        h2_next_data(&mut body, Duration::from_secs(3))
            .await
            .expect("first chunk"),
        Some(Bytes::from_static(b"partial-body"))
    );

    explode.notify_one();
    assert!(
        h2_next_data(&mut body, Duration::from_secs(3))
            .await
            .is_err(),
        "a mid-stream body error must reset the h2 stream instead of ending it cleanly"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn client_disconnect_cancels_the_upstream_body() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_for_responder = Arc::clone(&cancelled);
    let responder: Arc<UpstreamResponder> = Arc::new(move |_request| {
        let cancelled = Arc::clone(&cancelled_for_responder);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(2);
        tokio::spawn(async move {
            if sender
                .send(Ok(Bytes::from_static(b"chunk-1")))
                .await
                .is_err()
            {
                cancelled.store(true, Ordering::SeqCst);
                return;
            }
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if sender
                    .send(Ok(Bytes::from_static(b"chunk-x")))
                    .await
                    .is_err()
                {
                    cancelled.store(true, Ordering::SeqCst);
                    return;
                }
            }
        });
        hyper::Response::builder()
            .status(200)
            .body(StreamingBody::from_chunks(receiver))
            .expect("infinite stream")
    });
    let upstream = spawn_upstream(responder).await;
    let (runtime, address) = start_runtime(proxy_config(&upstream)).await;

    let mut response = RawResponse::open(address, "/infinite").await;
    assert!(
        response
            .read_until(b"chunk-1", Duration::from_secs(3))
            .await
    );
    drop(response);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cancelled.load(Ordering::SeqCst) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        cancelled.load(Ordering::SeqCst),
        "dropping the client must cancel the upstream response body"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn buffered_responses_keep_exact_content_length() {
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "hello"}]}]
        }}}}
    }))
    .expect("buffered config decodes");
    let (runtime, address) = start_runtime(config).await;

    let mut response = RawResponse::open(address, "/").await;
    assert!(response.read_until(b"hello", Duration::from_secs(3)).await);
    let head = response.head();
    assert!(head.contains("content-length: 5"), "got: {head}");
    assert!(!head.contains("transfer-encoding: chunked"), "got: {head}");
    runtime.shutdown().await;
}
