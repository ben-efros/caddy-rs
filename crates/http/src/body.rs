//! Streaming request/response body abstraction.
//!
//! The HTTP engine historically used buffered [`Bytes`] bodies everywhere: [`Request::body`] is a
//! `Bytes` value and [`Response::body`] is a `Bytes` value. Buffering is correct for small
//! payloads but pathological for large downloads and unbounded for Server-Sent Events.
//!
//! This module adds an *additive* streaming abstraction so streaming can be wired in without
//! breaking the buffered API:
//!
//! * [`Body`] — the byte-vs-stream union (`Body::Bytes` or `Body::Stream`). It implements
//!   [`http_body::Body`] so hyper can consume it directly; `into_bytes()` collects it for the
//!   legacy buffered path. [`ResponseBody`] and [`RequestBody`] are aliases that document the two
//!   directions it serves.
//! * [`StreamingBody`] — a chunk stream with an error terminus. Construct it from bytes, from a
//!   chunk channel (tests, adapters), from raw frames (data + trailers), or from any hyper body
//!   ([`StreamingBody::from_hyper`], the proxy path).
//! * [`StreamingResponse`] — response status/headers plus a [`Body`]; convert to/from the buffered
//!   [`Response`] with [`StreamingResponse::from_buffered`] / [`StreamingResponse::into_buffered`].
//! * [`StreamingOutcome`](crate::types::StreamingOutcome) and
//!   [`Handler::handle_streaming`](crate::types::Handler::handle_streaming) — the handler/router
//!   path that can return a streaming response.
//!
//! ## Semantics
//!
//! * Chunk boundaries are preserved from source to consumer: a `StreamingBody` never merges or
//!   splits frames on its own. `Body::Bytes` is exactly one data frame.
//! * End of stream is signalled by `poll_frame` returning `None`. Trailers are delivered as a
//!   final `Frame::trailers` before `None`.
//! * An error terminates the body: consumers must not assume more frames after `Some(Err(_))`.
//!   The server integration contract is to abort the downstream connection if headers were
//!   already sent (HTTP/1.1 close, HTTP/2 `RST_STREAM`).
//! * Dropping a `StreamingBody` cancels the producer: dropping the inner body (for example a
//!   hyper upstream `Incoming`) aborts the underlying request/connection. This is how a client
//!   disconnect cancels an in-flight upstream response.
//! * `size_hint` is only exact for byte bodies; streamed bodies are chunked unless the source
//!   reports an exact size.
//!
//! ## Server integration contract (implemented by `caddy-rs-server`)
//!
//! The server crate calls [`Router::handle_streaming`](crate::Router::handle_streaming) and hands
//! the returned [`Body`] to hyper without buffering (T-PROXY-038). The contract it implements is:
//!
//! 1. call `Router::handle_streaming(request)` and build a `hyper::Response` whose body is the
//!    returned [`Body`] (hyper accepts any `http_body::Body<Data = Bytes>` whose error is
//!    `Into<Box<dyn Error + Send + Sync>>`; [`BodyError`] satisfies that);
//! 2. not buffer the body, and let hyper poll it directly (each frame is written/flushed as it
//!    arrives; HTTP/1.1 uses chunked transfer when `Content-Length` is absent, HTTP/2 uses DATA
//!    frames);
//! 3. preserve an upstream `Content-Length` header only when it matches
//!    [`Body::exact_size`]; otherwise remove it so hyper frames the body correctly;
//! 4. propagate a mid-stream [`BodyError`] out of the body (hyper aborts the connection; it is
//!    too late for a new status);
//! 5. drop the body future on client disconnect so the upstream request is cancelled.
//!
//! Request-body streaming is not wired yet: `Request.body` remains `Bytes`, and the server still
//! collects `hyper::body::Incoming` before dispatch. [`RequestBody`] is the type that path will
//! carry once the server and handler traits are extended; see the report for T-PROXY-004.

use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use crate::types::Response;

/// Error terminus of a streaming body.
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    /// The source of the body (usually an upstream response) failed mid-stream.
    #[error("upstream body error: {0}")]
    Upstream(#[source] Box<dyn StdError + Send + Sync>),

    /// The body was explicitly cancelled by its producer.
    #[error("body stream was cancelled")]
    Cancelled,

    /// The body had already been consumed.
    #[error("body has already been consumed")]
    Consumed,

    /// An I/O error occurred while producing or consuming the body.
    #[error("body I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl BodyError {
    /// Wrap any upstream error.
    pub fn upstream(error: impl StdError + Send + Sync + 'static) -> Self {
        Self::Upstream(Box::new(error))
    }
}

type BoxedBody = Pin<Box<dyn HttpBody<Data = Bytes, Error = BodyError> + Send + 'static>>;

/// Receiver-backed body used by [`StreamingBody::from_chunks`].
struct ChunkReceiver {
    receiver: mpsc::Receiver<Result<Bytes, BodyError>>,
}

impl HttpBody for ChunkReceiver {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Receiver-backed body used by [`StreamingBody::from_frames`].
struct FrameReceiver {
    receiver: mpsc::Receiver<Result<Frame<Bytes>, BodyError>>,
}

impl HttpBody for FrameReceiver {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.receiver.poll_recv(cx)
    }
}

enum Inner {
    Bytes(Option<Bytes>),
    Boxed(BoxedBody),
}

/// A streaming body: an ordered sequence of data frames, optional trailers, then end-of-stream.
///
/// `StreamingBody` implements [`http_body::Body`] with `Data = Bytes` and [`BodyError`] as the
/// error type, so it can be handed to hyper (server or client) without an adapter.
pub struct StreamingBody {
    inner: Inner,
}

impl fmt::Debug for StreamingBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("StreamingBody");
        match &self.inner {
            Inner::Bytes(bytes) => debug.field("bytes", &bytes.as_ref().map(Bytes::len)),
            Inner::Boxed(_) => debug.field("boxed", &true),
        };
        debug.finish()
    }
}

impl StreamingBody {
    /// An empty body (immediate end of stream).
    pub fn empty() -> Self {
        Self::from_bytes(Bytes::new())
    }

    /// A body consisting of exactly one data frame.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self {
            inner: Inner::Bytes(Some(bytes.into())),
        }
    }

    /// A body fed by a chunk channel. Dropping the receiver cancels pending sends, which is how
    /// a client disconnect propagates to a producer. Send an error value to terminate with
    /// [`BodyError`] after any already-delivered chunks.
    pub fn from_chunks(receiver: mpsc::Receiver<Result<Bytes, BodyError>>) -> Self {
        Self {
            inner: Inner::Boxed(Box::pin(ChunkReceiver { receiver })),
        }
    }

    /// A body fed by a frame channel, allowing trailers (`Frame::trailers`) in addition to data.
    pub fn from_frames(receiver: mpsc::Receiver<Result<Frame<Bytes>, BodyError>>) -> Self {
        Self {
            inner: Inner::Boxed(Box::pin(FrameReceiver { receiver })),
        }
    }

    /// Bridge any hyper-body-compatible source (for example an upstream
    /// `hyper::body::Incoming`) into a streaming body.
    ///
    /// Dropping the returned body drops `body`, cancelling the upstream transfer.
    pub fn from_hyper<B>(body: B) -> Self
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        let mapped = body.map_err(BodyError::upstream);
        Self {
            inner: Inner::Boxed(Box::pin(mapped)),
        }
    }

    /// Whether the body has ended.
    pub fn is_end_stream(&self) -> bool {
        HttpBody::is_end_stream(self)
    }

    /// Size hint of the body (`Bytes` bodies are exact; streams are usually unknown).
    pub fn size_hint(&self) -> SizeHint {
        HttpBody::size_hint(self)
    }

    /// Collect the whole body into bytes (buffered compatibility path).
    pub async fn into_bytes(self) -> Result<Bytes, BodyError> {
        let collected = self.collect().await?;
        Ok(collected.to_bytes())
    }
}

impl HttpBody for StreamingBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match &mut self.get_mut().inner {
            Inner::Bytes(slot) => match slot.take() {
                Some(bytes) if bytes.is_empty() => Poll::Ready(None),
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None => Poll::Ready(None),
            },
            Inner::Boxed(body) => body.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Inner::Bytes(slot) => slot.as_ref().is_none_or(Bytes::is_empty),
            Inner::Boxed(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Inner::Bytes(slot) => {
                let remaining = slot.as_ref().map_or(0, Bytes::len) as u64;
                SizeHint::with_exact(remaining)
            }
            Inner::Boxed(body) => body.size_hint(),
        }
    }
}

/// The byte-vs-stream body union used by streaming responses (and, in the follow-up server
/// integration, streaming requests).
///
/// `Body` implements [`http_body::Body`], so it can be handed to hyper directly. For the buffered
/// compatibility path use [`Body::into_bytes`].
#[derive(Debug)]
pub enum Body {
    /// A fully buffered body: exactly one data frame.
    Bytes(Bytes),
    /// A chunked body; chunk boundaries come from the producer.
    Stream(StreamingBody),
}

/// Response body type alias for clarity in signatures.
pub type ResponseBody = Body;
/// Request body type alias for clarity in signatures (request streaming is follow-up wiring).
pub type RequestBody = Body;

impl Body {
    /// An empty buffered body.
    pub fn empty() -> Self {
        Body::Bytes(Bytes::new())
    }

    /// A buffered body.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Body::Bytes(bytes.into())
    }

    /// A streaming body.
    pub fn from_stream(stream: StreamingBody) -> Self {
        Body::Stream(stream)
    }

    /// Whether this body streams (chunked) instead of being fully buffered.
    pub fn is_streaming(&self) -> bool {
        matches!(self, Body::Stream(_))
    }

    /// Exact body size when known (buffered bodies always; streams only when their source reports
    /// an exact size hint).
    pub fn exact_size(&self) -> Option<u64> {
        match self {
            Body::Bytes(bytes) => Some(bytes.len() as u64),
            Body::Stream(stream) => stream.size_hint().exact(),
        }
    }

    /// Collect the body into bytes (buffered compatibility path).
    pub async fn into_bytes(self) -> Result<Bytes, BodyError> {
        match self {
            Body::Bytes(bytes) => Ok(bytes),
            Body::Stream(stream) => stream.into_bytes().await,
        }
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Body::Bytes(bytes)
    }
}

impl From<StreamingBody> for Body {
    fn from(stream: StreamingBody) -> Self {
        Body::Stream(stream)
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match self.get_mut() {
            Body::Bytes(bytes) => {
                if bytes.is_empty() {
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(Frame::data(std::mem::take(bytes)))))
            }
            Body::Stream(stream) => Pin::new(stream).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Body::Bytes(bytes) => bytes.is_empty(),
            Body::Stream(stream) => stream.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Body::Bytes(bytes) => SizeHint::with_exact(bytes.len() as u64),
            Body::Stream(stream) => stream.size_hint(),
        }
    }
}

/// A response whose body may be streamed.
#[derive(Debug)]
pub struct StreamingResponse {
    /// Response status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body, buffered or streamed.
    pub body: Body,
}

impl StreamingResponse {
    /// Build a streaming response from its parts.
    pub fn new(status: StatusCode, headers: HeaderMap, body: Body) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// Build from a fully buffered response.
    pub fn from_buffered(response: Response) -> Self {
        Self {
            status: response.status,
            headers: response.headers,
            body: Body::Bytes(response.body),
        }
    }

    /// Collect the body and return the buffered response (legacy compatibility path).
    pub async fn into_buffered(self) -> Result<Response, BodyError> {
        let body = self.body.into_bytes().await?;
        Ok(Response {
            status: self.status,
            headers: self.headers,
            body,
        })
    }

    /// Whether the body is streamed rather than buffered.
    pub fn is_streaming(&self) -> bool {
        self.body.is_streaming()
    }
}

impl From<Response> for StreamingResponse {
    fn from(response: Response) -> Self {
        Self::from_buffered(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Read frames until a non-empty data frame arrives; h2 delivers empty DATA frames around
    /// end-of-stream, which the bridge must pass through rather than hide.
    async fn next_data(body: &mut StreamingBody) -> Option<Bytes> {
        loop {
            match tokio::time::timeout(Duration::from_secs(2), body.frame())
                .await
                .expect("frame timeout")
            {
                None => return None,
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => return Some(data),
                    Err(_) => continue,
                },
                Some(Err(error)) => panic!("unexpected body error: {error}"),
            }
        }
    }

    #[tokio::test]
    async fn bytes_body_is_one_frame_then_end() {
        let mut body = StreamingBody::from_bytes("hello");
        let frame = body.frame().await.expect("frame").expect("data");
        assert_eq!(
            frame.into_data().expect("data frame"),
            Bytes::from_static(b"hello")
        );
        assert!(body.frame().await.is_none());
        assert!(body.is_end_stream());
    }

    #[tokio::test]
    async fn empty_body_ends_immediately() {
        let mut body = StreamingBody::empty();
        assert!(body.is_end_stream());
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn chunk_boundaries_are_preserved() {
        let (sender, receiver) = mpsc::channel(4);
        let mut body = StreamingBody::from_chunks(receiver);
        sender.send(Ok(Bytes::from_static(b"ab"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"c"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"def"))).await.unwrap();
        drop(sender);

        let mut chunks = Vec::new();
        while let Some(frame) = body.frame().await {
            chunks.push(frame.expect("frame").into_data().expect("data"));
        }
        assert_eq!(
            chunks,
            [
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"c"),
                Bytes::from_static(b"def")
            ],
            "chunk boundaries must not be merged or split"
        );
    }

    #[tokio::test]
    async fn trailers_are_delivered_before_end_of_stream() {
        let (sender, receiver) = mpsc::channel(4);
        let mut body = StreamingBody::from_frames(receiver);
        sender
            .send(Ok(Frame::data(Bytes::from_static(b"body"))))
            .await
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        sender
            .send(Ok(Frame::trailers(trailers.clone())))
            .await
            .unwrap();
        drop(sender);

        let data = body.frame().await.expect("data").expect("frame");
        assert_eq!(
            data.into_data().expect("data frame"),
            Bytes::from_static(b"body")
        );
        let trailers_frame = body.frame().await.expect("trailers").expect("frame");
        assert_eq!(trailers_frame.into_trailers().expect("trailers"), trailers);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn error_terminates_the_stream_after_previous_chunks() {
        let (sender, receiver) = mpsc::channel(4);
        let mut body = StreamingBody::from_chunks(receiver);
        sender.send(Ok(Bytes::from_static(b"first"))).await.unwrap();
        sender
            .send(Err(BodyError::upstream(std::io::Error::other(
                "upstream died",
            ))))
            .await
            .unwrap();
        drop(sender);

        let first = body.frame().await.expect("first").expect("data");
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"first"));
        let error = body
            .frame()
            .await
            .expect("error frame")
            .expect_err("error must surface");
        assert!(error.to_string().contains("upstream died"), "got: {error}");
    }

    #[tokio::test]
    async fn dropping_the_body_cancels_the_producer() {
        let (sender, receiver) = mpsc::channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let producer_cancelled = Arc::clone(&cancelled);
        tokio::spawn(async move {
            if sender.send(Ok(Bytes::from_static(b"first"))).await.is_err() {
                producer_cancelled.store(true, Ordering::SeqCst);
                return;
            }
            // The channel is full (capacity 1); this send blocks until the consumer polls or
            // drops the body.
            if sender
                .send(Ok(Bytes::from_static(b"second")))
                .await
                .is_err()
            {
                producer_cancelled.store(true, Ordering::SeqCst);
            }
        });

        let mut body = StreamingBody::from_chunks(receiver);
        let first = body.frame().await.expect("first").expect("data");
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"first"));
        drop(body);

        tokio::time::timeout(Duration::from_secs(2), async {
            while !cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("producer must observe receiver cancellation");
    }

    #[tokio::test]
    async fn body_utilities_agree_with_frames() {
        let body = Body::from_bytes(Bytes::from_static(b"payload"));
        assert!(!body.is_streaming());
        assert_eq!(body.exact_size(), Some(7));
        assert_eq!(
            body.into_bytes().await.unwrap(),
            Bytes::from_static(b"payload")
        );

        let (sender, receiver) = mpsc::channel(2);
        sender.send(Ok(Bytes::from_static(b"one"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"two"))).await.unwrap();
        drop(sender);
        let body = Body::from_stream(StreamingBody::from_chunks(receiver));
        assert!(body.is_streaming());
        assert_eq!(body.exact_size(), None);
        assert_eq!(
            body.into_bytes().await.unwrap(),
            Bytes::from_static(b"onetwo")
        );
    }

    #[tokio::test]
    async fn streaming_response_converts_to_and_from_buffered() {
        let response = Response::text(StatusCode::ACCEPTED, "hello");
        let streaming = StreamingResponse::from_buffered(response.clone());
        assert!(!streaming.is_streaming());
        assert_eq!(streaming.status, StatusCode::ACCEPTED);
        let buffered = streaming.into_buffered().await.unwrap();
        assert_eq!(buffered, response);
    }

    /// HTTP/2 prior-knowledge (h2c) upstream whose body streams chunks without buffering.
    #[tokio::test]
    async fn bridges_h2c_streaming_bodies_frame_by_frame() {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioExecutor;
        use hyper_util::rt::TokioIo;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind h2c listener");
        let address = listener.local_addr().expect("local address");
        let (sender, receiver) = mpsc::channel::<Result<Bytes, BodyError>>(4);
        let receiver = Arc::new(std::sync::Mutex::new(Some(receiver)));
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let receiver = Arc::clone(&receiver);
            let service = service_fn(move |_request: hyper::Request<hyper::body::Incoming>| {
                let receiver = Arc::clone(&receiver);
                async move {
                    let receiver = receiver
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                        .expect("single request");
                    Ok::<_, Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(StreamingBody::from_chunks(receiver))
                            .expect("response"),
                    )
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect h2c");
        let (mut client, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .expect("h2c handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = hyper::Request::builder()
            .uri(format!("http://{address}/stream"))
            .body(StreamingBody::empty())
            .expect("request");
        let response = client.send_request(request).await.expect("h2c response");
        assert_eq!(response.version(), http::Version::HTTP_2);
        let mut body = StreamingBody::from_hyper(response.into_body());

        sender
            .send(Ok(Bytes::from_static(b"first")))
            .await
            .expect("send first");
        assert_eq!(
            next_data(&mut body).await,
            Some(Bytes::from_static(b"first"))
        );

        sender
            .send(Ok(Bytes::from_static(b"second")))
            .await
            .expect("send second");
        assert_eq!(
            next_data(&mut body).await,
            Some(Bytes::from_static(b"second"))
        );

        drop(sender);
        assert_eq!(next_data(&mut body).await, None);
    }
}
