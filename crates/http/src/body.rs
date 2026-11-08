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
//! * [`RequestBody`] — the request-side body: buffered bytes or a streaming source, with an
//!   optional byte limit and chunk-preserving [`RequestBody::next_frame`] consumption.
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
//! Request bodies: the server hands [`RequestBody`] to the router without collecting it unless the
//! router contains a body-buffering handler (`reverse_proxy` today; proxy request streaming is the
//! T-PROXY-004 follow-up, whose contract is documented in the task report). `Request.body` remains
//! the buffered compatibility accessor for handlers/tests that need full bodies.

use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use caddy_rs_admin::access_log::BodyBytes;

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

    /// The body exceeded its configured byte limit while being streamed.
    ///
    /// The server maps this to `413 Request Entity Too Large` when the error is observed before
    /// response headers are sent; handlers that consume the body on the streaming path must map it
    /// themselves (the limit is enforced lazily, like Caddy's request-body limits).
    #[error("request body exceeds the configured limit of {limit} bytes")]
    TooLarge {
        /// Configured limit in bytes.
        limit: u64,
    },
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

/// How an observed response body finished.
///
/// The server attaches a [`ResponseBodyObserver`] to the final response body so it can emit the
/// access entry (and finish the request clock) when the *body* is done, not when the headers are
/// ready. Hyper owns the body after the service returns, so the completion callback is the only
/// reliable body-end signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyCompletion {
    /// Total data bytes polled from the body (what was handed to the transport).
    pub bytes: u64,
    /// Exact body length the body advertised, when it did (buffered bodies and fixed-length
    /// streams). Used to distinguish "all advertised bytes were written" from an aborted write.
    pub expected: Option<u64>,
    /// Whether the transport polled at least one frame.
    pub polled: bool,
    /// Why the body stopped.
    pub status: BodyStatus,
}

/// Why an observed response body stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStatus {
    /// The body signalled end of stream.
    Ended,
    /// The body yielded an error (an upstream read failure or an aborted write through the body).
    Failed(String),
    /// The body was dropped before it signalled end of stream (for example the client went away,
    /// or the transport never polls a body it is not going to send, like `HEAD`/`204`).
    Dropped,
}

/// Receives the one-shot completion of an observed response body.
///
/// See [`Body::observe`]. The callback runs synchronously when the body ends, fails or is dropped;
/// implementations must be cheap and must never panic.
pub trait ResponseBodyObserver: Send + Sync {
    /// Called exactly once per observed body.
    fn complete(&self, completion: BodyCompletion);
}

/// Bookkeeping for one observed body; dropped together with the body.
struct BodyObservation {
    observer: Arc<dyn ResponseBodyObserver>,
    expected: Option<u64>,
    bytes: u64,
    polled: bool,
}

/// A streaming body: an ordered sequence of data frames, optional trailers, then end-of-stream.
///
/// `StreamingBody` implements [`http_body::Body`] with `Data = Bytes` and [`BodyError`] as the
/// error type, so it can be handed to hyper (server or client) without an adapter.
///
/// A body may additionally carry a [`BodyBytes`] counter (used to report Caddy's actual
/// `bytes_read` for streamed request bodies) and a [`ResponseBodyObserver`] (used by the server to
/// emit the access entry at body end). Both are optional and transparent to the transport.
pub struct StreamingBody {
    inner: Inner,
    /// Shared actual-byte counter, when the caller wants streamed bytes reported.
    counter: Option<BodyBytes>,
    /// One-shot end-of-body callback, when the body is observed.
    observation: Option<BodyObservation>,
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
            counter: None,
            observation: None,
        }
    }

    /// A body fed by a chunk channel. Dropping the receiver cancels pending sends, which is how
    /// a client disconnect propagates to a producer. Send an error value to terminate with
    /// [`BodyError`] after any already-delivered chunks.
    pub fn from_chunks(receiver: mpsc::Receiver<Result<Bytes, BodyError>>) -> Self {
        Self {
            inner: Inner::Boxed(Box::pin(ChunkReceiver { receiver })),
            counter: None,
            observation: None,
        }
    }

    /// A body fed by a frame channel, allowing trailers (`Frame::trailers`) in addition to data.
    pub fn from_frames(receiver: mpsc::Receiver<Result<Frame<Bytes>, BodyError>>) -> Self {
        Self {
            inner: Inner::Boxed(Box::pin(FrameReceiver { receiver })),
            counter: None,
            observation: None,
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
            counter: None,
            observation: None,
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

    /// Count every data byte polled from this body into `counter`.
    ///
    /// The server attaches the per-request [`BodyBytes`] handle to streamed request bodies so the
    /// access entry reports Caddy's actual `bytes_read` rather than the declared
    /// `Content-Length`.
    pub fn with_counter(mut self, counter: BodyBytes) -> Self {
        self.counter = Some(counter);
        self
    }

    /// Notify `observer` exactly once when this body ends, fails, or is dropped.
    ///
    /// The exact length advertised by the body (if any) is captured now, before any frame is
    /// polled, so a completion can distinguish all-advertised-bytes-written from an aborted write.
    pub fn with_observer(mut self, observer: Arc<dyn ResponseBodyObserver>) -> Self {
        let expected = self.size_hint().exact();
        self.observation = Some(BodyObservation {
            observer,
            expected,
            bytes: 0,
            polled: false,
        });
        self
    }

    /// Complete the observation, if there is one, with `status`.
    fn finish_observation(&mut self, status: BodyStatus) {
        if let Some(observation) = self.observation.take() {
            observation.observer.complete(BodyCompletion {
                bytes: observation.bytes,
                expected: observation.expected,
                polled: observation.polled,
                status,
            });
        }
    }

    /// Account for one polled frame and complete the observation when the frame ends the body.
    fn record_poll(&mut self, poll: &Poll<Option<Result<Frame<Bytes>, BodyError>>>) {
        match poll {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(observation) = self.observation.as_mut() {
                    observation.polled = true;
                }
                if let Some(data) = frame.data_ref() {
                    let bytes = data.len() as u64;
                    if let Some(counter) = &self.counter {
                        counter.add(bytes);
                    }
                    if let Some(observation) = self.observation.as_mut() {
                        observation.bytes = observation.bytes.saturating_add(bytes);
                    }
                }
            }
            Poll::Ready(Some(Err(error))) => {
                if let Some(observation) = self.observation.as_mut() {
                    observation.polled = true;
                }
                self.finish_observation(BodyStatus::Failed(error.to_string()));
            }
            Poll::Ready(None) => {
                if let Some(observation) = self.observation.as_mut() {
                    observation.polled = true;
                }
                self.finish_observation(BodyStatus::Ended);
            }
            Poll::Pending => {}
        }
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
        let this = self.get_mut();
        let poll = match &mut this.inner {
            Inner::Bytes(slot) => match slot.take() {
                Some(bytes) if bytes.is_empty() => Poll::Ready(None),
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None => Poll::Ready(None),
            },
            Inner::Boxed(body) => body.as_mut().poll_frame(cx),
        };
        this.record_poll(&poll);
        poll
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

impl Drop for StreamingBody {
    fn drop(&mut self) {
        // A body dropped before its end-of-stream frame was polled (client disconnect, transport
        // skipping a body it must not send, or a mid-stream error) still completes the
        // observation. Exactly-once is guaranteed by taking the observation.
        self.finish_observation(BodyStatus::Dropped);
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

    /// Notify `observer` exactly once when this body ends, fails, or is dropped.
    ///
    /// The server attaches the per-request access-log observation here so the entry is rendered
    /// after the response body has been handed to the transport (Caddy's time-to-last-byte
    /// `duration` and actual `size`), not when the handler returns headers. Buffered bodies become
    /// a one-frame streaming body; their exact size is preserved for framing.
    pub fn observe(self, observer: Arc<dyn ResponseBodyObserver>) -> Self {
        match self {
            Body::Bytes(bytes) => {
                Body::Stream(StreamingBody::from_bytes(bytes).with_observer(observer))
            }
            Body::Stream(stream) => Body::Stream(stream.with_observer(observer)),
        }
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

/// The request body handed to handlers and the router.
///
/// The server passes a streaming body through without collecting it (unless the router contains a
/// handler that requires a buffered body — see
/// [`Router::requires_buffered_request_body`](crate::Router::requires_buffered_request_body)).
/// Handlers have two compatibility accessors:
///
/// * [`Request::body`](crate::Request::body) remains the buffered bytes for the compatibility path
///   (empty when the body is streamed or already taken), and
/// * [`RequestBody::collect`](RequestBody::collect) / [`RequestBody::next_frame`] consume or read
///   the streaming source.
///
/// `RequestBody` implements [`http_body::Body`] with `Data = Bytes` and [`BodyError`] so a handler
/// can hand it directly to a hyper client (the reverse-proxy request-streaming follow-up,
/// T-PROXY-004).
#[derive(Debug)]
pub struct RequestBody {
    inner: RequestBodyInner,
    /// Optional byte limit, enforced lazily as frames are consumed.
    limit: Option<u64>,
    /// Bytes delivered so far (for the limit).
    read: u64,
}

#[derive(Debug)]
enum RequestBodyInner {
    Buffered(Option<Bytes>),
    Streaming(Option<StreamingBody>),
}

impl RequestBody {
    /// An empty request body.
    pub fn empty() -> Self {
        Self::buffered(Bytes::new())
    }

    /// A fully buffered request body.
    pub fn buffered(bytes: impl Into<Bytes>) -> Self {
        Self {
            inner: RequestBodyInner::Buffered(Some(bytes.into())),
            limit: None,
            read: 0,
        }
    }

    /// A streaming request body.
    pub fn streaming(stream: StreamingBody) -> Self {
        Self {
            inner: RequestBodyInner::Streaming(Some(stream)),
            limit: None,
            read: 0,
        }
    }

    /// Wrap the body in a byte limit. Buffered bodies over the limit fail immediately; streaming
    /// bodies fail with [`BodyError::TooLarge`] as soon as a frame crosses the limit.
    pub fn with_limit(mut self, limit: Option<u64>) -> Self {
        self.limit = limit;
        self
    }

    /// Whether the body is streamed (not fully buffered).
    pub fn is_streaming(&self) -> bool {
        matches!(self.inner, RequestBodyInner::Streaming(_))
    }

    /// Exact size when known: buffered bodies always; streams only when their source reports one.
    pub fn exact_size(&self) -> Option<u64> {
        match &self.inner {
            RequestBodyInner::Buffered(Some(bytes)) => Some(bytes.len() as u64),
            RequestBodyInner::Buffered(None) => Some(0),
            RequestBodyInner::Streaming(Some(stream)) => stream.size_hint().exact(),
            RequestBodyInner::Streaming(None) => None,
        }
    }

    /// Borrow the buffered bytes when the body was not streamed (compatibility accessor).
    pub fn as_buffered(&self) -> Option<&Bytes> {
        match &self.inner {
            RequestBodyInner::Buffered(Some(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// Collect the body into bytes with an optional byte limit.
    pub async fn collect(self, limit: Option<u64>) -> Result<Bytes, BodyError> {
        match self.inner {
            RequestBodyInner::Buffered(Some(bytes)) => {
                if let Some(limit) = limit.or(self.limit) {
                    if bytes.len() as u64 > limit {
                        return Err(BodyError::TooLarge { limit });
                    }
                }
                Ok(bytes)
            }
            RequestBodyInner::Buffered(None) => Ok(Bytes::new()),
            RequestBodyInner::Streaming(Some(mut stream)) => {
                let effective_limit = limit.or(self.limit);
                let mut collected = bytes::BytesMut::new();
                let mut read = self.read;
                loop {
                    let frame =
                        std::future::poll_fn(|cx| Pin::new(&mut stream).poll_frame(cx)).await;
                    let Some(frame) = frame else { break };
                    let frame = frame?;
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    read = read.checked_add(data.len() as u64).unwrap_or(u64::MAX);
                    if let Some(limit) = effective_limit {
                        if read > limit {
                            return Err(BodyError::TooLarge { limit });
                        }
                    }
                    collected.extend_from_slice(&data);
                }
                Ok(collected.freeze())
            }
            RequestBodyInner::Streaming(None) => Err(BodyError::Consumed),
        }
    }

    /// Take the streaming body, if this request body is streamed.
    pub fn into_streaming(self) -> Option<StreamingBody> {
        match self.inner {
            RequestBodyInner::Streaming(stream) => stream,
            _ => None,
        }
    }

    /// Read the next frame from the body.
    ///
    /// Buffered bodies yield exactly one data frame, then `None`. Streamed bodies preserve their
    /// chunk boundaries. A `TooLarge` error terminates the body.
    pub async fn next_frame(&mut self) -> Option<Result<Frame<Bytes>, BodyError>> {
        match &mut self.inner {
            RequestBodyInner::Buffered(slot) => match slot.take() {
                Some(bytes) if bytes.is_empty() => None,
                Some(bytes) => {
                    if let Some(limit) = self.limit {
                        if bytes.len() as u64 > limit {
                            return Some(Err(BodyError::TooLarge { limit }));
                        }
                    }
                    Some(Ok(Frame::data(bytes)))
                }
                None => None,
            },
            RequestBodyInner::Streaming(slot) => match slot {
                Some(stream) => {
                    let frame =
                        std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_frame(cx)).await;
                    match frame {
                        Some(Ok(frame)) => match frame.into_data() {
                            Ok(data) => {
                                if let Some(limit) = self.limit {
                                    let read = self
                                        .read
                                        .checked_add(data.len() as u64)
                                        .unwrap_or(u64::MAX);
                                    self.read = read;
                                    if read > limit {
                                        return Some(Err(BodyError::TooLarge { limit }));
                                    }
                                }
                                Some(Ok(Frame::data(data)))
                            }
                            Err(frame) => Some(Ok(frame)),
                        },
                        Some(Err(error)) => Some(Err(error)),
                        None => {
                            // End of stream: mark the body consumed so a later `collect` is a
                            // loud error instead of replaying an already-drained stream as empty.
                            *slot = None;
                            None
                        }
                    }
                }
                None => None,
            },
        }
    }
}

impl HttpBody for RequestBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        match &mut this.inner {
            RequestBodyInner::Buffered(slot) => match slot.take() {
                Some(bytes) if bytes.is_empty() => Poll::Ready(None),
                Some(bytes) => {
                    if let Some(limit) = this.limit {
                        if bytes.len() as u64 > limit {
                            return Poll::Ready(Some(Err(BodyError::TooLarge { limit })));
                        }
                    }
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
                None => Poll::Ready(None),
            },
            RequestBodyInner::Streaming(slot) => match slot {
                Some(stream) => match Pin::new(stream).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => {
                            if let Some(limit) = this.limit {
                                let read =
                                    this.read.checked_add(data.len() as u64).unwrap_or(u64::MAX);
                                this.read = read;
                                if read > limit {
                                    return Poll::Ready(Some(Err(BodyError::TooLarge { limit })));
                                }
                            }
                            Poll::Ready(Some(Ok(Frame::data(data))))
                        }
                        Err(frame) => Poll::Ready(Some(Ok(frame))),
                    },
                    other => other,
                },
                None => Poll::Ready(None),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            RequestBodyInner::Buffered(slot) => slot.as_ref().is_none_or(Bytes::is_empty),
            RequestBodyInner::Streaming(Some(stream)) => stream.is_end_stream(),
            RequestBodyInner::Streaming(None) => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.exact_size()
            .map(SizeHint::with_exact)
            .unwrap_or_else(SizeHint::default)
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

    // ---- request bodies (T-PROXY-039 sub-wave: http/server streaming model) ---------------

    #[tokio::test]
    async fn request_body_buffered_and_streaming_collectors() {
        // Buffered bodies collect without a stream and enforce the limit eagerly.
        let body = RequestBody::buffered(Bytes::from_static(b"hello"));
        assert!(!body.is_streaming());
        assert_eq!(body.exact_size(), Some(5));
        assert_eq!(
            body.collect(None).await.expect("collect"),
            Bytes::from_static(b"hello")
        );
        let body = RequestBody::buffered(Bytes::from_static(b"hello"));
        let error = body.collect(Some(4)).await.expect_err("over limit");
        assert!(matches!(error, BodyError::TooLarge { limit: 4 }), "{error}");

        // Streaming bodies preserve chunk boundaries through `next_frame`.
        let (sender, receiver) = mpsc::channel(4);
        let mut body = RequestBody::streaming(StreamingBody::from_chunks(receiver));
        assert!(body.is_streaming());
        sender.send(Ok(Bytes::from_static(b"aa"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"bbb"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"c"))).await.unwrap();
        drop(sender);
        let mut chunks = Vec::new();
        while let Some(frame) = body.next_frame().await {
            let frame = frame.expect("frame");
            chunks.push(frame.into_data().expect("data frame"));
        }
        assert_eq!(
            chunks,
            vec![
                Bytes::from_static(b"aa"),
                Bytes::from_static(b"bbb"),
                Bytes::from_static(b"c")
            ]
        );

        // A consumed streaming body cannot be replayed (no silent empty body).
        let (sender, receiver) = mpsc::channel(4);
        let mut body = RequestBody::streaming(StreamingBody::from_chunks(receiver));
        sender.send(Ok(Bytes::from_static(b"x"))).await.unwrap();
        drop(sender);
        let _ = body.next_frame().await.expect("first frame");
        let _ = body.next_frame().await;
        let error = body.collect(None).await.expect_err("consumed");
        assert!(matches!(error, BodyError::Consumed), "{error}");
    }

    #[tokio::test]
    async fn request_body_limit_is_enforced_while_streaming() {
        let (sender, receiver) = mpsc::channel(4);
        let mut body =
            RequestBody::streaming(StreamingBody::from_chunks(receiver)).with_limit(Some(5));
        sender.send(Ok(Bytes::from_static(b"1234"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"56"))).await.unwrap();
        drop(sender);
        let first = body
            .next_frame()
            .await
            .expect("first frame")
            .expect("ok frame");
        assert_eq!(
            first.into_data().expect("data"),
            Bytes::from_static(b"1234")
        );
        let error = body
            .next_frame()
            .await
            .expect("second frame")
            .expect_err("limit crossed");
        assert!(matches!(error, BodyError::TooLarge { limit: 5 }), "{error}");

        // Buffered bodies over the limit fail before yielding data.
        let mut body = RequestBody::buffered(Bytes::from_static(b"123456")).with_limit(Some(5));
        let error = body
            .next_frame()
            .await
            .expect("frame")
            .expect_err("too large");
        assert!(matches!(error, BodyError::TooLarge { limit: 5 }), "{error}");

        // RequestBody is a normal `http_body::Body` for upstream forwarding.
        let (sender, receiver) = mpsc::channel(4);
        let body = RequestBody::streaming(StreamingBody::from_chunks(receiver));
        sender.send(Ok(Bytes::from_static(b"data"))).await.unwrap();
        drop(sender);
        let collected = http_body_util::BodyExt::collect(body)
            .await
            .expect("http-body collect");
        assert_eq!(
            http_body_util::BodyExt::collect(Body::from_bytes(Bytes::new()))
                .await
                .expect("empty")
                .to_bytes(),
            Bytes::new()
        );
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"data"));
    }
}

#[cfg(test)]
mod access_log_observation_tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingObserver {
        completions: Mutex<Vec<BodyCompletion>>,
    }

    impl RecordingObserver {
        fn take(&self) -> Vec<BodyCompletion> {
            std::mem::take(
                &mut *self
                    .completions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        }
    }

    impl ResponseBodyObserver for RecordingObserver {
        fn complete(&self, completion: BodyCompletion) {
            self.completions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(completion);
        }
    }

    #[tokio::test]
    async fn observed_body_reports_actual_bytes_at_end() {
        let observer = Arc::new(RecordingObserver::default());
        let mut body = Body::from_bytes(Bytes::from_static(b"hello")).observe(observer.clone());

        let frame = body.frame().await.expect("frame").expect("data frame");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"hello")
        );
        assert!(body.frame().await.is_none());

        let completions = observer.take();
        assert_eq!(completions.len(), 1, "completion runs exactly once");
        assert_eq!(completions[0].bytes, 5);
        assert_eq!(completions[0].expected, Some(5));
        assert!(completions[0].polled);
        assert_eq!(completions[0].status, BodyStatus::Ended);
    }

    #[tokio::test]
    async fn dropped_observed_body_reports_partial_progress() {
        let observer = Arc::new(RecordingObserver::default());
        let mut body = Body::from_bytes(Bytes::from_static(b"hello")).observe(observer.clone());
        let frame = body.frame().await.expect("frame").expect("data frame");
        assert_eq!(frame.into_data().expect("data").len(), 5);
        drop(body);

        let completions = observer.take();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].bytes, 5);
        assert_eq!(completions[0].expected, Some(5));
        assert!(completions[0].polled);
        assert_eq!(completions[0].status, BodyStatus::Dropped);
    }

    #[tokio::test]
    async fn observed_body_error_reports_failure_with_partial_bytes() {
        let observer = Arc::new(RecordingObserver::default());
        let (sender, receiver) = mpsc::channel(4);
        sender
            .send(Ok(Bytes::from_static(b"part")))
            .await
            .expect("first chunk");
        sender
            .send(Err(BodyError::Cancelled))
            .await
            .expect("error chunk");
        drop(sender);
        let mut body =
            Body::from_stream(StreamingBody::from_chunks(receiver)).observe(observer.clone());

        let frame = body.frame().await.expect("frame").expect("data frame");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"part")
        );
        assert!(body.frame().await.expect("error frame").is_err());

        let completions = observer.take();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].bytes, 4);
        assert_eq!(
            completions[0].status,
            BodyStatus::Failed("body stream was cancelled".to_string())
        );
    }

    #[tokio::test]
    async fn streamed_body_counter_tracks_actual_bytes_read() {
        let counter = BodyBytes::new();
        let (sender, receiver) = mpsc::channel(4);
        sender
            .send(Ok(Bytes::from_static(b"abc")))
            .await
            .expect("first chunk");
        sender
            .send(Ok(Bytes::from_static(b"de")))
            .await
            .expect("second chunk");
        drop(sender);
        let mut body = RequestBody::streaming(
            StreamingBody::from_chunks(receiver).with_counter(counter.clone()),
        );

        let mut total = 0_usize;
        while let Some(frame) = body.next_frame().await {
            total += frame.expect("frame").into_data().expect("data").len();
        }
        assert_eq!(total, 5);
        assert_eq!(counter.get(), 5, "counter reports actual bytes, not a hint");
    }
}
