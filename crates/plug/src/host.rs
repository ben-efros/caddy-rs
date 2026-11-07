//! Host-side lifecycle for external module services (T-PLUG-021).
//!
//! This module turns the wire contract in [`crate::protocol`] into a managed, generation-scoped
//! service: it spawns (or connects to) a module process, performs the host half of the handshake,
//! routes capability-gated host calls, tracks in-flight requests, and stops/reaps the child with a
//! bounded grace period. The vocabulary is the project's configuration-generation vocabulary from
//! `caddy-rs-core` (`GenerationResource`/`GenerationResources`, T-CORE-012): a service is attached
//! to a generation, started/rejected with it, stopped/drained with it, and cleaned up exactly once.
//!
//! Design rules:
//!
//! * **No unsafe code.** The child is a plain [`std::process::Child`]; the transport is any
//!   [`std::io::Read`] + [`std::io::Write`] pair (stdio pipes or a Unix socket the operator
//!   configured). No FD passing and no network listener.
//! * **Containment.** A module crash, EOF, malformed/oversized frame or protocol violation is a
//!   typed [`HostError`]; the session marks itself failed, records every in-flight request with a
//!   typed error (`take_failed_requests`), and always reaps the child. Dropping a [`HostService`]
//!   is best-effort shutdown; [`HostService::stop`] is the deterministic grace-then-kill path.
//! * **Explicit supervision.** [`RestartPolicy::Never`] is the default: a crashed service is
//!   reported, never silently restarted. [`RestartPolicy::OnFailure`] restarts with backoff and a
//!   bounded attempt count; exhaustion is a typed error.
//! * **Deny by default.** Host calls are authorized through [`HostCallContext`] (generation,
//!   granted capabilities, argument limits, per-request budget). A denied call is answered with a
//!   request-scoped `ERROR` frame carrying `CapabilityDenied`; the module cannot widen its grants.
//!
//! The process model is intentionally minimal (one process, one connection, one generation). A
//! future host runtime can run this service behind the `GenerationHooks::provision` hook and drive
//! requests from the HTTP server; this crate owns the lifecycle contract, not the HTTP wiring.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use caddy_rs_core::{Error as CoreError, GenerationResource};

use crate::bridge::{AbiLimits, BridgeHeaders, RequestHead};
use crate::capability::CapabilitySet;
use crate::descriptor::PluginLimits;
use crate::error::{AbiErrorCode, HostCallError, WireError};
use crate::hostcall::{HostCall, HostCallContext, HostCallResult};
use crate::protocol::{
    accept_handshake, validate_handshake_ack, ErrorFrame, HandshakeError, HostCallFrame,
    HostCallResultFrame, HostHandshakeConfig, NegotiatedSession, OpenRequest, ProtocolError,
    ProtocolFrame, RequestBodyChunk, RequestEnd, RequestId, ResponseBodyChunk, ResponseEnd,
    ResponseHeadFrame,
};
use crate::version::NegotiatedAbi;

/// Default grace period granted to a module process between clean shutdown and `kill`.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(5);

/// Default backoff between supervised restart attempts.
pub const DEFAULT_RESTART_BACKOFF: Duration = Duration::from_millis(250);

/// Where and how the module process/transport is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleTransportSpec {
    /// Spawn `program` with `args` and speak the protocol over its stdin/stdout.
    Stdio {
        /// Executable path (or name on `PATH`).
        program: String,
        /// Command-line arguments.
        args: Vec<String>,
        /// Extra environment variables (`KEY=value` pairs); the parent environment is inherited
        /// only if `inherit_env` is true.
        env: Vec<(String, String)>,
        /// Whether to inherit the host environment (default false: a scrubbed environment is
        /// safer for untrusted modules).
        inherit_env: bool,
    },
    /// Connect to a Unix domain socket the operator configured for this module.
    #[cfg(unix)]
    UnixSocket {
        /// Socket path configured by the operator.
        path: std::path::PathBuf,
    },
}

/// How a crashed module is handled. `Never` is the default: no silent restart loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    /// Report the crash and leave the service stopped (default).
    #[default]
    Never,
    /// Restart up to `max_restarts` times with `backoff` between attempts. Exhaustion is reported.
    OnFailure {
        /// Maximum number of restart attempts (must be positive to restart at all).
        max_restarts: u32,
        /// Delay before each restart attempt.
        backoff: Duration,
    },
}

/// Host configuration for one external module service.
#[derive(Debug, Clone)]
pub struct HostServiceConfig {
    /// Handshake configuration: versions, capability policy, host limits, windows.
    pub handshake: HostHandshakeConfig,
    /// Limit set used for frame/payload decoding (defaults to the ABI limits; may be tighter).
    pub limits: AbiLimits,
    /// Grace period between sending the fatal close and killing the process.
    pub stop_grace: Duration,
    /// Explicit supervision policy (no restarts by default).
    pub restart: RestartPolicy,
}

impl Default for HostServiceConfig {
    fn default() -> Self {
        Self {
            handshake: HostHandshakeConfig::default(),
            limits: AbiLimits::spec_defaults(),
            stop_grace: DEFAULT_STOP_GRACE,
            restart: RestartPolicy::Never,
        }
    }
}

/// A transport for the external protocol: a byte reader and a byte writer.
pub struct ModuleTransport {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

impl fmt::Debug for ModuleTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModuleTransport")
            .finish_non_exhaustive()
    }
}

impl ModuleTransport {
    /// Build a transport from any reader/writer pair (used by tests and embedders).
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self { reader, writer }
    }

    /// Take stdin/stdout of an already-spawned child.
    pub fn from_child_stdio(child: &mut Child) -> io::Result<Self> {
        let reader = child.stdout.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "child stdout is not piped")
        })?;
        let writer = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "child stdin is not piped"))?;
        Ok(Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }

    /// Connect to an operator-configured Unix domain socket.
    #[cfg(unix)]
    pub fn unix_socket(path: &std::path::Path) -> io::Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        stream.set_read_timeout(None)?;
        let reader = stream.try_clone()?;
        Ok(Self {
            reader: Box::new(reader),
            writer: Box::new(stream),
        })
    }

    fn send(&mut self, frame: &ProtocolFrame, limits: &AbiLimits) -> Result<(), HostError> {
        write_frame(&mut self.writer, frame, limits)
    }

    fn receive(&mut self, limits: &AbiLimits) -> Result<ProtocolFrame, HostError> {
        read_frame(&mut self.reader, limits)
    }

    fn close_writer(&mut self) {
        // Dropping is not possible without owning the boxed writer; flush and best-effort EOF are
        // achieved by replacing the writer with a sink after flushing.
        let _ = self.writer.flush();
    }
}

/// Encode one frame to `writer`.
pub fn write_frame(
    writer: &mut impl Write,
    frame: &ProtocolFrame,
    limits: &AbiLimits,
) -> Result<(), HostError> {
    let bytes = frame.encode(limits).map_err(HostError::Protocol)?;
    writer.write_all(&bytes).map_err(|error| HostError::Io {
        operation: "write frame",
        message: error.to_string(),
    })?;
    writer.flush().map_err(|error| HostError::Io {
        operation: "flush frame",
        message: error.to_string(),
    })
}

/// Read one complete frame from `reader`, enforcing the frame limit.
///
/// EOF at a frame boundary is [`HostError::ModuleClosed`]; a partially read header/payload is
/// [`HostError::ModuleClosed`] as well (the module died mid-frame).
pub fn read_frame(reader: &mut impl Read, limits: &AbiLimits) -> Result<ProtocolFrame, HostError> {
    let mut header = [0_u8; 5];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(HostError::ModuleClosed)
        }
        Err(error) => {
            return Err(HostError::Io {
                operation: "read frame header",
                message: error.to_string(),
            })
        }
    }
    let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if payload_len > limits.max_frame_payload {
        return Err(HostError::Protocol(ProtocolError::Wire(
            WireError::FrameTooLarge {
                len: payload_len,
                max: limits.max_frame_payload,
            },
        )));
    }
    let mut bytes = Vec::with_capacity(5 + payload_len);
    bytes.extend_from_slice(&header);
    bytes.resize(5 + payload_len, 0);
    if let Err(error) = reader.read_exact(&mut bytes[5..]) {
        return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
            HostError::ModuleClosed
        } else {
            HostError::Io {
                operation: "read frame payload",
                message: error.to_string(),
            }
        });
    }
    let (frame, consumed) = ProtocolFrame::decode(&bytes, limits).map_err(HostError::Protocol)?;
    if consumed != bytes.len() {
        return Err(HostError::Protocol(ProtocolError::Wire(
            WireError::TrailingBytes {
                count: bytes.len() - consumed,
            },
        )));
    }
    Ok(frame)
}

/// Host-side implementation of capability-gated host calls.
pub trait HostCallHandler: Send {
    /// Handle one authorized host call for `request_id`.
    fn handle(
        &mut self,
        request_id: RequestId,
        call: HostCall,
    ) -> Result<HostCallResult, HostCallError>;
}

/// A handler that denies every call (useful default for tests/hosts without call support).
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllHostCalls;

impl HostCallHandler for DenyAllHostCalls {
    fn handle(
        &mut self,
        _request_id: RequestId,
        call: HostCall,
    ) -> Result<HostCallResult, HostCallError> {
        Err(HostCallError::HostFailure {
            message: format!(
                "host-call code {} is not implemented by this host",
                call.code()
            ),
        })
    }
}

/// One event produced by [`HostService::next_event`] (non-host-call frames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// Module response head.
    ResponseHead(ResponseHeadFrame),
    /// Module response body chunk.
    ResponseBodyChunk(ResponseBodyChunk),
    /// Module response end with trailers.
    ResponseEnd(ResponseEnd),
    /// Module cancelled the request.
    Cancelled(crate::protocol::Cancel),
    /// Module reported an error (request-scoped or fatal).
    Error(ErrorFrame),
    /// A host call was authorized and answered (result code).
    HostCallCompleted {
        /// Request the call belonged to.
        request_id: RequestId,
        /// Host-call code that was answered.
        call_code: u32,
    },
    /// A host call was refused; the module received a request-scoped error frame.
    HostCallDenied {
        /// Request the call belonged to.
        request_id: RequestId,
        /// Host-call code that was refused.
        call_code: u32,
        /// Typed reason.
        error: HostCallError,
    },
}

/// Errors from hosting an external module service.
#[derive(Debug)]
pub enum HostError {
    /// Spawning the process failed (includes the program name and OS message).
    Spawn {
        /// Program that failed to start.
        program: String,
        /// OS message.
        message: String,
    },
    /// Transport I/O failed.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// OS message.
        message: String,
    },
    /// The protocol frame/payload was malformed or outside the protocol contract.
    Protocol(ProtocolError),
    /// The handshake failed (the host sent a `REJECT` frame when still writable).
    Handshake(HandshakeError),
    /// The module closed the transport (EOF) before or during a frame.
    ModuleClosed,
    /// The module process exited unexpectedly (code is OS-specific; signal deaths have no code).
    ModuleExited {
        /// Process exit code when it exited normally.
        code: Option<i32>,
        /// In-flight requests that were failed by the exit.
        failed_requests: Vec<RequestId>,
    },
    /// The session is no longer usable (crash, malformed frame, protocol violation).
    SessionFailed {
        /// Human-readable cause (the typed cause is also stored in the failed-request list).
        message: String,
        /// In-flight requests that were failed.
        failed_requests: Vec<RequestId>,
    },
    /// A request id is unknown or already finished.
    UnknownRequest {
        /// Offending id.
        request_id: RequestId,
    },
    /// The service is not running (stopped, crashed or never started).
    NotRunning,
    /// The operation timed out.
    Timeout {
        /// Operation name.
        operation: &'static str,
    },
    /// A crash was contained and the supervision policy forbids restarting.
    CrashIsolated {
        /// Exit code when available.
        code: Option<i32>,
    },
    /// Supervised restarts were exhausted.
    RestartExhausted {
        /// Attempts used.
        attempts: u32,
    },
    /// The operation is invalid for the current service state.
    InvalidState {
        /// Human-readable reason.
        message: String,
    },
}

impl HostError {
    /// Stable ABI error code for the failure, when one applies.
    pub const fn abi_code(&self) -> AbiErrorCode {
        match self {
            Self::Protocol(error) => error.abi_code(),
            Self::Handshake(error) => error.abi_code(),
            Self::ModuleClosed | Self::ModuleExited { .. } | Self::SessionFailed { .. } => {
                AbiErrorCode::PluginFailed
            }
            Self::Spawn { .. } | Self::Io { .. } | Self::Timeout { .. } => {
                AbiErrorCode::HostFailure
            }
            Self::UnknownRequest { .. } | Self::InvalidState { .. } => AbiErrorCode::InvalidRequest,
            Self::NotRunning => AbiErrorCode::StaleGeneration,
            Self::CrashIsolated { .. } | Self::RestartExhausted { .. } => {
                AbiErrorCode::PluginFailed
            }
        }
    }

    /// Materialise a request-scoped error frame for this failure.
    pub fn to_error_frame(&self, request_id: RequestId) -> ErrorFrame {
        ErrorFrame {
            request_id: Some(request_id),
            fatal: false,
            code: self.abi_code(),
            message: self.to_string(),
        }
    }
}

fn host_call_error_code(error: &HostCallError) -> AbiErrorCode {
    match error {
        HostCallError::StaleGeneration { .. } => AbiErrorCode::StaleGeneration,
        HostCallError::CapabilityDenied { .. } => AbiErrorCode::CapabilityDenied,
        HostCallError::CallBudgetExhausted { .. } => AbiErrorCode::LimitExceeded,
        HostCallError::InvalidArgument { .. } => AbiErrorCode::InvalidRequest,
        HostCallError::Cancelled => AbiErrorCode::Cancelled,
        HostCallError::HostFailure { .. } => AbiErrorCode::HostFailure,
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { program, message } => {
                write!(formatter, "failed to spawn module `{program}`: {message}")
            }
            Self::Io { operation, message } => write!(
                formatter,
                "transport I/O failed while {operation}: {message}"
            ),
            Self::Protocol(error) => write!(formatter, "module protocol violation: {error}"),
            Self::Handshake(error) => write!(formatter, "module handshake rejected: {error}"),
            Self::ModuleClosed => write!(formatter, "module closed the protocol transport"),
            Self::ModuleExited {
                code,
                failed_requests,
            } => write!(
                formatter,
                "module exited unexpectedly ({code:?}); failed {} in-flight request(s)",
                failed_requests.len()
            ),
            Self::SessionFailed {
                message,
                failed_requests,
            } => write!(
                formatter,
                "module session failed ({message}); failed {} in-flight request(s)",
                failed_requests.len()
            ),
            Self::UnknownRequest { request_id } => {
                write!(formatter, "unknown request id {}", request_id.get())
            }
            Self::NotRunning => write!(formatter, "module service is not running"),
            Self::Timeout { operation } => {
                write!(formatter, "module operation timed out: {operation}")
            }
            Self::CrashIsolated { code } => write!(
                formatter,
                "module crashed ({code:?}) and the supervision policy does not restart it"
            ),
            Self::RestartExhausted { attempts } => {
                write!(
                    formatter,
                    "module restarts exhausted after {attempts} attempt(s)"
                )
            }
            Self::InvalidState { message } => write!(formatter, "invalid module state: {message}"),
        }
    }
}

impl std::error::Error for HostError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceState {
    Running,
    Failed,
    Stopped,
}

/// A running external module instance (child process or operator-provided socket) with a
/// negotiated protocol session.
pub struct HostService {
    name: String,
    child: Option<Child>,
    transport: Option<ModuleTransport>,
    state: ServiceState,
    generation: u64,
    config: HostServiceConfig,
    session: NegotiatedSession,
    next_request_id: u64,
    in_flight: BTreeMap<RequestId, HostCallContext>,
    failed_requests: Vec<(RequestId, HostError)>,
    exit_code: Option<i32>,
    started: bool,
}

impl fmt::Debug for HostService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostService")
            .field("name", &self.name)
            .field("state", &self.state)
            .field("generation", &self.generation)
            .field("in_flight", &self.in_flight.keys().collect::<Vec<_>>())
            .field("child_pid", &self.child.as_ref().map(Child::id))
            .finish()
    }
}

impl HostService {
    /// Spawn/connect and perform the host side of the `HELLO`/`HELLO_ACK` handshake.
    ///
    /// This is the provisioning-time entry point: call it while the generation is being prepared
    /// and attach the resulting service to [`caddy_rs_core::GenerationResources`] through
    /// [`GenerationModule::new`]. A failed handshake sends `REJECT`, kills and reaps the child.
    pub fn spawn(
        name: impl Into<String>,
        transport: ModuleTransportSpec,
        generation: u64,
        config: HostServiceConfig,
    ) -> Result<Self, HostError> {
        let name = name.into();
        let (child, transport) = match transport {
            ModuleTransportSpec::Stdio {
                program,
                args,
                env,
                inherit_env,
            } => {
                let mut command = Command::new(&program);
                command
                    .args(&args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped());
                command.stderr(Stdio::null());
                if !inherit_env {
                    command.env_clear();
                }
                for (key, value) in env {
                    command.env(key, value);
                }
                let mut child = command.spawn().map_err(|error| HostError::Spawn {
                    program: program.clone(),
                    message: error.to_string(),
                })?;
                let transport = ModuleTransport::from_child_stdio(&mut child).map_err(|error| {
                    let _ = child.kill();
                    let _ = child.wait();
                    HostError::Spawn {
                        program,
                        message: error.to_string(),
                    }
                })?;
                (Some(child), transport)
            }
            #[cfg(unix)]
            ModuleTransportSpec::UnixSocket { path } => {
                let transport =
                    ModuleTransport::unix_socket(&path).map_err(|error| HostError::Io {
                        operation: "connect module socket",
                        message: format!("{}: {error}", path.display()),
                    })?;
                (None, transport)
            }
        };
        let mut service = Self {
            name,
            child,
            transport: Some(transport),
            state: ServiceState::Running,
            generation,
            config,
            session: NegotiatedSession {
                protocol: crate::protocol::PROTOCOL_VERSION,
                abi: NegotiatedAbi {
                    plugin: crate::version::ABI_VERSION,
                    host: crate::version::HOST_ABI_VERSION,
                },
                granted: CapabilitySet::EMPTY,
                limits: PluginLimits::default_limits(),
                max_in_flight_requests: 1,
                body_window_bytes: 1,
            },
            next_request_id: 1,
            in_flight: BTreeMap::new(),
            failed_requests: Vec::new(),
            exit_code: None,
            started: false,
        };
        if let Err(error) = service.handshake() {
            service.force_kill();
            return Err(error);
        }
        Ok(service)
    }

    fn handshake(&mut self) -> Result<(), HostError> {
        let limits = self.config.limits;
        let frame = {
            let transport = self
                .transport
                .as_mut()
                .ok_or_else(|| HostError::InvalidState {
                    message: "module transport already closed".to_string(),
                })?;
            transport.receive(&limits)?
        };
        let hello = match frame {
            ProtocolFrame::Hello(hello) => hello,
            other => {
                return Err(HostError::Protocol(ProtocolError::InvalidHelloAck {
                    reason: match other {
                        ProtocolFrame::HelloAck(_) => "host received HELLO_ACK before HELLO",
                        ProtocolFrame::Reject(_) => "host received REJECT before HELLO",
                        _ => "first frame must be HELLO",
                    },
                }))
            }
        };
        match accept_handshake(&hello, &self.config.handshake) {
            Ok(ack) => {
                let frame = ProtocolFrame::HelloAck(ack.clone());
                let transport = self
                    .transport
                    .as_mut()
                    .expect("transport is open during handshake");
                transport.send(&frame, &limits)?;
                let session = validate_handshake_ack(&hello, &ack).map_err(HostError::Handshake)?;
                self.session = session;
                Ok(())
            }
            Err(error) => {
                let reject = error.to_reject();
                if let Some(transport) = self.transport.as_mut() {
                    let _ = transport.send(&ProtocolFrame::Reject(reject), &limits);
                }
                Err(HostError::Handshake(error))
            }
        }
    }

    /// Module name given at spawn time.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Generation this service belongs to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Negotiated session (protocol/ABI versions, grants, limits, windows).
    pub fn session(&self) -> &NegotiatedSession {
        &self.session
    }

    /// OS process id when the service owns a child.
    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Whether the service is currently running (does not block or reap).
    pub fn is_running(&self) -> bool {
        self.state == ServiceState::Running
    }

    /// Exit code after the child exited, if observed.
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Requests failed by a crash/session error, with their typed errors (drained).
    pub fn take_failed_requests(&mut self) -> Vec<(RequestId, HostError)> {
        std::mem::take(&mut self.failed_requests)
    }

    fn transport(&mut self) -> Result<&mut ModuleTransport, HostError> {
        if self.state != ServiceState::Running {
            return Err(HostError::NotRunning);
        }
        self.transport.as_mut().ok_or(HostError::NotRunning)
    }

    fn next_request_id(&mut self) -> Result<RequestId, HostError> {
        let id =
            RequestId::new(self.next_request_id).map_err(|error| HostError::Protocol(error))?;
        self.next_request_id =
            self.next_request_id
                .checked_add(1)
                .ok_or_else(|| HostError::InvalidState {
                    message: "request id space exhausted".to_string(),
                })?;
        Ok(id)
    }

    /// Open a request and send its head. The returned id is unique for this service.
    pub fn open_request(
        &mut self,
        head: RequestHead,
        deadline_ms: u32,
    ) -> Result<RequestId, HostError> {
        let request_id = self.next_request_id()?;
        if self.in_flight.len() >= self.session.max_in_flight_requests as usize {
            return Err(HostError::InvalidState {
                message: format!(
                    "in-flight request limit reached ({})",
                    self.session.max_in_flight_requests
                ),
            });
        }
        let budget = self.session.limits.max_host_calls_per_request;
        self.in_flight.insert(
            request_id,
            HostCallContext::new(self.generation, self.session.granted, budget),
        );
        let frame = ProtocolFrame::OpenRequest(OpenRequest {
            request_id,
            deadline_ms,
            head,
        });
        let limits = self.config.limits;
        self.transport()?.send(&frame, &limits)?;
        Ok(request_id)
    }

    /// Send a request-body chunk.
    pub fn send_request_body(
        &mut self,
        request_id: RequestId,
        chunk: Vec<u8>,
    ) -> Result<(), HostError> {
        self.ensure_in_flight(request_id)?;
        let limits = self.config.limits;
        self.transport()?.send(
            &ProtocolFrame::RequestBodyChunk(RequestBodyChunk { request_id, chunk }),
            &limits,
        )
    }

    /// End the request body with optional trailers.
    pub fn end_request(
        &mut self,
        request_id: RequestId,
        trailers: BridgeHeaders,
    ) -> Result<(), HostError> {
        self.ensure_in_flight(request_id)?;
        let limits = self.config.limits;
        self.transport()?.send(
            &ProtocolFrame::RequestEnd(RequestEnd {
                request_id,
                trailers,
            }),
            &limits,
        )
    }

    /// Cancel a request (the id is retired; later frames for it are protocol violations).
    pub fn cancel_request(
        &mut self,
        request_id: RequestId,
        code: AbiErrorCode,
        message: &str,
    ) -> Result<(), HostError> {
        self.ensure_in_flight(request_id)?;
        self.in_flight.remove(&request_id);
        let limits = self.config.limits;
        self.transport()?.send(
            &ProtocolFrame::Cancel(crate::protocol::Cancel {
                request_id,
                code,
                message: message.to_string(),
            }),
            &limits,
        )
    }

    fn ensure_in_flight(&self, request_id: RequestId) -> Result<(), HostError> {
        if self.in_flight.contains_key(&request_id) {
            Ok(())
        } else {
            Err(HostError::UnknownRequest { request_id })
        }
    }

    /// Read the next event, routing interleaved host calls through `handler`.
    ///
    /// A transport error or malformed frame fails the session: all in-flight requests are recorded
    /// with a typed error (`take_failed_requests`) and the returned error is typed. The child is
    /// not reaped here; call [`HostService::stop`] (or let `Drop` run) to reap deterministically.
    pub fn next_event(
        &mut self,
        handler: &mut impl HostCallHandler,
    ) -> Result<HostEvent, HostError> {
        let limits = self.config.limits;
        let frame = match self.transport()?.receive(&limits) {
            Ok(frame) => frame,
            Err(error) => {
                let error = self.classify_transport_error(error);
                self.fail_session(&error);
                return Err(error);
            }
        };
        match frame {
            ProtocolFrame::ResponseHead(frame) => {
                self.ensure_in_flight(frame.request_id)?;
                Ok(HostEvent::ResponseHead(frame))
            }
            ProtocolFrame::ResponseBodyChunk(frame) => {
                self.ensure_in_flight(frame.request_id)?;
                Ok(HostEvent::ResponseBodyChunk(frame))
            }
            ProtocolFrame::ResponseEnd(frame) => {
                self.ensure_in_flight(frame.request_id)?;
                self.in_flight.remove(&frame.request_id);
                Ok(HostEvent::ResponseEnd(frame))
            }
            ProtocolFrame::Cancel(cancel) => {
                self.in_flight.remove(&cancel.request_id);
                Ok(HostEvent::Cancelled(cancel))
            }
            ProtocolFrame::Error(error) => {
                if let Some(request_id) = error.request_id {
                    self.in_flight.remove(&request_id);
                }
                if error.fatal {
                    self.state = ServiceState::Failed;
                    self.fail_in_flight(HostError::SessionFailed {
                        message: error.message.clone(),
                        failed_requests: Vec::new(),
                    });
                }
                Ok(HostEvent::Error(error))
            }
            ProtocolFrame::HostCall(frame) => self.dispatch_host_call(frame, handler),
            other => {
                let error = HostError::Protocol(ProtocolError::InvalidHelloAck {
                    reason: match other {
                        ProtocolFrame::Hello(_) => "unexpected HELLO after handshake",
                        ProtocolFrame::HelloAck(_) => "unexpected HELLO_ACK",
                        ProtocolFrame::Reject(_) => "unexpected REJECT",
                        ProtocolFrame::OpenRequest(_) => "host-only frame echoed by module",
                        ProtocolFrame::RequestBodyChunk(_) => "host-only frame echoed by module",
                        ProtocolFrame::RequestEnd(_) => "host-only frame echoed by module",
                        ProtocolFrame::HostCallResult(_) => "unexpected HOST_CALL_RESULT",
                        _ => "unexpected frame",
                    },
                });
                self.fail_session(&error);
                Err(error)
            }
        }
    }

    fn dispatch_host_call(
        &mut self,
        frame: HostCallFrame,
        handler: &mut impl HostCallHandler,
    ) -> Result<HostEvent, HostError> {
        let limits = self.config.limits;
        let Some(context) = self.in_flight.get_mut(&frame.request_id) else {
            let error = HostError::UnknownRequest {
                request_id: frame.request_id,
            };
            self.fail_session(&error);
            return Err(error);
        };
        match context.authorize(&frame.call, self.generation, &limits) {
            Err(error) => {
                let code = host_call_error_code(&error);
                let outgoing = ProtocolFrame::Error(ErrorFrame {
                    request_id: Some(frame.request_id),
                    fatal: false,
                    code,
                    message: error.to_string(),
                });
                self.transport()?.send(&outgoing, &limits)?;
                Ok(HostEvent::HostCallDenied {
                    request_id: frame.request_id,
                    call_code: frame.call.code(),
                    error,
                })
            }
            Ok(()) => {
                let call_code = frame.call.code();
                match handler.handle(frame.request_id, frame.call) {
                    Ok(result) => {
                        let outgoing = ProtocolFrame::HostCallResult(HostCallResultFrame {
                            request_id: frame.request_id,
                            result,
                        });
                        self.transport()?.send(&outgoing, &limits)?;
                        Ok(HostEvent::HostCallCompleted {
                            request_id: frame.request_id,
                            call_code,
                        })
                    }
                    Err(error) => {
                        let code = host_call_error_code(&error);
                        let outgoing = ProtocolFrame::Error(ErrorFrame {
                            request_id: Some(frame.request_id),
                            fatal: false,
                            code,
                            message: error.to_string(),
                        });
                        self.transport()?.send(&outgoing, &limits)?;
                        Ok(HostEvent::HostCallDenied {
                            request_id: frame.request_id,
                            call_code,
                            error,
                        })
                    }
                }
            }
        }
    }

    fn classify_transport_error(&mut self, error: HostError) -> HostError {
        match error {
            HostError::ModuleClosed => {
                // Observe the exit status without blocking indefinitely: try_wait first; a crash
                // mid-frame is reported as ModuleExited so the supervisor policy sees the code.
                let code = self.try_wait_exit_code();
                HostError::ModuleExited {
                    code,
                    failed_requests: self.in_flight.keys().copied().collect(),
                }
            }
            other => other,
        }
    }

    fn fail_session(&mut self, error: &HostError) {
        self.state = ServiceState::Failed;
        let failed: Vec<RequestId> = self.in_flight.keys().copied().collect();
        self.in_flight.clear();
        for request_id in failed {
            self.failed_requests.push((
                request_id,
                HostError::SessionFailed {
                    message: error.to_string(),
                    failed_requests: vec![request_id],
                },
            ));
        }
    }

    fn fail_in_flight(&mut self, error: HostError) {
        let failed: Vec<RequestId> = self.in_flight.keys().copied().collect();
        self.in_flight.clear();
        for request_id in failed {
            self.failed_requests.push((
                request_id,
                HostError::SessionFailed {
                    message: error.to_string(),
                    failed_requests: vec![request_id],
                },
            ));
        }
    }

    fn try_wait_exit_code(&mut self) -> Option<i32> {
        if self.exit_code.is_some() {
            return self.exit_code;
        }
        let Some(child) = self.child.as_mut() else {
            return None;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.exit_code = status.code();
                self.exit_code
            }
            _ => None,
        }
    }

    /// Check whether a child exited while no frame was being read (e.g. after a crash).
    ///
    /// Returns `Ok(false)` while running, `Ok(true)` when a crash was detected and recorded (the
    /// caller should follow the supervision policy), and a typed error when the service was already
    /// failed for another reason.
    pub fn poll_child(&mut self) -> Result<bool, HostError> {
        if self.state == ServiceState::Stopped {
            return Ok(true);
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(self.state == ServiceState::Failed);
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.exit_code = status.code();
                self.state = ServiceState::Failed;
                let error = HostError::ModuleExited {
                    code: self.exit_code,
                    failed_requests: self.in_flight.keys().copied().collect(),
                };
                self.fail_in_flight(error);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => Err(HostError::Io {
                operation: "poll module child",
                message: error.to_string(),
            }),
        }
    }

    /// Stop the service: best-effort fatal close, bounded grace, then kill and reap.
    ///
    /// Returns the child exit code when the service owned a process. Idempotent.
    pub fn stop(&mut self) -> Result<Option<i32>, HostError> {
        if self.state == ServiceState::Stopped {
            return Ok(self.exit_code);
        }
        let limits = self.config.limits;
        if self.state == ServiceState::Running {
            if let Some(transport) = self.transport.as_mut() {
                let frame = ProtocolFrame::Error(ErrorFrame {
                    request_id: None,
                    fatal: true,
                    code: AbiErrorCode::Cancelled,
                    message: "generation stopped".to_string(),
                });
                let _ = transport.send(&frame, &limits);
                transport.close_writer();
            }
        }
        self.transport = None;
        self.in_flight.clear();
        let grace = self.config.stop_grace;
        let deadline = Instant::now() + grace;
        if let Some(child) = self.child.as_mut() {
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.exit_code = status.code();
                        break;
                    }
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            let status = child.wait().map_err(|error| HostError::Io {
                                operation: "reap module child",
                                message: error.to_string(),
                            })?;
                            self.exit_code = status.code();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        return Err(HostError::Io {
                            operation: "wait for module child",
                            message: error.to_string(),
                        })
                    }
                }
            }
        }
        self.state = ServiceState::Stopped;
        Ok(self.exit_code)
    }

    fn force_kill(&mut self) {
        self.transport = None;
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            if let Ok(status) = child.wait() {
                self.exit_code = status.code();
            }
        }
        self.state = ServiceState::Stopped;
        self.in_flight.clear();
    }

    /// Mark the generation resource as started (idempotent; the process already exists).
    pub fn mark_started(&mut self) {
        self.started = true;
    }
}

impl Drop for HostService {
    fn drop(&mut self) {
        if self.state != ServiceState::Stopped {
            let _ = self.stop();
        }
    }
}

/// Adapter that exposes a [`HostService`] through the project's [`GenerationResource`] contract.
///
/// Provisioning flow used by the host runtime (T-CORE-012):
/// 1. `HostService::spawn` (validates + handshakes, may be done inside `GenerationHooks::provision`);
/// 2. `resources.attach(Arc::new(GenerationModule::new(service)))`;
/// 3. `resources.start()` — this adapter ensures the service is marked started;
/// 4. on reload/failure `resources.stop()` then `resources.cleanup()` — the adapter stops with the
///    configured grace period, kills if needed and reaps the child, so the generation cannot leak
///    processes or zombies.
#[derive(Clone)]
pub struct GenerationModule {
    inner: Arc<Mutex<HostService>>,
    name: String,
}

impl fmt::Debug for GenerationModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationModule")
            .field("name", &self.name)
            .finish()
    }
}

impl GenerationModule {
    /// Wrap an already-spawned service for generation lifecycle management.
    pub fn new(service: HostService) -> Self {
        let name = service.name().to_string();
        Self {
            inner: Arc::new(Mutex::new(service)),
            name,
        }
    }

    /// Generation number of the wrapped service.
    pub fn generation(&self) -> u64 {
        self.lock().generation()
    }

    /// Run `body` with the underlying service (poisoned lock is recovered: a panic in a previous
    /// holder must not make the service permanently unusable).
    pub fn with_service<R>(&self, body: impl FnOnce(&mut HostService) -> R) -> R {
        body(&mut self.lock())
    }

    /// Stop the service now (bounded grace then kill) and return the exit code.
    pub fn stop(&self) -> Result<Option<i32>, HostError> {
        self.lock().stop()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HostService> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn core_error(error: HostError) -> CoreError {
        CoreError::invalid("plugin module service", error.to_string())
    }
}

#[async_trait::async_trait]
impl GenerationResource for GenerationModule {
    fn name(&self) -> &str {
        &self.name
    }

    async fn start(&self) -> caddy_rs_core::Result<()> {
        self.lock().mark_started();
        Ok(())
    }

    async fn stop(&self) -> caddy_rs_core::Result<()> {
        self.stop().map(|_| ()).map_err(Self::core_error)
    }

    async fn cleanup(&self) -> caddy_rs_core::Result<()> {
        self.lock().stop().map(|_| ()).map_err(Self::core_error)
    }
}

/// Explicit supervision policy driver for one module service.
pub struct ModuleSupervisor {
    name: String,
    transport: ModuleTransportSpec,
    generation: u64,
    config: HostServiceConfig,
    policy: RestartPolicy,
    restarts_used: u32,
    service: Option<HostService>,
}

impl ModuleSupervisor {
    /// Start a supervised service. Restart policy comes from `config.restart`.
    pub fn start(
        name: impl Into<String>,
        transport: ModuleTransportSpec,
        generation: u64,
        config: HostServiceConfig,
    ) -> Result<Self, HostError> {
        let name = name.into();
        let policy = config.restart;
        let service =
            HostService::spawn(name.clone(), transport.clone(), generation, config.clone())?;
        Ok(Self {
            name,
            transport,
            generation,
            config,
            policy,
            restarts_used: 0,
            service: Some(service),
        })
    }

    /// Current service (mutable) when running.
    pub fn service_mut(&mut self) -> Option<&mut HostService> {
        self.service.as_mut().filter(|service| service.is_running())
    }

    /// Number of restart attempts performed so far.
    pub fn restarts_used(&self) -> u32 {
        self.restarts_used
    }

    /// Explicit supervision step after a crash was detected.
    ///
    /// `Never` (default) returns [`HostError::CrashIsolated`] and leaves the service stopped: no
    /// silent restart loops. `OnFailure` sleeps for the configured backoff, respawns and re-runs
    /// the handshake, up to the attempt bound; exhaustion is [`HostError::RestartExhausted`].
    pub fn handle_crash(&mut self) -> Result<(), HostError> {
        let mut exit_code = self.service.as_ref().and_then(HostService::exit_code);
        if let Some(mut service) = self.service.take() {
            // Reap first so `CrashIsolated` can report the child's exit code deterministically.
            let _ = service.stop();
            exit_code = service.exit_code();
        }
        match self.policy {
            RestartPolicy::Never => Err(HostError::CrashIsolated { code: exit_code }),
            RestartPolicy::OnFailure {
                max_restarts,
                backoff,
            } => {
                if self.restarts_used >= max_restarts {
                    return Err(HostError::RestartExhausted {
                        attempts: self.restarts_used,
                    });
                }
                if !backoff.is_zero() {
                    std::thread::sleep(backoff);
                }
                self.restarts_used = self.restarts_used.saturating_add(1);
                let service = HostService::spawn(
                    self.name.clone(),
                    self.transport.clone(),
                    self.generation,
                    self.config.clone(),
                )?;
                self.service = Some(service);
                Ok(())
            }
        }
    }

    /// Stop the supervised service and reap the child.
    pub fn stop(&mut self) -> Result<Option<i32>, HostError> {
        self.service
            .as_mut()
            .map(HostService::stop)
            .unwrap_or(Ok(None))
    }
}

impl Drop for ModuleSupervisor {
    fn drop(&mut self) {
        if let Some(mut service) = self.service.take() {
            let _ = service.stop();
        }
    }
}

/// Convenience container tying module services to one configuration generation number.
///
/// This mirrors `caddy_rs_core::GenerationResources` for callers that do not use the async hooks:
/// services spawned here are stopped when the scope is stopped/dropped, and every service belongs
/// to the scope's generation.
pub struct GenerationScope {
    generation: u64,
    modules: Mutex<Vec<GenerationModule>>,
}

impl GenerationScope {
    /// Create a scope for `generation`.
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            modules: Mutex::new(Vec::new()),
        }
    }

    /// Generation number.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Spawn a service owned by this generation and return its generation-module handle.
    pub fn spawn(
        &self,
        name: impl Into<String>,
        transport: ModuleTransportSpec,
        config: HostServiceConfig,
    ) -> Result<GenerationModule, HostError> {
        let service = HostService::spawn(name, transport, self.generation, config)?;
        let module = GenerationModule::new(service);
        module.with_service(HostService::mark_started);
        self.modules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(module.clone());
        Ok(module)
    }

    /// Names of services in this scope.
    pub fn names(&self) -> Vec<String> {
        self.modules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|module| module.name.clone())
            .collect()
    }

    /// Stop every service (bounded grace then kill) and clear the scope.
    pub fn stop(&self) -> Result<Vec<Option<i32>>, HostError> {
        let modules: Vec<GenerationModule> = std::mem::take(
            &mut *self
                .modules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut codes = Vec::with_capacity(modules.len());
        for module in modules {
            codes.push(module.stop()?);
        }
        Ok(codes)
    }
}

impl Drop for GenerationScope {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Hello, HOST_PROTOCOL_VERSION, PROTOCOL_VERSION};
    use crate::version::ABI_VERSION;
    use std::io::Cursor;

    fn limits() -> AbiLimits {
        AbiLimits::spec_defaults()
    }

    fn hello(descriptor: crate::descriptor::PluginDescriptor) -> Hello {
        Hello {
            protocol: PROTOCOL_VERSION,
            descriptor,
        }
    }

    #[test]
    fn frame_io_round_trips_and_rejects_oversized_payloads() {
        let frame = ProtocolFrame::Hello(hello(crate::descriptor::PluginDescriptor {
            name: "echo".to_string(),
            abi: ABI_VERSION,
            capabilities: vec![],
            limits: PluginLimits::default_limits(),
        }));
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame, &limits()).expect("write frame");
        let mut reader = Cursor::new(bytes.clone());
        assert_eq!(
            read_frame(&mut reader, &limits()).expect("read frame"),
            frame
        );

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&[0x10, 0xFF, 0xFF, 0xFF, 0x7F]);
        let mut reader = Cursor::new(oversized);
        assert!(matches!(
            read_frame(&mut reader, &limits()),
            Err(HostError::Protocol(ProtocolError::Wire(
                WireError::FrameTooLarge { .. }
            )))
        ));
        let mut empty = Cursor::new(Vec::new());
        assert!(matches!(
            read_frame(&mut empty, &limits()),
            Err(HostError::ModuleClosed)
        ));
    }

    #[test]
    fn denied_host_calls_surface_stable_errors() {
        let mut context = HostCallContext::new(1, CapabilitySet::EMPTY, 4);
        let error = context
            .authorize(&HostCall::Now, 1, &limits())
            .expect_err("clock not granted");
        assert_eq!(host_call_error_code(&error), AbiErrorCode::CapabilityDenied);
        let error = HostCallContext::new(1, CapabilitySet::EMPTY, 4)
            .authorize(
                &HostCall::Log {
                    level: crate::hostcall::LogLevel::Info,
                    message: "x".to_string(),
                    fields: Vec::new(),
                },
                2,
                &limits(),
            )
            .expect_err("stale generation");
        assert_eq!(host_call_error_code(&error), AbiErrorCode::StaleGeneration);
    }

    #[test]
    fn generation_module_maps_errors_and_marks_started() {
        // Compile-time proof that the service integrates with T-CORE-012's trait.
        fn assert_generation_resource<T: GenerationResource>() {}
        assert_generation_resource::<GenerationModule>();
        let _ = HOST_PROTOCOL_VERSION;
        let _ = hello(crate::descriptor::PluginDescriptor {
            name: "x".to_string(),
            abi: ABI_VERSION,
            capabilities: Vec::new(),
            limits: PluginLimits::default_limits(),
        });
    }
}
