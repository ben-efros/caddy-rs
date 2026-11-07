//! In-process WASM host runtime (T-PLUG-011).
//!
//! This module implements the host side of the in-process ABI from [`crate::bridge`] on top of
//! Wasmtime. It is compiled only with the default-on `wasm-runtime` feature; `default-features =
//! false` keeps the pure wire-contract crate (used by the out-of-tree template) free of Wasmtime.
//!
//! # Calling convention
//!
//! The in-process ABI document leaves the guest call mechanism open. This runtime defines the
//! smallest concrete convention (also documented in `docs/PLUGIN-ABI.md`):
//!
//! * Guest exports: `memory`, `alloc(len: u32) -> u32`, and
//!   `handle_request(ptr: u32, len: u32) -> i64`.
//! * The host writes a sequence of [`BridgeFrame`] request frames (`REQUEST_HEAD`, body chunks,
//!   `REQUEST_END`) into guest memory at `alloc(len)` and calls `handle_request`.
//! * The guest returns a packed `i64`: non-negative means `(response_ptr << 32) | response_len`,
//!   pointing at a sequence of response frames (`RESPONSE_HEAD`, chunks, `RESPONSE_END`); a
//!   negative value is `-(AbiErrorCode)` and fails the invocation with that stable code.
//! * Guest imports `caddy.host_call(call_ptr, call_len, out_ptr, out_len) -> i64`: the guest places
//!   a [`HostCall`] payload at `call_ptr/call_len`, offers an output buffer at `out_ptr/out_len`,
//!   and the host returns the encoded [`HostCallResult`] length written to the output buffer, or a
//!   negative `AbiErrorCode` on denial/failure. Calls are authorized against the negotiated
//!   capability set, generation, argument limits and per-request budget before dispatch.
//!
//! # Limits
//!
//! * **Fuel**: `Config::consume_fuel(true)`; every request starts with `fuel_per_request`.
//!   `Trap::OutOfFuel` becomes [`WasmError::FuelExhausted`].
//! * **Wall clock**: epoch interruption with a one-shot timer per request; `Trap::Interrupt`
//!   becomes [`WasmError::Timeout`].
//! * **Memory**: `StoreLimits` (max memory bytes, one instance) is installed as the store limiter.
//! * **Bodies/module size**: request/response body caps and a maximum module byte size are checked
//!   by the host; oversized input is a typed error before compilation/instantiation or call.
//!
//! Every failure is a typed [`WasmError`] (mapped to an [`AbiErrorCode`]); no failure path panics or
//! takes down the host. WASI is **not** linked (no ambient filesystem/network/clock); the component
//! model is not used (core modules only). Host-call implementations are injected through
//! [`HostCallProvider`]; the default provider implements log/now/config (empty snapshot), uses
//! `/dev/urandom` for random on Unix, and reports `http_client` as a typed host failure (a host
//! embedding the runtime should inject a generation-scoped HTTP client).

use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wasmtime::{
    Caller, Config, Engine, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, TypedFunc,
};

use crate::bridge::{AbiLimits, BodyMode, BridgeFrame, BridgeHeaders, RequestHead, ResponseHead};
use crate::capability::{CapabilityPolicy, CapabilitySet};
use crate::descriptor::{NegotiatedPlugin, PluginDescriptor};
use crate::encoding::{Reader, Writer};
use crate::error::{AbiError, AbiErrorCode, HostCallError};
use crate::hostcall::{HostCall, HostCallContext, HostCallResult, LogLevel, MAX_RANDOM_BYTES};
use crate::version::ABI_VERSION;

/// Default maximum module size accepted for compilation (16 MiB).
pub const DEFAULT_MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;
/// Default fuel budget per request.
pub const DEFAULT_FUEL_PER_REQUEST: u64 = 10_000_000;
/// Default wall-clock timeout per request.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Default guest memory limit (64 MiB).
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Default request body cap (64 MiB, the ABI announced-body hard cap).
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Host-call implementations backing the in-process ABI.
///
/// The runtime calls these only after `HostCallContext::authorize` succeeds, so implementations can
/// assume the capability, generation, argument limits and budget were checked.
pub trait HostCallProvider: Send + Sync {
    /// Emit a log record (capability `log`).
    fn log(
        &self,
        level: LogLevel,
        message: &str,
        fields: &[(String, String)],
    ) -> Result<(), HostCallError>;
    /// Current Unix time in nanoseconds (capability `clock`).
    fn now(&self) -> Result<u64, HostCallError>;
    /// Cryptographic random bytes of the requested length (capability `random`).
    fn random(&self, len: u32) -> Result<Vec<u8>, HostCallError>;
    /// Perform an outbound HTTP request (capability `http_client`).
    fn http_request(
        &self,
        method: crate::bridge::BridgeMethod,
        url: &str,
        headers: &BridgeHeaders,
        body: &[u8],
    ) -> Result<(u16, BridgeHeaders, Vec<u8>), HostCallError>;
    /// Read a value from the generation's immutable configuration snapshot (capability
    /// `config_read`).
    fn read_config(&self, key: &str) -> Result<Option<String>, HostCallError>;
}

/// Safe default host-call provider for development/tests.
///
/// * `log`: writes to stderr;
/// * `now`: system wall clock;
/// * `random`: `/dev/urandom` on Unix, typed host failure elsewhere;
/// * `http_client`: typed host failure (no ambient network);
/// * `config_read`: `None` (no configuration snapshot wired).
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultHostCalls;

impl HostCallProvider for DefaultHostCalls {
    fn log(
        &self,
        level: LogLevel,
        message: &str,
        fields: &[(String, String)],
    ) -> Result<(), HostCallError> {
        let fields = fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("caddy-rs plugin [{level:?}] {message} {fields}");
        Ok(())
    }

    fn now(&self) -> Result<u64, HostCallError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| HostCallError::HostFailure {
                message: format!("system clock before Unix epoch: {error}"),
            })?;
        u64::try_from(elapsed.as_nanos()).map_err(|_| HostCallError::HostFailure {
            message: "system time does not fit in u64 nanoseconds".to_string(),
        })
    }

    fn random(&self, len: u32) -> Result<Vec<u8>, HostCallError> {
        if len > MAX_RANDOM_BYTES {
            return Err(HostCallError::InvalidArgument {
                message: format!("random length {len} exceeds {MAX_RANDOM_BYTES}"),
            });
        }
        #[cfg(unix)]
        {
            use std::io::Read;
            let mut bytes = vec![0_u8; len as usize];
            let mut file = std::fs::File::open("/dev/urandom").map_err(|error| {
                HostCallError::HostFailure {
                    message: format!("cannot open /dev/urandom: {error}"),
                }
            })?;
            file.read_exact(&mut bytes)
                .map_err(|error| HostCallError::HostFailure {
                    message: format!("cannot read /dev/urandom: {error}"),
                })?;
            Ok(bytes)
        }
        #[cfg(not(unix))]
        {
            Err(HostCallError::HostFailure {
                message: "no cryptographically secure random source is wired on this platform"
                    .to_string(),
            })
        }
    }

    fn http_request(
        &self,
        _method: crate::bridge::BridgeMethod,
        _url: &str,
        _headers: &BridgeHeaders,
        _body: &[u8],
    ) -> Result<(u16, BridgeHeaders, Vec<u8>), HostCallError> {
        Err(HostCallError::HostFailure {
            message: "http_client capability is not wired into this host runtime".to_string(),
        })
    }

    fn read_config(&self, _key: &str) -> Result<Option<String>, HostCallError> {
        Ok(None)
    }
}

/// Configuration for [`WasmRuntime`].
#[derive(Debug, Clone)]
pub struct WasmRuntimeConfig {
    /// ABI wire/argument limits used for frame decoding and host-call validation.
    pub limits: AbiLimits,
    /// Maximum module byte size accepted for compilation.
    pub max_module_bytes: usize,
    /// Fuel budget per request.
    pub fuel_per_request: u64,
    /// Wall-clock timeout per request (zero disables epoch interruption).
    pub request_timeout: Duration,
    /// Maximum guest linear memory bytes.
    pub max_memory_bytes: u64,
    /// Maximum request body bytes (before framing).
    pub max_request_body_bytes: u64,
    /// Maximum response body bytes (after framing/decode).
    pub max_response_body_bytes: u64,
    /// Maximum number of instances per store (guest `memory.grow`/instantiation bound).
    pub max_instances: usize,
}

impl Default for WasmRuntimeConfig {
    fn default() -> Self {
        Self {
            limits: AbiLimits::spec_defaults(),
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            fuel_per_request: DEFAULT_FUEL_PER_REQUEST,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_instances: 1,
        }
    }
}

/// Typed WASM runtime failure. Every variant maps to an [`AbiErrorCode`].
#[derive(Debug)]
pub enum WasmError {
    /// Module bytes were larger than `max_module_bytes`.
    ModuleTooLarge {
        /// Observed size.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Module compilation/validation failed.
    Compile {
        /// Wasmtime error text.
        message: String,
    },
    /// A required guest export is missing or has the wrong type.
    MissingExport {
        /// Export name.
        name: &'static str,
        /// Wasmtime error text.
        message: String,
    },
    /// Instantiation/linking failed (for example an import other than `caddy.host_call`).
    Instantiate {
        /// Wasmtime error text.
        message: String,
    },
    /// Descriptor negotiation/capability grant failed.
    Negotiation {
        /// Stable ABI code.
        code: AbiErrorCode,
        /// Human-readable reason.
        message: String,
    },
    /// Guest returned a negative `AbiErrorCode`.
    GuestAbi {
        /// Code returned by the guest.
        code: AbiErrorCode,
    },
    /// Fuel budget exhausted.
    FuelExhausted,
    /// Wall-clock timeout/epoch interruption.
    Timeout,
    /// Guest trapped for another reason.
    Trap {
        /// Wasmtime trap text.
        message: String,
    },
    /// Guest response was malformed or violated the ABI.
    InvalidResponse {
        /// Human-readable reason.
        message: String,
    },
    /// A request/response body or frame limit was exceeded.
    LimitExceeded {
        /// Limit name.
        field: &'static str,
        /// Observed size.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Host-call handling failed before a result could be produced.
    HostCall {
        /// Stable ABI code.
        code: AbiErrorCode,
        /// Human-readable reason.
        message: String,
    },
    /// A store operation failed (fuel setup, memory access, ...).
    Store {
        /// Wasmtime error text.
        message: String,
    },
}

impl WasmError {
    /// Stable ABI error code for this failure.
    pub const fn abi_code(&self) -> AbiErrorCode {
        match self {
            Self::ModuleTooLarge { .. }
            | Self::LimitExceeded { .. }
            | Self::InvalidResponse { .. }
            | Self::MissingExport { .. } => AbiErrorCode::InvalidRequest,
            Self::Compile { .. } | Self::Instantiate { .. } | Self::Store { .. } => {
                AbiErrorCode::PluginFailed
            }
            Self::Negotiation { code, .. } => *code,
            Self::GuestAbi { code } => *code,
            Self::FuelExhausted => AbiErrorCode::LimitExceeded,
            Self::Timeout => AbiErrorCode::Cancelled,
            Self::Trap { .. } => AbiErrorCode::PluginFailed,
            Self::HostCall { code, .. } => *code,
        }
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleTooLarge { len, max } => {
                write!(formatter, "wasm module is {len} bytes, maximum is {max}")
            }
            Self::Compile { message } => write!(formatter, "wasm compilation failed: {message}"),
            Self::MissingExport { name, message } => {
                write!(
                    formatter,
                    "required guest export `{name}` is missing/invalid: {message}"
                )
            }
            Self::Instantiate { message } => {
                write!(formatter, "wasm instantiation failed: {message}")
            }
            Self::Negotiation { code, message } => {
                write!(formatter, "plugin negotiation failed ({code:?}): {message}")
            }
            Self::GuestAbi { code } => {
                write!(formatter, "guest reported ABI error {code:?}")
            }
            Self::FuelExhausted => write!(formatter, "plugin fuel budget exhausted"),
            Self::Timeout => write!(formatter, "plugin request timed out"),
            Self::Trap { message } => write!(formatter, "plugin trapped: {message}"),
            Self::InvalidResponse { message } => {
                write!(formatter, "invalid plugin response: {message}")
            }
            Self::LimitExceeded { field, len, max } => {
                write!(formatter, "{field} is {len} bytes, maximum is {max}")
            }
            Self::HostCall { code, message } => {
                write!(formatter, "host call failed ({code:?}): {message}")
            }
            Self::Store { message } => write!(formatter, "wasm store error: {message}"),
        }
    }
}

impl std::error::Error for WasmError {}

struct HostState {
    limits: AbiLimits,
    provider: Arc<dyn HostCallProvider>,
    context: HostCallContext,
    store_limits: StoreLimits,
}

/// Compiled WASM runtime: engine + validated module + configuration.
///
/// Compile once per module (or per generation) and instantiate a fresh [`WasmPlugin`] per plugin
/// instance; a plugin instance owns its store and linear memory.
pub struct WasmRuntime {
    engine: Engine,
    module: Module,
    config: WasmRuntimeConfig,
}

impl std::fmt::Debug for WasmRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl WasmRuntime {
    /// Build a deterministic engine and compile `wasm` (WAT is accepted when Wasmtime's `wat`
    /// feature is enabled, which is the default).
    pub fn compile(config: WasmRuntimeConfig, wasm: impl AsRef<[u8]>) -> Result<Self, WasmError> {
        let wasm = wasm.as_ref();
        if wasm.len() > config.max_module_bytes {
            return Err(WasmError::ModuleTooLarge {
                len: wasm.len(),
                max: config.max_module_bytes,
            });
        }
        let mut engine_config = Config::new();
        engine_config.consume_fuel(true);
        engine_config.epoch_interruption(true);
        // Deterministic compilation/sandbox defaults: no threads, no WASI, no component model.
        engine_config.wasm_threads(false);
        engine_config.wasm_reference_types(true);
        engine_config.wasm_simd(true);
        engine_config.wasm_bulk_memory(true);
        let engine = Engine::new(&engine_config).map_err(|error| WasmError::Compile {
            message: error.to_string(),
        })?;
        let module = Module::new(&engine, wasm).map_err(|error| WasmError::Compile {
            message: error.to_string(),
        })?;
        Ok(Self {
            engine,
            module,
            config,
        })
    }

    /// Runtime configuration.
    pub fn config(&self) -> &WasmRuntimeConfig {
        &self.config
    }

    /// Instantiate one plugin instance for `generation`, negotiating the descriptor and denying any
    /// capability the policy does not grant.
    pub fn instantiate(
        &self,
        descriptor: &PluginDescriptor,
        policy: &CapabilityPolicy,
        generation: u64,
        provider: Arc<dyn HostCallProvider>,
    ) -> Result<WasmPlugin, WasmError> {
        let negotiated: NegotiatedPlugin =
            descriptor
                .negotiate(ABI_VERSION, policy)
                .map_err(|error| WasmError::Negotiation {
                    code: match &error {
                        AbiError::Capability(_) => AbiErrorCode::CapabilityDenied,
                        AbiError::Negotiation(_) => AbiErrorCode::Unsupported,
                        _ => AbiErrorCode::InvalidRequest,
                    },
                    message: error.to_string(),
                })?;
        let limits = self.config.limits;
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes as usize)
            .instances(self.config.max_instances)
            .build();
        let budget = negotiated.limits.max_host_calls_per_request;
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                provider,
                context: HostCallContext::new(generation, negotiated.granted, budget),
                store_limits,
            },
        );
        store.limiter(|state| &mut state.store_limits);
        // Epoch interruption defaults to an already-expired deadline; arm it far away until the
        // first request sets its real deadline (instantiation must not trap).
        store.set_epoch_deadline(u64::MAX / 2);
        store
            .set_fuel(self.config.fuel_per_request)
            .map_err(|error| WasmError::Store {
                message: error.to_string(),
            })?;
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        linker
            .func_wrap(
                "caddy",
                "host_call",
                |mut caller: Caller<'_, HostState>,
                 call_ptr: u32,
                 call_len: u32,
                 out_ptr: u32,
                 out_len: u32|
                 -> i64 {
                    host_call_impl(
                        &mut caller,
                        call_ptr as usize,
                        call_len as usize,
                        out_ptr as usize,
                        out_len as usize,
                    )
                },
            )
            .map_err(|error| WasmError::Instantiate {
                message: error.to_string(),
            })?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|error| WasmError::Instantiate {
                message: error.to_string(),
            })?;
        let memory =
            instance
                .get_memory(&mut store, "memory")
                .ok_or_else(|| WasmError::MissingExport {
                    name: "memory",
                    message: "guest must export a linear memory named `memory`".to_string(),
                })?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "alloc")
            .map_err(|error| WasmError::MissingExport {
                name: "alloc",
                message: error.to_string(),
            })?;
        let handle_request = instance
            .get_typed_func::<(u32, u32), i64>(&mut store, "handle_request")
            .map_err(|error| WasmError::MissingExport {
                name: "handle_request",
                message: error.to_string(),
            })?;
        Ok(WasmPlugin {
            engine: self.engine.clone(),
            config: self.config.clone(),
            store,
            instance: Some(instance),
            memory,
            alloc,
            handle_request,
            negotiated,
        })
    }
}

/// One instantiated plugin: store, memory and typed guest entry points.
pub struct WasmPlugin {
    engine: Engine,
    config: WasmRuntimeConfig,
    store: Store<HostState>,
    instance: Option<Instance>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    handle_request: TypedFunc<(u32, u32), i64>,
    negotiated: NegotiatedPlugin,
}

impl std::fmt::Debug for WasmPlugin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmPlugin")
            .field("name", &self.negotiated.name)
            .field("granted", &self.negotiated.granted)
            .finish_non_exhaustive()
    }
}

/// Successful plugin response assembled from ABI response frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmResponse {
    /// Response status.
    pub status: u16,
    /// Response headers.
    pub headers: BridgeHeaders,
    /// Buffered response body.
    pub body: Vec<u8>,
    /// Response trailers.
    pub trailers: BridgeHeaders,
}

impl WasmPlugin {
    /// Negotiated descriptor/session information.
    pub fn negotiated(&self) -> &NegotiatedPlugin {
        &self.negotiated
    }

    /// Granted capabilities.
    pub fn granted(&self) -> CapabilitySet {
        self.negotiated.granted
    }

    /// Invoke the guest once. Fuel is reset, the epoch deadline is armed and every response frame is
    /// validated before being returned. A failure leaves the host healthy; callers can invoke again
    /// or drop the plugin.
    pub fn handle_request(
        &mut self,
        head: RequestHead,
        body: &[u8],
        trailers: BridgeHeaders,
    ) -> Result<WasmResponse, WasmError> {
        if body.len() as u64 > self.config.max_request_body_bytes {
            return Err(WasmError::LimitExceeded {
                field: "request body",
                len: body.len(),
                max: self.config.max_request_body_bytes as usize,
            });
        }
        let mut request_bytes = Vec::new();
        push_frame(
            &mut request_bytes,
            &BridgeFrame::RequestHead(head),
            &self.config.limits,
        )?;
        for chunk in body.chunks(self.config.limits.max_body_chunk.max(1)) {
            push_frame(
                &mut request_bytes,
                &BridgeFrame::RequestBodyChunk(chunk.to_vec()),
                &self.config.limits,
            )?;
        }
        push_frame(
            &mut request_bytes,
            &BridgeFrame::RequestEnd(trailers),
            &self.config.limits,
        )?;

        self.store
            .set_fuel(self.config.fuel_per_request)
            .map_err(|error| WasmError::Store {
                message: error.to_string(),
            })?;

        // Arm the deadline/timer before *any* guest code runs (alloc is guest code too); joining
        // after the call guarantees no timer leaks.
        let timer = if self.config.request_timeout.is_zero() {
            self.store.set_epoch_deadline(u64::MAX / 2);
            None
        } else {
            self.store.set_epoch_deadline(1);
            let (done_tx, done_rx) = mpsc::channel::<()>();
            let engine = self.engine.clone();
            let timeout = self.config.request_timeout;
            let handle = std::thread::spawn(move || {
                if done_rx.recv_timeout(timeout).is_err() {
                    engine.increment_epoch();
                }
            });
            Some((done_tx, handle))
        };

        let request_ptr = self
            .alloc
            .call(&mut self.store, request_bytes.len() as u32)
            .map_err(|error| self.map_call_error(error))?;
        self.memory
            .write(&mut self.store, request_ptr as usize, &request_bytes)
            .map_err(|error| WasmError::Store {
                message: format!("cannot write request into guest memory: {error}"),
            })?;

        let result = self
            .handle_request
            .call(&mut self.store, (request_ptr, request_bytes.len() as u32));

        if let Some((done_tx, handle)) = timer {
            let _ = done_tx.send(());
            let _ = handle.join();
        }
        // Disarm the epoch deadline so no stale increment affects the next invocation.
        self.store.set_epoch_deadline(u64::MAX / 2);

        let packed = result.map_err(|error| self.map_call_error(error))?;
        if packed < 0 {
            let code = u32::try_from(-packed).unwrap_or(u32::MAX);
            let code = AbiErrorCode::from_code(code).ok_or(WasmError::InvalidResponse {
                message: format!("guest returned unknown ABI error code {code}"),
            })?;
            return Err(WasmError::GuestAbi { code });
        }
        let ptr = (packed >> 32) as u32;
        let len = (packed & 0xFFFF_FFFF) as u32;
        if len as usize > self.config.max_response_body_bytes as usize {
            return Err(WasmError::LimitExceeded {
                field: "response buffer",
                len: len as usize,
                max: self.config.max_response_body_bytes as usize,
            });
        }
        let data = self.memory.data(&self.store);
        let start = ptr as usize;
        let end = start.saturating_add(len as usize);
        if end > data.len() {
            return Err(WasmError::InvalidResponse {
                message: format!(
                    "guest response {start}..{end} is outside linear memory ({} bytes)",
                    data.len()
                ),
            });
        }
        let response_bytes = &data[start..end];
        self.decode_response(response_bytes)
    }

    fn map_call_error(&self, error: wasmtime::Error) -> WasmError {
        if let Some(trap) = error.downcast_ref::<Trap>() {
            return match trap {
                Trap::OutOfFuel => WasmError::FuelExhausted,
                Trap::Interrupt => WasmError::Timeout,
                other => WasmError::Trap {
                    message: format!("{other:?}"),
                },
            };
        }
        WasmError::Trap {
            message: error.to_string(),
        }
    }

    fn decode_response(&self, bytes: &[u8]) -> Result<WasmResponse, WasmError> {
        let mut offset = 0;
        let mut head: Option<ResponseHead> = None;
        let mut body = Vec::new();
        let mut trailers: Option<BridgeHeaders> = None;
        while offset < bytes.len() {
            let (frame, consumed) = BridgeFrame::decode(&bytes[offset..], &self.config.limits)
                .map_err(|error| WasmError::InvalidResponse {
                    message: error.to_string(),
                })?;
            offset += consumed;
            match frame {
                BridgeFrame::ResponseHead(response_head) => {
                    if head.is_some() {
                        return Err(WasmError::InvalidResponse {
                            message: "more than one RESPONSE_HEAD frame".to_string(),
                        });
                    }
                    head = Some(response_head);
                }
                BridgeFrame::ResponseBodyChunk(chunk) => {
                    if trailers.is_some() {
                        return Err(WasmError::InvalidResponse {
                            message: "body chunk after RESPONSE_END".to_string(),
                        });
                    }
                    body.extend_from_slice(&chunk);
                    if body.len() as u64 > self.config.max_response_body_bytes {
                        return Err(WasmError::LimitExceeded {
                            field: "response body",
                            len: body.len(),
                            max: self.config.max_response_body_bytes as usize,
                        });
                    }
                }
                BridgeFrame::ResponseEnd(response_trailers) => {
                    if trailers.is_some() {
                        return Err(WasmError::InvalidResponse {
                            message: "more than one RESPONSE_END frame".to_string(),
                        });
                    }
                    trailers = Some(response_trailers);
                }
                non_response => {
                    return Err(WasmError::InvalidResponse {
                        message: format!(
                            "guest sent a non-response frame (tag {})",
                            non_response.tag()
                        ),
                    });
                }
            }
        }
        let head = head.ok_or_else(|| WasmError::InvalidResponse {
            message: "missing RESPONSE_HEAD frame".to_string(),
        })?;
        let trailers = trailers.ok_or_else(|| WasmError::InvalidResponse {
            message: "missing RESPONSE_END frame".to_string(),
        })?;
        // Declared body mode must agree with the buffered body seen.
        match head.body {
            BodyMode::Empty => {
                if !body.is_empty() {
                    return Err(WasmError::InvalidResponse {
                        message: "response declared an empty body but sent bytes".to_string(),
                    });
                }
            }
            BodyMode::Buffered { length } => {
                if body.len() != length as usize {
                    return Err(WasmError::InvalidResponse {
                        message: format!(
                            "response declared {length} buffered bytes but sent {}",
                            body.len()
                        ),
                    });
                }
            }
            BodyMode::Streamed => {}
        }
        Ok(WasmResponse {
            status: head.status,
            headers: head.headers,
            body,
            trailers,
        })
    }
}

impl Drop for WasmPlugin {
    fn drop(&mut self) {
        // Dropping the store releases Wasmtime resources; no host state can escape.
        self.instance.take();
    }
}

fn push_frame(out: &mut Vec<u8>, frame: &BridgeFrame, limits: &AbiLimits) -> Result<(), WasmError> {
    let bytes = frame
        .encode(limits)
        .map_err(|error| WasmError::InvalidResponse {
            message: format!("cannot encode request frame: {error}"),
        })?;
    out.extend_from_slice(&bytes);
    Ok(())
}

fn host_call_error_code(error: &HostCallError) -> AbiErrorCode {
    match error {
        HostCallError::CapabilityDenied { .. } => AbiErrorCode::CapabilityDenied,
        HostCallError::StaleGeneration { .. } => AbiErrorCode::StaleGeneration,
        HostCallError::InvalidArgument { .. } => AbiErrorCode::InvalidRequest,
        HostCallError::CallBudgetExhausted { .. } => AbiErrorCode::LimitExceeded,
        HostCallError::Cancelled => AbiErrorCode::Cancelled,
        HostCallError::HostFailure { .. } => AbiErrorCode::HostFailure,
    }
}

fn host_call_impl(
    caller: &mut Caller<'_, HostState>,
    call_ptr: usize,
    call_len: usize,
    out_ptr: usize,
    out_len: usize,
) -> i64 {
    let Some(memory) = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    else {
        return -i64::from(AbiErrorCode::InvalidRequest.code());
    };
    if call_len > caller.data().limits.max_frame_payload {
        return -i64::from(AbiErrorCode::LimitExceeded.code());
    }
    let mut call_bytes = vec![0_u8; call_len];
    if memory.read(&*caller, call_ptr, &mut call_bytes).is_err() {
        return -i64::from(AbiErrorCode::InvalidRequest.code());
    }
    let mut reader = Reader::new(&call_bytes);
    let call = match HostCall::decode(&mut reader, &caller.data().limits) {
        Ok(call) => {
            if reader.finish().is_err() {
                return -i64::from(AbiErrorCode::InvalidRequest.code());
            }
            call
        }
        Err(_) => return -i64::from(AbiErrorCode::InvalidRequest.code()),
    };
    let generation = caller.data().context.generation();
    let limits = caller.data().limits;
    if let Err(error) = caller
        .data_mut()
        .context
        .authorize(&call, generation, &limits)
    {
        return -i64::from(host_call_error_code(&error).code());
    }
    let provider = caller.data().provider.clone();
    let result = match &call {
        HostCall::Log {
            level,
            message,
            fields,
        } => provider
            .log(*level, message, fields)
            .map(|()| HostCallResult::Logged),
        HostCall::Now => provider
            .now()
            .map(|unix_nanos| HostCallResult::Now { unix_nanos }),
        HostCall::Random { len } => provider
            .random(*len)
            .map(|bytes| HostCallResult::Random { bytes }),
        HostCall::HttpRequest {
            method,
            url,
            headers,
            body,
        } => provider
            .http_request(method.clone(), url, headers, body)
            .map(|(status, headers, body)| HostCallResult::HttpResponse {
                status,
                headers,
                body,
            }),
        HostCall::ReadConfig { key } => provider
            .read_config(key)
            .map(|value| HostCallResult::ConfigValue { value }),
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => return -i64::from(host_call_error_code(&error).code()),
    };
    let mut payload = Writer::new();
    if let Err(error) = result.encode(&mut payload, &limits) {
        let _ = error;
        return -i64::from(AbiErrorCode::InvalidRequest.code());
    }
    let bytes = payload.into_vec();
    if bytes.len() > out_len {
        return -i64::from(AbiErrorCode::LimitExceeded.code());
    }
    if memory.write(&mut *caller, out_ptr, &bytes).is_err() {
        return -i64::from(AbiErrorCode::InvalidRequest.code());
    }
    bytes.len() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_too_large_is_rejected() {
        let config = WasmRuntimeConfig {
            max_module_bytes: 8,
            ..WasmRuntimeConfig::default()
        };
        let error = WasmRuntime::compile(config, b"this is not wasm").expect_err("oversized");
        assert!(matches!(error, WasmError::ModuleTooLarge { .. }));
        assert_eq!(error.abi_code(), AbiErrorCode::InvalidRequest);
    }

    #[test]
    fn plain_wat_garbage_is_a_typed_compile_error() {
        let error = WasmRuntime::compile(WasmRuntimeConfig::default(), b"(module")
            .expect_err("invalid wat");
        assert!(matches!(error, WasmError::Compile { .. }));
        assert_eq!(error.abi_code(), AbiErrorCode::PluginFailed);
    }
}
