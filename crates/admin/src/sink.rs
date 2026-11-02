//! Access-log sink and encoder (plan task T-ADMIN-020/T-ADMIN-022).
//!
//! [`AccessLogEntry`](crate::AccessLogEntry) models one Caddy-compatible structured access-log
//! record. This module turns that record into bytes and writes it to a configured destination:
//!
//! ```text
//! AccessLogEntry --(redaction + field selection)--> JSON --(sampling)--> sink --(buffered)--> writer
//! ```
//!
//! * [`AccessLogEncoder`] applies the [`AccessLogConfig`] redaction/field-selection rules and
//!   produces one compact JSON object followed by `\n` (one line per entry, zap's console/JSON
//!   framing).
//! * [`AccessLogSink`] owns the destination: `stdout`, `stderr`, a file appended to
//!   `filename`, or `discard`, with an optional [`SamplingConfig`] applied at emission and a
//!   `BufWriter` for amortised writes. It is a cheap, cloneable, thread-safe handle: clones share
//!   the destination, sampling state and statistics.
//! * [`AccessLogSink::flush`] and [`AccessLogSink::close`] expose explicit durability control;
//!   `close` is idempotent and makes later emissions fail with a located error instead of silently
//!   dropping records. `Drop` performs a best-effort flush.
//!
//! ## Log rotation
//!
//! This sink deliberately does **not** rotate files: Caddy's `roll_*` writer options are not
//! implemented (tracked as a follow-up; see the task report/DIV). Operators rotate externally
//! (logrotate/container runtime) or reopen the sink; the file is opened in append mode so external
//! rotation + reopen does not truncate it.
//!
//! ## Errors
//!
//! Every failure is located: [`AccessLogError`] names the offending configuration path
//! (`writer.filename`, `writer.buffer_bytes`, `sampling.*`, `redaction.*`) or the failing
//! operation (`writer`, `entry`, `sink`), so a bad access-log configuration fails loudly at
//! startup rather than silently dropping records at request time.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::access_log::{
    AccessLogConfig, AccessLogEntry, AccessLogError, AccessLogSampler, SamplingConfig,
};

/// Default [`BufWriter`] capacity for an access-log sink (32 KiB).
pub const DEFAULT_ACCESS_LOG_BUFFER_BYTES: usize = 32 * 1024;

/// Where an [`AccessLogSink`] writes entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogOutput {
    /// Write to the process's standard error stream (Caddy's default log writer).
    #[default]
    Stderr,
    /// Write to the process's standard output stream.
    Stdout,
    /// Encode (and sample) but discard the bytes. Useful to disable output without changing the
    /// encoder/sampling configuration, mirroring Caddy's `discard` writer.
    Discard,
    /// Append to [`AccessLogSinkConfig::filename`].
    File,
}

impl AccessLogOutput {
    /// Stable lowercase name (Caddy's `writer.output` spelling).
    pub fn as_str(self) -> &'static str {
        match self {
            AccessLogOutput::Stderr => "stderr",
            AccessLogOutput::Stdout => "stdout",
            AccessLogOutput::Discard => "discard",
            AccessLogOutput::File => "file",
        }
    }
}

/// Configuration for one access-log sink.
///
/// This is the admin-crate-facing equivalent of Caddy's `logging.logs[].writer` plus
/// `logging.logs[].encoder` selection; the server runtime is responsible for translating the
/// configuration document into it (a follow-up, see the task report).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLogSinkConfig {
    /// Destination of the encoded entries.
    #[serde(default)]
    pub output: AccessLogOutput,
    /// Path appended to when `output` is [`AccessLogOutput::File`]. Ignored (as in Caddy) for the
    /// other destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<PathBuf>,
    /// Field selection, redaction and sampling policy.
    #[serde(default)]
    pub encoder: AccessLogConfig,
    /// Capacity of the write buffer in bytes.
    #[serde(default = "default_buffer_bytes")]
    pub buffer_bytes: usize,
}

fn default_buffer_bytes() -> usize {
    DEFAULT_ACCESS_LOG_BUFFER_BYTES
}

impl Default for AccessLogSinkConfig {
    fn default() -> Self {
        Self {
            output: AccessLogOutput::Stderr,
            filename: None,
            encoder: AccessLogConfig::default(),
            buffer_bytes: DEFAULT_ACCESS_LOG_BUFFER_BYTES,
        }
    }
}

impl AccessLogSinkConfig {
    /// Build a sink configuration writing to a file.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            output: AccessLogOutput::File,
            filename: Some(path.into()),
            ..Self::default()
        }
    }

    /// Validate the sink configuration, returning the first located problem.
    pub fn validate(&self) -> Result<(), AccessLogError> {
        self.encoder.validate()?;
        if self.buffer_bytes == 0 {
            return Err(AccessLogError::new(
                "writer.buffer_bytes",
                "must be greater than zero",
            ));
        }
        if self.output == AccessLogOutput::File {
            match &self.filename {
                None => {
                    return Err(AccessLogError::new(
                        "writer.filename",
                        "file output requires a filename",
                    ))
                }
                Some(path) if path.as_os_str().is_empty() => {
                    return Err(AccessLogError::new("writer.filename", "must not be empty"))
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

/// The outcome of [`AccessLogSink::emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// The entry was encoded and written to the destination.
    Written,
    /// The sampling policy suppressed the entry; nothing was encoded or written.
    SampledOut,
}

/// A snapshot of sink activity, useful for diagnostics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessLogSinkStats {
    /// Entries encoded and accepted by the sink (buffered counts as accepted).
    pub written: u64,
    /// Entries suppressed by sampling.
    pub sampled_out: u64,
    /// Encoded bytes accepted by the destination.
    pub bytes_written: u64,
    /// Write/flush failures observed (each also returned to the caller).
    pub write_errors: u64,
    /// Explicit flushes requested after the sink was created.
    pub flushes: u64,
}

/// Encodes [`AccessLogEntry`] values with redaction and field selection applied.
#[derive(Debug, Clone)]
pub struct AccessLogEncoder {
    config: AccessLogConfig,
}

impl AccessLogEncoder {
    /// Validate `config` and build an encoder.
    pub fn new(config: AccessLogConfig) -> Result<Self, AccessLogError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The encoder's configuration (field selection, redaction, sampling policy).
    pub fn config(&self) -> &AccessLogConfig {
        &self.config
    }

    /// Encode one entry as a single compact JSON line (including the trailing `\n`).
    ///
    /// Redaction runs before field selection, so a field selected out can never leak a redacted
    /// value and a redaction rule always sees the full record.
    pub fn encode_line(&self, entry: &AccessLogEntry) -> Result<Vec<u8>, AccessLogError> {
        let rendered = entry.render(&self.config)?;
        let mut line = serde_json::to_vec(&rendered)
            .map_err(|error| AccessLogError::new("entry", format!("cannot encode: {error}")))?;
        line.push(b'\n');
        Ok(line)
    }

    /// Encode one entry to a compact JSON string (without the trailing newline).
    pub fn encode_string(&self, entry: &AccessLogEntry) -> Result<String, AccessLogError> {
        let rendered = entry.render(&self.config)?;
        serde_json::to_string(&rendered)
            .map_err(|error| AccessLogError::new("entry", format!("cannot encode: {error}")))
    }
}

enum SinkTarget {
    Stdout(BufWriter<io::Stdout>),
    Stderr(BufWriter<io::Stderr>),
    Discard,
    File(BufWriter<File>),
    Custom(BufWriter<Box<dyn Write + Send>>),
}

impl fmt::Debug for SinkTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            SinkTarget::Stdout(_) => "AccessLogTarget::Stdout",
            SinkTarget::Stderr(_) => "AccessLogTarget::Stderr",
            SinkTarget::Discard => "AccessLogTarget::Discard",
            SinkTarget::File(_) => "AccessLogTarget::File",
            SinkTarget::Custom(_) => "AccessLogTarget::Custom",
        })
    }
}

impl SinkTarget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            SinkTarget::Stdout(writer) => writer.write_all(bytes),
            SinkTarget::Stderr(writer) => writer.write_all(bytes),
            SinkTarget::Discard => Ok(()),
            SinkTarget::File(writer) => writer.write_all(bytes),
            SinkTarget::Custom(writer) => writer.write_all(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            SinkTarget::Stdout(writer) => writer.flush(),
            SinkTarget::Stderr(writer) => writer.flush(),
            SinkTarget::Discard => Ok(()),
            SinkTarget::File(writer) => writer.flush(),
            SinkTarget::Custom(writer) => writer.flush(),
        }
    }

    fn is_discard(&self) -> bool {
        matches!(self, SinkTarget::Discard)
    }
}

struct SinkState {
    target: SinkTarget,
}

struct SinkInner {
    encoder: AccessLogEncoder,
    sampler: Option<Mutex<AccessLogSampler>>,
    state: Mutex<SinkState>,
    closed: AtomicBool,
    written: AtomicU64,
    sampled_out: AtomicU64,
    bytes_written: AtomicU64,
    write_errors: AtomicU64,
    flushes: AtomicU64,
}

/// A cheap, cloneable, thread-safe access-log sink.
///
/// Cloning shares the destination, sampling window and statistics, so the server can hand a clone
/// to each request task and keep one for shutdown (`close` on any clone closes the shared sink).
#[derive(Clone)]
pub struct AccessLogSink {
    inner: Arc<SinkInner>,
}

impl fmt::Debug for AccessLogSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessLogSink")
            .field("config", self.inner.encoder.config())
            .field("closed", &self.is_closed())
            .field("stats", &self.stats())
            .finish()
    }
}

impl AccessLogSink {
    /// Build a sink from a validated configuration.
    ///
    /// Returns a located [`AccessLogError`] when the configuration is invalid or the file cannot be
    /// opened (for example a missing parent directory or insufficient permissions); startup should
    /// fail rather than silently dropping access records.
    pub fn from_config(config: &AccessLogSinkConfig) -> Result<Self, AccessLogError> {
        config.validate()?;
        let encoder = AccessLogEncoder::new(config.encoder.clone())?;
        let capacity = config.buffer_bytes;
        let target = match config.output {
            AccessLogOutput::Stdout => {
                SinkTarget::Stdout(BufWriter::with_capacity(capacity, io::stdout()))
            }
            AccessLogOutput::Stderr => {
                SinkTarget::Stderr(BufWriter::with_capacity(capacity, io::stderr()))
            }
            AccessLogOutput::Discard => SinkTarget::Discard,
            AccessLogOutput::File => {
                let path = config
                    .filename
                    .as_ref()
                    .expect("validated file output has a filename");
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|error| {
                        AccessLogError::new(
                            "writer.filename",
                            format!("cannot open `{}`: {error}", path.display()),
                        )
                    })?;
                SinkTarget::File(BufWriter::with_capacity(capacity, file))
            }
        };
        let sampler = match &config.encoder.sampling {
            Some(sampling) => Some(Mutex::new(AccessLogSampler::new(
                sampling.clone(),
                Instant::now(),
            )?)),
            None => None,
        };
        Ok(Self {
            inner: Arc::new(SinkInner {
                encoder,
                sampler,
                state: Mutex::new(SinkState { target }),
                closed: AtomicBool::new(false),
                written: AtomicU64::new(0),
                sampled_out: AtomicU64::new(0),
                bytes_written: AtomicU64::new(0),
                write_errors: AtomicU64::new(0),
                flushes: AtomicU64::new(0),
            }),
        })
    }

    /// Build a sink writing to any [`Write`] implementation (tests, custom transports).
    ///
    /// The writer is wrapped in a buffer sized by `config.buffer_bytes`. This is also how the
    /// server can direct access logs to a destination the admin crate does not model.
    pub fn to_writer(
        writer: impl Write + Send + 'static,
        config: AccessLogConfig,
    ) -> Result<Self, AccessLogError> {
        let sink_config = AccessLogSinkConfig {
            encoder: config,
            ..AccessLogSinkConfig::default()
        };
        sink_config.validate()?;
        let encoder = AccessLogEncoder::new(sink_config.encoder.clone())?;
        let sampler = match &sink_config.encoder.sampling {
            Some(sampling) => Some(Mutex::new(AccessLogSampler::new(
                sampling.clone(),
                Instant::now(),
            )?)),
            None => None,
        };
        Ok(Self {
            inner: Arc::new(SinkInner {
                encoder,
                sampler,
                state: Mutex::new(SinkState {
                    target: SinkTarget::Custom(BufWriter::with_capacity(
                        sink_config.buffer_bytes,
                        Box::new(writer),
                    )),
                }),
                closed: AtomicBool::new(false),
                written: AtomicU64::new(0),
                sampled_out: AtomicU64::new(0),
                bytes_written: AtomicU64::new(0),
                write_errors: AtomicU64::new(0),
                flushes: AtomicU64::new(0),
            }),
        })
    }

    /// Build a sink that encodes and samples but discards the bytes.
    pub fn discard(config: AccessLogConfig) -> Result<Self, AccessLogError> {
        Self::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::Discard,
            encoder: config,
            ..AccessLogSinkConfig::default()
        })
    }

    /// The encoder in use (redaction/field-selection/sampling policy).
    pub fn encoder(&self) -> &AccessLogEncoder {
        &self.inner.encoder
    }

    /// The sink configuration's sampling policy, if sampling is enabled.
    pub fn sampling(&self) -> Option<&SamplingConfig> {
        self.inner.encoder.config().sampling.as_ref()
    }

    /// Whether [`AccessLogSink::close`] has been called.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// A consistent-enough snapshot of sink activity.
    pub fn stats(&self) -> AccessLogSinkStats {
        AccessLogSinkStats {
            written: self.inner.written.load(Ordering::Relaxed),
            sampled_out: self.inner.sampled_out.load(Ordering::Relaxed),
            bytes_written: self.inner.bytes_written.load(Ordering::Relaxed),
            write_errors: self.inner.write_errors.load(Ordering::Relaxed),
            flushes: self.inner.flushes.load(Ordering::Relaxed),
        }
    }

    /// Encode and write one entry, applying the sampling policy.
    ///
    /// Returns [`EmitOutcome::SampledOut`] when the sampling policy suppressed the record and
    /// [`AccessLogError`] when encoding or writing failed (or the sink is closed).
    pub fn emit(&self, entry: &AccessLogEntry) -> Result<EmitOutcome, AccessLogError> {
        if self.is_closed() {
            return Err(AccessLogError::new(
                "sink",
                "cannot emit an access log entry after close",
            ));
        }
        if let Some(sampler) = &self.inner.sampler {
            let should_log = sampler
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .should_log(Instant::now(), entry.level, &entry.msg);
            if !should_log {
                self.inner.sampled_out.fetch_add(1, Ordering::Relaxed);
                return Ok(EmitOutcome::SampledOut);
            }
        }
        let line = self.inner.encoder.encode_line(entry)?;
        self.write_bytes(&line)?;
        Ok(EmitOutcome::Written)
    }

    /// Flush buffered entries to the destination.
    ///
    /// Flushing a closed sink is a no-op (close already flushed); flushing an open sink returns a
    /// located error if the underlying writer fails.
    pub fn flush(&self) -> Result<(), AccessLogError> {
        if self.is_closed() {
            return Ok(());
        }
        self.inner.flushes.fetch_add(1, Ordering::Relaxed);
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.target.flush().map_err(|error| {
            self.inner.write_errors.fetch_add(1, Ordering::Relaxed);
            AccessLogError::new("writer", format!("cannot flush access log: {error}"))
        })
    }

    /// Flush and close the sink. Idempotent.
    ///
    /// After a successful close, [`AccessLogSink::emit`] fails with a located error so records can
    /// never be silently dropped. A failed flush still closes the sink (the failure is returned)
    /// because the destination is no longer reliable.
    pub fn close(&self) -> Result<(), AccessLogError> {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.target.flush().map_err(|error| {
            self.inner.write_errors.fetch_add(1, Ordering::Relaxed);
            AccessLogError::new(
                "writer",
                format!("cannot flush access log on close: {error}"),
            )
        })
    }

    fn write_bytes(&self, bytes: &[u8]) -> Result<(), AccessLogError> {
        // Check again under the write lock so an emit racing with close cannot write after close.
        if self.is_closed() {
            return Err(AccessLogError::new(
                "sink",
                "cannot emit an access log entry after close",
            ));
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.target.write(bytes).map_err(|error| {
            self.inner.write_errors.fetch_add(1, Ordering::Relaxed);
            AccessLogError::new("writer", format!("cannot write access log entry: {error}"))
        })?;
        self.inner.written.fetch_add(1, Ordering::Relaxed);
        // A discard sink still validates/encodes the entry, but no bytes reach a destination.
        let delivered = if state.target.is_discard() {
            0
        } else {
            bytes.len() as u64
        };
        self.inner
            .bytes_written
            .fetch_add(delivered, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for SinkInner {
    fn drop(&mut self) {
        // Best effort only: Drop cannot report a failure. Explicit `close()` is the supported way
        // to observe a flush error at shutdown.
        if !self.closed.load(Ordering::Acquire) {
            if let Ok(state) = self.state.get_mut() {
                let _ = state.target.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::Value;

    use super::*;
    use crate::access_log::{
        AccessLogEntry, AccessLogRequest, HeaderRedaction, HeaderTarget, RedactionPolicy, REDACTED,
    };

    /// A writer that records bytes/flushes in shared buffers for assertions.
    #[derive(Clone, Default)]
    struct RecordingWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<AtomicUsize>,
        fail: bool,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self::default()
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn flushes(&self) -> usize {
            self.flushes.load(Ordering::Acquire)
        }
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail {
                return Err(io::Error::other("injected writer failure"));
            }
            self.bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail {
                return Err(io::Error::other("injected flush failure"));
            }
            self.flushes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn entry(body: &str, status: u16) -> AccessLogEntry {
        let mut request = AccessLogRequest::new("GET", "example.com", "/hello?token=secret");
        request.headers.insert(
            "Authorization".to_string(),
            vec!["Bearer super-secret".to_string()],
        );
        request
            .headers
            .insert("Cookie".to_string(), vec!["session=abc123".to_string()]);
        request
            .headers
            .insert("Accept".to_string(), vec!["text/plain".to_string()]);
        AccessLogEntry::new(request)
            .with_status(status)
            .with_duration(std::time::Duration::from_millis(3))
            .with_size(body.len() as u64)
    }

    fn parse_lines(bytes: &[u8]) -> Vec<Value> {
        let text = std::str::from_utf8(bytes).expect("utf-8 log output");
        let mut entries = Vec::new();
        for line in text.lines() {
            assert!(!line.is_empty(), "blank log line");
            entries.push(serde_json::from_str(line).expect("each log line is JSON"));
        }
        entries
    }

    fn sink_with_recorder(config: AccessLogConfig) -> (AccessLogSink, RecordingWriter) {
        let writer = RecordingWriter::new();
        let sink = AccessLogSink::to_writer(writer.clone(), config).expect("sink");
        (sink, writer)
    }

    // -- encoder ---------------------------------------------------------------------------

    #[test]
    fn encoder_applies_redaction_and_field_selection() {
        let encoder = AccessLogEncoder::new(AccessLogConfig {
            exclude: vec![
                crate::AccessLogField::RespHeaders,
                crate::AccessLogField::Upstream,
            ],
            redaction: RedactionPolicy {
                headers: vec![HeaderRedaction::Replace {
                    header: "Accept".to_string(),
                    value: "text/*".to_string(),
                    target: HeaderTarget::Request,
                }],
                query_parameters: vec!["token".to_string()],
                cookies: vec!["session".to_string()],
            },
            ..AccessLogConfig::default()
        })
        .expect("encoder");

        let mut log_entry = entry("hello", 200);
        log_entry
            .resp_headers
            .insert("Content-Type".to_string(), vec!["text/plain".to_string()]);
        let line = encoder.encode_line(&log_entry).expect("encode");
        assert_eq!(*line.last().expect("newline"), b'\n');
        let value: Value = serde_json::from_slice(&line).expect("json");

        // Credential redaction is on by default; headers are value arrays.
        assert_eq!(
            value["request"]["headers"]["Authorization"],
            Value::Array(vec![Value::String(REDACTED.to_string())])
        );
        assert_eq!(
            value["request"]["headers"]["Cookie"],
            Value::Array(vec![Value::String(REDACTED.to_string())])
        );
        // Explicit replace rule.
        assert_eq!(
            value["request"]["headers"]["Accept"],
            Value::Array(vec![Value::String("text/*".to_string())])
        );
        // Query parameter and cookie-value redaction.
        assert_eq!(
            value["request"]["uri"],
            Value::String("/hello?token=REDACTED".to_string())
        );
        // Field selection: excluded fields are absent, fundamental fields stay.
        assert!(value.get("resp_headers").is_none());
        assert!(value.get("upstream").is_none());
        assert!(value.get("ts").is_some());
        assert!(value.get("level").is_some());
        assert!(value.get("logger").is_some());
        assert!(value.get("msg").is_some());
    }

    #[test]
    fn encoder_rejects_invalid_redaction_configuration() {
        let error = AccessLogEncoder::new(AccessLogConfig {
            redaction: RedactionPolicy {
                headers: vec![HeaderRedaction::Redact {
                    header: "not a header".to_string(),
                    target: HeaderTarget::Both,
                }],
                ..RedactionPolicy::default()
            },
            ..AccessLogConfig::default()
        })
        .expect_err("invalid header name");
        assert_eq!(error.path(), "redaction.headers[0].header");
    }

    // -- sink writing ---------------------------------------------------------------------

    #[test]
    fn sink_writes_one_json_line_per_entry_and_flushes() {
        let (sink, writer) = sink_with_recorder(AccessLogConfig::default());
        assert_eq!(
            sink.emit(&entry("hello", 200)).unwrap(),
            EmitOutcome::Written
        );
        assert_eq!(
            sink.emit(&entry("world", 500)).unwrap(),
            EmitOutcome::Written
        );
        // Buffered: nothing necessarily visible before flush, but flush must make it visible.
        sink.flush().expect("flush");
        assert!(writer.flushes() >= 1);

        let entries = parse_lines(&writer.bytes());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["request"]["method"], "GET");
        assert_eq!(entries[0]["request"]["headers"]["Accept"][0], "text/plain");
        assert_eq!(entries[1]["status"], 500);
        assert_eq!(entries[1]["level"], "error");
        assert_eq!(
            entries[0]["request"]["headers"]["Authorization"][0],
            REDACTED
        );

        let stats = sink.stats();
        assert_eq!(stats.written, 2);
        assert_eq!(stats.sampled_out, 0);
        assert!(stats.bytes_written > 0);
        assert_eq!(stats.write_errors, 0);
    }

    #[test]
    fn close_flushes_and_rejects_later_emissions() {
        let (sink, writer) = sink_with_recorder(AccessLogConfig::default());
        sink.emit(&entry("before close", 200)).unwrap();
        sink.close().expect("close");
        assert!(sink.is_closed());
        assert_eq!(writer.flushes(), 1);
        assert_eq!(parse_lines(&writer.bytes()).len(), 1);

        let error = sink.emit(&entry("after close", 200)).expect_err("closed");
        assert_eq!(error.path(), "sink");
        assert!(error.message().contains("after close"), "{error}");
        // close is idempotent and flush after close is a no-op.
        sink.close().expect("second close");
        sink.flush().expect("flush after close");
        assert_eq!(writer.flushes(), 1);
        assert_eq!(parse_lines(&writer.bytes()).len(), 1);
    }

    #[test]
    fn write_failures_surface_on_flush_and_are_located() {
        // The sink is buffered: a small entry is accepted into the buffer and the transport failure
        // is reported by the explicit flush (or close), which is the durability boundary.
        let writer = RecordingWriter::failing();
        let sink =
            AccessLogSink::to_writer(writer.clone(), AccessLogConfig::default()).expect("sink");
        assert_eq!(
            sink.emit(&entry("hello", 200)).expect("buffered write"),
            EmitOutcome::Written
        );
        let error = sink.flush().expect_err("flush fails");
        assert_eq!(error.path(), "writer");
        assert!(
            error.message().contains("injected writer failure"),
            "{error}"
        );
        assert_eq!(sink.stats().write_errors, 1);
    }

    #[test]
    fn close_reports_flush_failure_and_still_closes() {
        let writer = RecordingWriter::failing();
        let sink = AccessLogSink::to_writer(writer, AccessLogConfig::default()).expect("sink");
        sink.emit(&entry("hello", 200)).expect("buffered write");
        let error = sink.close().expect_err("close flush fails");
        assert_eq!(error.path(), "writer");
        assert!(sink.is_closed());
        assert_eq!(
            sink.emit(&entry("after", 200)).expect_err("closed").path(),
            "sink"
        );
    }

    #[test]
    fn file_output_appends_and_reopens() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("access.log");
        let config = AccessLogSinkConfig::file(&path);

        let first = AccessLogSink::from_config(&config).expect("first sink");
        assert_eq!(
            first.emit(&entry("one", 200)).unwrap(),
            EmitOutcome::Written
        );
        first.close().expect("close first");

        // A second sink (for example after a reload) appends rather than truncating.
        let second = AccessLogSink::from_config(&config).expect("second sink");
        assert_eq!(
            second.emit(&entry("two", 200)).unwrap(),
            EmitOutcome::Written
        );
        second.close().expect("close second");

        let contents = std::fs::read(&path).expect("read access log");
        assert_eq!(parse_lines(&contents).len(), 2);
    }

    #[test]
    fn invalid_file_sink_fails_loudly() {
        let directory = tempfile::tempdir().expect("tempdir");
        let missing_parent = directory.path().join("does-not-exist").join("access.log");
        let error = AccessLogSink::from_config(&AccessLogSinkConfig::file(&missing_parent))
            .expect_err("missing parent directory");
        assert_eq!(error.path(), "writer.filename");
        assert!(
            error.message().contains("does-not-exist"),
            "error names the offending path: {error}"
        );

        // File output without a filename is rejected at validation time.
        let error = AccessLogSink::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::File,
            ..AccessLogSinkConfig::default()
        })
        .expect_err("file without filename");
        assert_eq!(error.path(), "writer.filename");
    }

    #[test]
    fn sink_configuration_validation_is_located() {
        let error = AccessLogSink::from_config(&AccessLogSinkConfig {
            buffer_bytes: 0,
            ..AccessLogSinkConfig::default()
        })
        .expect_err("zero buffer");
        assert_eq!(error.path(), "writer.buffer_bytes");

        let error = AccessLogSink::from_config(&AccessLogSinkConfig {
            encoder: AccessLogConfig {
                sampling: Some(SamplingConfig {
                    interval: std::time::Duration::ZERO,
                    first: 1,
                    thereafter: 1,
                }),
                ..AccessLogConfig::default()
            },
            ..AccessLogSinkConfig::default()
        })
        .expect_err("zero sampling interval");
        assert_eq!(error.path(), "sampling.interval");
    }

    #[test]
    fn discard_output_encodes_but_writes_nothing() {
        let sink = AccessLogSink::discard(AccessLogConfig::default()).expect("discard sink");
        let outcome = sink.emit(&entry("hidden", 200)).expect("emit");
        assert_eq!(outcome, EmitOutcome::Written);
        let stats = sink.stats();
        // The entry is still validated/encoded; no bytes reach a destination.
        assert_eq!(stats.bytes_written, 0);
        sink.flush().expect("flush discard");
    }

    // -- sampling -------------------------------------------------------------------------

    #[test]
    fn sampling_suppresses_entries_at_emission() {
        let config = AccessLogConfig {
            sampling: Some(SamplingConfig {
                interval: std::time::Duration::from_secs(3600),
                first: 2,
                thereafter: 1_000_000,
            }),
            ..AccessLogConfig::default()
        };
        let (sink, writer) = sink_with_recorder(config);
        let outcomes: Vec<EmitOutcome> = (0..4)
            .map(|index| sink.emit(&entry(&format!("entry {index}"), 200)).unwrap())
            .collect();
        assert_eq!(
            outcomes,
            vec![
                EmitOutcome::Written,
                EmitOutcome::Written,
                EmitOutcome::SampledOut,
                EmitOutcome::SampledOut,
            ]
        );
        sink.flush().expect("flush");
        assert_eq!(parse_lines(&writer.bytes()).len(), 2);
        let stats = sink.stats();
        assert_eq!(stats.written, 2);
        assert_eq!(stats.sampled_out, 2);
    }

    // -- concurrency ----------------------------------------------------------------------

    #[test]
    fn concurrent_emissions_are_line_atomic_and_thread_safe() {
        let (sink, writer) = sink_with_recorder(AccessLogConfig::default());
        let mut handles = Vec::new();
        for thread in 0..8 {
            let sink = sink.clone();
            handles.push(std::thread::spawn(move || {
                for index in 0..100 {
                    sink.emit(&entry(&format!("thread {thread} entry {index}"), 200))
                        .expect("emit");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
        sink.close().expect("close");
        let entries = parse_lines(&writer.bytes());
        assert_eq!(entries.len(), 800, "every entry is one complete JSON line");
        assert_eq!(sink.stats().written, 800);
        assert_eq!(sink.stats().write_errors, 0);
        // Spot-check that no line was interleaved: each record parses and names one thread.
        assert!(entries.iter().all(|entry| {
            entry["request"]["method"]
                .as_str()
                .is_some_and(|method| method == "GET")
        }));
    }

    // -- configuration serialization -------------------------------------------------------

    #[test]
    fn sink_handle_is_send_sync_for_runtime_wiring() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AccessLogSink>();
        assert_send_sync::<AccessLogSinkConfig>();
        assert_send_sync::<AccessLogEncoder>();
    }

    #[test]
    fn sink_configuration_round_trips_as_json() {
        let config = AccessLogSinkConfig {
            output: AccessLogOutput::File,
            filename: Some(PathBuf::from("/var/log/caddy/access.log")),
            buffer_bytes: 4096,
            ..AccessLogSinkConfig::default()
        };
        let json = serde_json::to_value(&config).expect("serialize");
        assert_eq!(json["output"], "file");
        assert_eq!(json["buffer_bytes"], 4096);
        let decoded: AccessLogSinkConfig = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded, config);
        // Default output is Caddy's stderr writer.
        assert_eq!(AccessLogOutput::default(), AccessLogOutput::Stderr);
    }
}
