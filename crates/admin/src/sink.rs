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
//! ## Writers and rotation
//!
//! Supported destinations: `stdout`, `stderr`, `discard`, `file` and `net`.
//!
//! File sinks honour Caddy's `mode`/`dir_mode` (Unix), create missing parent directories, and
//! rotate by size (`roll_size_mb`, default roll enabled when configured) keeping at most
//! `roll_keep` backup files and deleting backups older than `roll_keep_days`. Rotated files are
//! named `<filename>.<unix-millis>` (a documented divergence from Caddy's timberjack naming and
//! compression; `roll_interval`/`roll_minutes`/`roll_at`/`roll_compression`/`roll_local_time`/
//! `backup_time_format` are rejected by the configuration mapper).
//!
//! Net sinks (`net` writer) connect with `dial_timeout`, reconnect once and retry a failed line,
//! and with `soft_start` fall back to stderr while the socket is unavailable. Unix sockets are
//! not supported.
//!
//! ## Encoders
//!
//! `AccessLogFormat::Json` is the default (compact JSON + `line_ending`, default newline).
//! `AccessLogFormat::Console` renders Caddy's console encoder framing:
//! `<UTC wall time with millis>\t<colored LEVEL>\t[logger\t]<msg>\t<fields JSON with ": "/", ">
//! separators`. JSON encoder key options (`message_key`, `level_key`, `time_key`, `name_key`) and
//! filter-encoder field operations (`delete`, `replace`, `rename`, `hash` = SHA-256 first 4 bytes
//! hex, `ip_mask`) are applied by [`AccessLogEncoder`] via [`AccessLogConfig`].
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
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::access_log::{
    AccessLogConfig, AccessLogEntry, AccessLogError, AccessLogSampler, LogLevel, SamplingConfig,
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
    /// Append to [`AccessLogSinkConfig::filename`] (with optional rotation/modes).
    File,
    /// Write to a network socket (Caddy's `net` writer; TCP or UDP).
    Net,
}

impl AccessLogOutput {
    /// Stable lowercase name (Caddy's `writer.output` spelling).
    pub fn as_str(self) -> &'static str {
        match self {
            AccessLogOutput::Stderr => "stderr",
            AccessLogOutput::Stdout => "stdout",
            AccessLogOutput::Discard => "discard",
            AccessLogOutput::File => "file",
            AccessLogOutput::Net => "net",
        }
    }
}

/// Encoder framing used by a sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogFormat {
    /// One compact JSON object per line (Caddy's `json` encoder).
    #[default]
    Json,
    /// Caddy's `console` encoder: `<utc wall time with millis>\t<colored level>\t[logger\t]<msg>\t<fields>`.
    Console,
}

impl AccessLogFormat {
    /// Stable lowercase name (Caddy's `encoder.format` spelling).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Console => "console",
        }
    }
}

/// Caddy `file` writer options supported by caddy-rs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriterOptions {
    /// File permissions (octal value, e.g. `0o600`); applied on Unix only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Directory permissions for directories created to reach the log file (octal value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_mode: Option<u32>,
    /// Whether to rotate the file (Caddy's `roll`; default true).
    #[serde(default = "default_roll")]
    pub roll: bool,
    /// Rotate when the file exceeds roughly this many megabytes (Caddy `roll_size_mb`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roll_size_mb: Option<u64>,
    /// Number of rotated files to keep (Caddy `roll_keep`, default 10).
    #[serde(default = "default_roll_keep")]
    pub roll_keep: usize,
    /// Delete rotated files older than this many days (Caddy `roll_keep_days`, default 90).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roll_keep_days: Option<u64>,
}

fn default_roll() -> bool {
    true
}

fn default_roll_keep() -> usize {
    10
}

impl Default for FileWriterOptions {
    fn default() -> Self {
        Self {
            mode: None,
            dir_mode: None,
            roll: true,
            roll_size_mb: None,
            roll_keep: 10,
            roll_keep_days: None,
        }
    }
}

/// Network protocol for the `net` writer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetProtocol {
    /// TCP stream with reconnect-on-write-failure (Caddy's default).
    #[default]
    Tcp,
    /// UDP datagrams (each encoded line is one datagram).
    Udp,
}

/// Caddy `net` writer options supported by caddy-rs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetWriterConfig {
    /// Socket address (`host:port`). Caddy's `tcp/`/`udp/` prefix form is accepted by the
    /// configuration mapper.
    pub address: String,
    /// Protocol (Caddy infers it from the address prefix; explicit form for caddy-rs configs).
    #[serde(default)]
    pub network: NetProtocol,
    /// Connection timeout in nanoseconds (Caddy `dial_timeout`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_timeout_ns: Option<u64>,
    /// Allow startup with an unreachable socket; writes fall back to stderr while reconnecting
    /// (Caddy `soft_start`).
    #[serde(default)]
    pub soft_start: bool,
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
    /// Encoder framing (`json` or `console`).
    #[serde(default)]
    pub format: AccessLogFormat,
    /// File writer options (rotation/permissions), used when `output` is `file`.
    #[serde(default)]
    pub file: FileWriterOptions,
    /// Network writer options, required when `output` is `net`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetWriterConfig>,
    /// Capacity of the write buffer in bytes.
    #[serde(default = "default_buffer_bytes")]
    pub buffer_bytes: usize,
    /// Minimum entry level to emit (Caddy's `logging.logs.<name>.level`). Entries below it are
    /// counted as [`AccessLogSinkStats::filtered_out`] and never encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,
}

fn default_buffer_bytes() -> usize {
    DEFAULT_ACCESS_LOG_BUFFER_BYTES
}

impl Default for AccessLogSinkConfig {
    fn default() -> Self {
        Self {
            output: AccessLogOutput::Stderr,
            filename: None,
            format: AccessLogFormat::Json,
            file: FileWriterOptions::default(),
            net: None,
            encoder: AccessLogConfig::default(),
            buffer_bytes: DEFAULT_ACCESS_LOG_BUFFER_BYTES,
            level: None,
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

    /// Set the minimum emitted level (Caddy's `logging.logs.<name>.level`).
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
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
            if self.file.roll_keep == 0 {
                return Err(AccessLogError::new(
                    "writer.roll_keep",
                    "must be greater than zero",
                ));
            }
            if self.file.roll_size_mb == Some(0) {
                return Err(AccessLogError::new(
                    "writer.roll_size_mb",
                    "must be greater than zero",
                ));
            }
            if self.file.roll_keep_days == Some(0) {
                return Err(AccessLogError::new(
                    "writer.roll_keep_days",
                    "must be greater than zero",
                ));
            }
            if let Some(mode) = self.file.mode {
                if mode > 0o7777 {
                    return Err(AccessLogError::new(
                        "writer.mode",
                        "must be an octal file mode (0-07777)",
                    ));
                }
            }
            if let Some(mode) = self.file.dir_mode {
                if mode > 0o7777 {
                    return Err(AccessLogError::new(
                        "writer.dir_mode",
                        "must be an octal file mode (0-07777)",
                    ));
                }
            }
        }
        if self.output == AccessLogOutput::Net {
            let Some(net) = &self.net else {
                return Err(AccessLogError::new(
                    "writer.address",
                    "net output requires an address",
                ));
            };
            if net.address.is_empty() {
                return Err(AccessLogError::new(
                    "writer.address",
                    "net writer address must not be empty",
                ));
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
    /// The configured minimum level filtered the entry out; nothing was encoded or written.
    FilteredOut,
}

/// A snapshot of sink activity, useful for diagnostics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessLogSinkStats {
    /// Entries encoded and accepted by the sink (buffered counts as accepted).
    pub written: u64,
    /// Entries suppressed by sampling.
    pub sampled_out: u64,
    /// Entries suppressed by the configured minimum level.
    pub filtered_out: u64,
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
    format: AccessLogFormat,
}

impl AccessLogEncoder {
    /// Validate `config` and build a JSON encoder.
    pub fn new(config: AccessLogConfig) -> Result<Self, AccessLogError> {
        Self::with_format(config, AccessLogFormat::Json)
    }

    /// Validate `config` and build an encoder using `format`.
    pub fn with_format(
        config: AccessLogConfig,
        format: AccessLogFormat,
    ) -> Result<Self, AccessLogError> {
        config.validate()?;
        Ok(Self { config, format })
    }

    /// The encoder framing in use.
    pub fn format(&self) -> AccessLogFormat {
        self.format
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
        match self.format {
            AccessLogFormat::Json => {
                let mut line = serde_json::to_vec(&rendered).map_err(|error| {
                    AccessLogError::new("entry", format!("cannot encode: {error}"))
                })?;
                line.push(b'\n');
                Ok(line)
            }
            AccessLogFormat::Console => encode_console_line(&rendered),
        }
    }

    /// Encode one entry to a compact JSON string (without the trailing newline).
    pub fn encode_string(&self, entry: &AccessLogEntry) -> Result<String, AccessLogError> {
        let rendered = entry.render(&self.config)?;
        serde_json::to_string(&rendered)
            .map_err(|error| AccessLogError::new("entry", format!("cannot encode: {error}")))
    }
}

/// Format a Unix timestamp (floating seconds) as Caddy's console `wall_milli` time in UTC:
/// `YYYY/MM/DD HH:MM:SS.mmm` (zap's console encoder uses UTC unless `time_local` is set).
fn format_wall_milli(seconds: f64) -> String {
    let whole = seconds.floor() as i64;
    let millis = ((seconds - whole as f64) * 1000.0)
        .round()
        .clamp(0.0, 999.0) as u32;
    let days = whole.div_euclid(86_400);
    let seconds_of_day = whole.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}")
}

/// Howard Hinnant's `civil_from_days` (days since 1970-01-01 -> year/month/day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (
        year + i64::from(month <= 2),
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// zap's colored level names (console encoder default `level_format: color`).
fn colored_level(level: &str) -> String {
    let color = match level {
        "error" | "fatal" | "panic" | "dpanic" => 31,
        "warn" => 33,
        "info" => 34,
        _ => 35,
    };
    format!("\u{1b}[{color}m{}\u{1b}[0m", level.to_ascii_uppercase())
}

/// Encode one rendered entry in Caddy's console format:
/// `<time>\t<level>\t[logger\t]<msg>\t<json fields>\n`.
fn encode_console_line(rendered: &serde_json::Value) -> Result<Vec<u8>, AccessLogError> {
    let object = rendered
        .as_object()
        .ok_or_else(|| AccessLogError::new("entry", "console encoding requires an entry object"))?;
    let timestamp = object
        .get("ts")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    let level = object
        .get("level")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("info");
    let logger = object
        .get("logger")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let message = object
        .get("msg")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let mut fields = object.clone();
    for fundamental in ["ts", "level", "logger", "msg"] {
        fields.remove(fundamental);
    }
    let fields = spaced_json(&serde_json::Value::Object(fields));
    let time = format_wall_milli(timestamp);
    let level = colored_level(level);
    let text = if logger.is_empty() {
        format!("{time}\t{level}\t{message}\t{fields}\n")
    } else {
        format!("{time}\t{level}\t{logger}\t{message}\t{fields}\n")
    };
    Ok(text.into_bytes())
}

/// Serialize JSON with zap console's `": "` and `", "` separators (outside strings).
fn spaced_json(value: &serde_json::Value) -> String {
    let compact = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    let mut result = String::with_capacity(compact.len() + compact.len() / 8);
    let mut in_string = false;
    let mut escaped = false;
    for character in compact.chars() {
        result.push(character);
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
        } else if character == ':' || character == ',' {
            result.push(' ');
        }
    }
    result
}

/// File destination with Caddy-style size rotation and optional permissions.
struct FileSink {
    path: PathBuf,
    options: FileWriterOptions,
    capacity: usize,
    writer: BufWriter<File>,
    bytes: u64,
}

impl FileSink {
    fn open(path: PathBuf, options: FileWriterOptions, capacity: usize) -> io::Result<Self> {
        create_parent_directories(&path, &options)?;
        let file = open_append(&path, &options)?;
        let bytes = file.metadata()?.len();
        Ok(Self {
            path,
            options,
            capacity,
            writer: BufWriter::with_capacity(capacity, file),
            bytes,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.should_roll(bytes.len()) {
            self.rotate()?;
        }
        self.writer.write_all(bytes)?;
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn should_roll(&self, incoming: usize) -> bool {
        if !self.options.roll {
            return false;
        }
        let Some(size_mb) = self.options.roll_size_mb else {
            return false;
        };
        let limit = size_mb.saturating_mul(1024 * 1024);
        self.bytes.saturating_add(incoming as u64) > limit
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        let backup = unique_backup_path(&self.path);
        std::fs::rename(&self.path, &backup)?;
        let file = open_append(&self.path, &self.options)?;
        self.writer = BufWriter::with_capacity(self.capacity, file);
        self.bytes = 0;
        prune_backups(&self.path, &self.options);
        Ok(())
    }
}

fn open_append(path: &Path, options: &FileWriterOptions) -> io::Result<File> {
    let mut open = OpenOptions::new();
    open.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(mode) = options.mode {
            open.mode(mode);
        }
    }
    open.open(path)
}

fn create_parent_directories(path: &Path, options: &FileWriterOptions) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    if let Some(dir_mode) = options.dir_mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(dir_mode))?;
    }
    let _ = options;
    Ok(())
}

fn unique_backup_path(path: &Path) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let mut candidate = PathBuf::from(format!("{}.{millis}", path.display()));
    let mut counter = 0u32;
    while candidate.exists() {
        counter += 1;
        candidate = PathBuf::from(format!("{}.{millis}.{counter}", path.display()));
    }
    candidate
}

/// Delete rotated files beyond `roll_keep` (and older than `roll_keep_days`), best-effort.
fn prune_backups(path: &Path, options: &FileWriterOptions) {
    let Some(parent) = path.parent() else {
        return;
    };
    let Some(prefix) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let mut backups: Vec<(SystemTime, PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            if !name.starts_with(&format!("{prefix}.")) {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    backups.sort_by_key(|(modified, _)| *modified);
    let keep = options.roll_keep.max(1);
    let keep_days = options
        .roll_keep_days
        .map(Duration::from_secs)
        .map(|days| days.as_secs() * 24 * 3600);
    let now = SystemTime::now();
    while backups.len() > keep {
        if let Some((_, path)) = backups.first() {
            let _ = std::fs::remove_file(path);
        }
        backups.remove(0);
    }
    if let Some(limit) = keep_days {
        for (modified, path) in &backups {
            if now
                .duration_since(*modified)
                .map(|age| age.as_secs() > limit)
                .unwrap_or(false)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

enum NetConnection {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

/// Network destination: dials on first use, reconnects once on write failure, and (with
/// `soft_start`) falls back to stderr while the socket is unavailable, like Caddy's net writer.
struct NetSink {
    config: NetWriterConfig,
    connection: Option<NetConnection>,
}

impl NetSink {
    fn new(config: NetWriterConfig) -> io::Result<Self> {
        let mut sink = Self {
            config,
            connection: None,
        };
        match sink.connect() {
            Ok(connection) => sink.connection = Some(connection),
            Err(error) if sink.config.soft_start => {
                eprintln!(
                    "caddy-rs: net log writer failed to connect to {}: {error} (will retry; logs fall back to stderr)",
                    sink.config.address
                );
            }
            Err(error) => return Err(error),
        }
        Ok(sink)
    }

    fn connect(&self) -> io::Result<NetConnection> {
        let timeout = self.config.dial_timeout_ns.map(Duration::from_nanos);
        match self.config.network {
            NetProtocol::Tcp => {
                let stream = match timeout {
                    Some(timeout) => {
                        let address =
                            self.config.address.to_socket_addrs_first().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!("invalid address `{}`", self.config.address),
                                )
                            })?;
                        TcpStream::connect_timeout(&address, timeout)?
                    }
                    None => TcpStream::connect(&self.config.address)?,
                };
                let _ = stream.set_nodelay(true);
                Ok(NetConnection::Tcp(stream))
            }
            NetProtocol::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                socket.connect(&self.config.address)?;
                Ok(NetConnection::Udp(socket))
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.connection.is_none() {
            self.connection = Some(self.connect()?);
        }
        let result = match self.connection.as_mut() {
            Some(NetConnection::Tcp(stream)) => stream.write_all(bytes),
            Some(NetConnection::Udp(socket)) => socket.send(bytes).map(|_| ()),
            None => unreachable!("connection established above"),
        };
        if result.is_err() {
            // Reconnect once and retry the line, like Caddy's redialerConn.
            self.connection = None;
            self.connection = Some(self.connect()?);
            match self.connection.as_mut() {
                Some(NetConnection::Tcp(stream)) => stream.write_all(bytes),
                Some(NetConnection::Udp(socket)) => socket.send(bytes).map(|_| ()),
                None => unreachable!(),
            }?;
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self.send(bytes) {
            Ok(()) => Ok(()),
            Err(error) if self.config.soft_start => {
                eprintln!(
                    "caddy-rs: net log writer {} unavailable: {error}; falling back to stderr",
                    self.config.address
                );
                let _ = io::stderr().write_all(bytes);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(NetConnection::Tcp(stream)) = &mut self.connection {
            stream.flush()?;
        }
        Ok(())
    }
}

/// Resolve a host:port string to one socket address without requiring a full resolver API.
trait ToSocketAddrsFirst {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}

impl ToSocketAddrsFirst for str {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok()?.next()
    }
}

enum SinkTarget {
    Stdout(BufWriter<io::Stdout>),
    Stderr(BufWriter<io::Stderr>),
    Discard,
    File(FileSink),
    Net(NetSink),
    Custom(BufWriter<Box<dyn Write + Send>>),
}

impl fmt::Debug for SinkTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            SinkTarget::Stdout(_) => "AccessLogTarget::Stdout",
            SinkTarget::Stderr(_) => "AccessLogTarget::Stderr",
            SinkTarget::Discard => "AccessLogTarget::Discard",
            SinkTarget::File(_) => "AccessLogTarget::File",
            SinkTarget::Net(_) => "AccessLogTarget::Net",
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
            SinkTarget::File(file) => file.write(bytes),
            SinkTarget::Net(net) => net.write(bytes),
            SinkTarget::Custom(writer) => writer.write_all(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            SinkTarget::Stdout(writer) => writer.flush(),
            SinkTarget::Stderr(writer) => writer.flush(),
            SinkTarget::Discard => Ok(()),
            SinkTarget::File(file) => file.flush(),
            SinkTarget::Net(net) => net.flush(),
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
    min_level: Option<LogLevel>,
    state: Mutex<SinkState>,
    closed: AtomicBool,
    written: AtomicU64,
    sampled_out: AtomicU64,
    filtered_out: AtomicU64,
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
        let encoder = AccessLogEncoder::with_format(config.encoder.clone(), config.format)?;
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
                    .clone()
                    .expect("validated file output has a filename");
                let file = FileSink::open(path.clone(), config.file.clone(), capacity).map_err(
                    |error| {
                        AccessLogError::new(
                            "writer.filename",
                            format!("cannot open `{}`: {error}", path.display()),
                        )
                    },
                )?;
                SinkTarget::File(file)
            }
            AccessLogOutput::Net => {
                let net = config
                    .net
                    .clone()
                    .expect("validated net output has a configuration");
                let net = NetSink::new(net).map_err(|error| {
                    AccessLogError::new(
                        "writer.address",
                        format!("cannot connect net log writer: {error}"),
                    )
                })?;
                SinkTarget::Net(net)
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
                min_level: config.level,
                state: Mutex::new(SinkState { target }),
                closed: AtomicBool::new(false),
                written: AtomicU64::new(0),
                sampled_out: AtomicU64::new(0),
                filtered_out: AtomicU64::new(0),
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
                min_level: sink_config.level,
                state: Mutex::new(SinkState {
                    target: SinkTarget::Custom(BufWriter::with_capacity(
                        sink_config.buffer_bytes,
                        Box::new(writer),
                    )),
                }),
                closed: AtomicBool::new(false),
                written: AtomicU64::new(0),
                sampled_out: AtomicU64::new(0),
                filtered_out: AtomicU64::new(0),
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
            filtered_out: self.inner.filtered_out.load(Ordering::Relaxed),
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
        if let Some(min_level) = self.inner.min_level {
            if entry.level < min_level {
                self.inner.filtered_out.fetch_add(1, Ordering::Relaxed);
                return Ok(EmitOutcome::FilteredOut);
            }
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
        // Caddy creates missing parent directories (with the configured dir_mode); caddy-rs does
        // the same, so a missing parent is no longer an error.
        let nested = directory.path().join("does-not-exist").join("access.log");
        let sink = AccessLogSink::from_config(&AccessLogSinkConfig::file(&nested))
            .expect("missing parent directories are created");
        sink.close().expect("close");
        assert!(nested.is_file());

        // A parent path that is itself a file still fails loudly and names the path.
        let file_parent = directory.path().join("not-a-directory");
        std::fs::write(&file_parent, b"x").expect("write file");
        let invalid = file_parent.join("access.log");
        let error = AccessLogSink::from_config(&AccessLogSinkConfig::file(&invalid))
            .expect_err("parent is a file");
        assert_eq!(error.path(), "writer.filename");
        assert!(
            error.message().contains("access.log"),
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
    fn minimum_level_filters_entries_before_encoding() {
        let sink = AccessLogSink::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::Discard,
            level: Some(LogLevel::Warn),
            ..AccessLogSinkConfig::default()
        })
        .expect("sink");
        assert_eq!(
            sink.emit(&entry("info", 200)).expect("emit"),
            EmitOutcome::FilteredOut
        );
        assert_eq!(
            sink.emit(&entry("error", 500)).expect("emit"),
            EmitOutcome::Written
        );
        let stats = sink.stats();
        assert_eq!(stats.filtered_out, 1);
        assert_eq!(stats.written, 1);
        assert_eq!(stats.sampled_out, 0);
    }

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

    // ---- expanded writers/encoders (T-ADMIN-032) -------------------------------------------

    #[test]
    fn size_rotation_rolls_and_prunes_backups() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("access.log");
        let sink = AccessLogSink::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::File,
            filename: Some(path.clone()),
            file: FileWriterOptions {
                roll: true,
                roll_size_mb: Some(1),
                roll_keep: 2,
                roll_keep_days: None,
                ..FileWriterOptions::default()
            },
            encoder: AccessLogConfig {
                exclude: vec![],
                ..AccessLogConfig::default()
            },
            ..AccessLogSinkConfig::default()
        })
        .expect("rotating sink");

        // Write a bit more than three megabytes so the 1 MiB file rolls repeatedly.
        let line_padding = "x".repeat(256);
        let large = AccessLogEntry {
            user_id: line_padding,
            ..entry("rotated", 200)
        };
        for _ in 0..14_000 {
            sink.emit(&large).expect("emit");
        }
        sink.close().expect("close");
        assert!(path.is_file(), "current log file exists");
        let backups: Vec<_> = std::fs::read_dir(directory.path())
            .expect("dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("access.log.")
            })
            .collect();
        assert!(!backups.is_empty(), "rotation created backup files");
        assert!(
            backups.len() <= 2,
            "roll_keep prunes old backups, got {}",
            backups.len()
        );
    }

    #[test]
    fn net_writer_streams_lines_to_a_tcp_listener() {
        use std::io::{BufRead, BufReader};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let sink = AccessLogSink::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::Net,
            net: Some(NetWriterConfig {
                address: address.to_string(),
                network: NetProtocol::Tcp,
                dial_timeout_ns: Some(1_000_000_000),
                soft_start: false,
            }),
            ..AccessLogSinkConfig::default()
        })
        .expect("net sink");
        sink.emit(&entry("over the wire", 200)).expect("emit");
        let (stream, _peer) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read line");
        let value: Value = serde_json::from_str(line.trim()).expect("json line");
        assert_eq!(value["status"], 200);
        assert_eq!(value["msg"], "handled request");
        sink.close().expect("close");
    }

    #[test]
    fn net_writer_fails_loudly_without_soft_start_and_tolerates_soft_start() {
        // Nothing is listening on this reserved-but-closed ephemeral port.
        let address = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("address").to_string()
        };
        let error = AccessLogSink::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::Net,
            net: Some(NetWriterConfig {
                address: address.clone(),
                network: NetProtocol::Tcp,
                dial_timeout_ns: Some(100_000_000),
                soft_start: false,
            }),
            ..AccessLogSinkConfig::default()
        })
        .expect_err("unreachable socket");
        assert_eq!(error.path(), "writer.address");

        // soft_start tolerates the unreachable socket and falls back to stderr while reconnecting.
        let sink = AccessLogSink::from_config(&AccessLogSinkConfig {
            output: AccessLogOutput::Net,
            net: Some(NetWriterConfig {
                address,
                network: NetProtocol::Tcp,
                dial_timeout_ns: Some(100_000_000),
                soft_start: true,
            }),
            ..AccessLogSinkConfig::default()
        })
        .expect("soft start");
        assert_eq!(
            sink.emit(&entry("fallback", 200)).expect("emit"),
            EmitOutcome::Written
        );
        sink.close().expect("close");
    }

    #[test]
    fn console_encoder_matches_caddys_console_framing() {
        let encoder =
            AccessLogEncoder::with_format(AccessLogConfig::default(), AccessLogFormat::Console)
                .expect("encoder");
        let mut log_entry = entry("console", 200);
        log_entry.timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let line = encoder.encode_line(&log_entry).expect("console line");
        let line = String::from_utf8(line).expect("utf8");
        assert!(
            line.starts_with("2023/11/14 22:13:20.000\t\u{1b}[34mINFO\u{1b}[0m\thttp.log.access\thandled request\t{"),
            "got: {line}"
        );
        assert!(
            line.contains("\"status\": 200"),
            "spaced JSON fields: {line}"
        );
        assert!(line.ends_with('\n'));
    }
}
