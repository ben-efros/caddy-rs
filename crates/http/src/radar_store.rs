//! Persistent storage backends for the Radar client cache (`radar_client`).
//!
//! The cache is a small set of JSON documents keyed by endpoint (`ddos/l7`, `ddos/l34`,
//! `bgp/hijacks`, `traffic/anomalies`). A [`RadarStorage`] implementation persists one document per
//! key; the client writes every cached endpoint after a successful poll and reads them back when
//! radar is enabled (`auto` after the first Internet-routable client IP, `on` at startup).
//!
//! Three backends are provided:
//!
//! * [`FileStorage`] — one JSON object (`{ "<key>": "<document>" }`) in a file, rewritten with a
//!   temp-file-plus-rename so a crash or a full disk never leaves a truncated cache behind. This is
//!   the default.
//! * [`MemoryStorage`] — an in-process map, for tests and for deployments that only want the TTL
//!   cache.
//! * [`RedisStorage`] — a deliberately minimal RESP client over [`tokio::net::TcpStream`]
//!   (`SET <prefix><key> <json>` / `GET <prefix><key>`), one connection per operation. No `redis`
//!   crate: the cache needs exactly two commands, and a full client would add a large dependency
//!   tree to the HTTP engine for no benefit.
//!
//! Storage failures are values ([`StorageError`]), never panics: a broken cache must degrade radar
//! to "poll without persistence", not take the process down. The client counts them in
//! `radar_errors_total` and keeps serving whatever it already has in memory.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Default cache file, relative to the process working directory unless configured otherwise.
pub const DEFAULT_CACHE_PATH: &str = "radar-cache.json";

/// Connect/read/write timeout applied to every Redis operation.
const REDIS_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on one buffered Radar payload, shared by the Redis `$<len>` bulk reader below and the
/// HTTP response reader in [`crate::radar_client`]. A Radar page or cached document is a few KiB, so
/// 1 MiB leaves generous headroom for growth while keeping a hostile or broken peer from forcing an
/// unbounded allocation.
pub const MAX_RADAR_BYTES: usize = 1024 * 1024;

/// A storage operation failed. The message is user-facing and names the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError {
    message: String,
}

impl StorageError {
    /// Build an error from a displayable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The underlying message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StorageError {}

/// Key/value persistence for the Radar cache.
///
/// Keys are endpoint identifiers without a leading slash (`ddos/l7`). Values are opaque JSON
/// documents; the backend never inspects them.
#[async_trait]
pub trait RadarStorage: Send + Sync + fmt::Debug {
    /// Persist `json` under `key`, replacing any previous value.
    async fn save(&self, key: &str, json: &str) -> Result<(), StorageError>;

    /// Read the document stored under `key`, or `None` when the key is absent.
    async fn load(&self, key: &str) -> Result<Option<String>, StorageError>;

    /// Persist a whole cache snapshot. The default implementation calls [`Self::save`] per key;
    /// file-backed storage overrides it to rewrite the file once.
    async fn save_all(&self, entries: &BTreeMap<String, String>) -> Result<(), StorageError> {
        for (key, json) in entries {
            self.save(key, json).await?;
        }
        Ok(())
    }

    /// Short backend description for logs (`file:/path`, `redis:host:port`, `memory`).
    fn describe(&self) -> String;
}

/// Which backend the cache uses.
///
/// The textual spec accepted by [`StorageSpec::parse`] mirrors a Caddyfile directive body:
///
/// ```text
/// file{path=/var/lib/caddy/radar-cache.json}   # default; path optional
/// redis{url=redis://127.0.0.1:6379,prefix=radar:}
/// memory
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSpec {
    /// JSON file, atomically replaced.
    File {
        /// Cache file path.
        path: PathBuf,
    },
    /// Redis server, one key per endpoint under `prefix`.
    Redis {
        /// `redis://host:port` URL (plaintext only; TLS is not implemented).
        url: String,
        /// Key prefix, e.g. `radar:`.
        prefix: String,
    },
    /// Process-local map; nothing survives a restart.
    Memory,
}

impl Default for StorageSpec {
    fn default() -> Self {
        Self::File {
            path: PathBuf::from(DEFAULT_CACHE_PATH),
        }
    }
}

impl StorageSpec {
    /// Parse a storage spec. An empty spec selects the default (`file`, default path).
    pub fn parse(spec: &str) -> Result<Self, StorageError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(Self::default());
        }
        if spec == "memory" {
            return Ok(Self::Memory);
        }
        let (kind, body) = match spec.find('{') {
            Some(index) => {
                let kind = spec[..index].trim();
                let rest = spec[index + 1..].trim();
                let body = rest.strip_suffix('}').ok_or_else(|| {
                    StorageError::new(format!("radar storage: '{spec}' is missing a closing '}}'"))
                })?;
                (kind, body)
            }
            None => (spec, ""),
        };
        let options = parse_options(body)?;
        match kind {
            "file" => {
                let path = options
                    .get("path")
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_CACHE_PATH.to_string());
                if path.is_empty() {
                    return Err(StorageError::new(
                        "radar storage: file{path=...} needs a non-empty path",
                    ));
                }
                Ok(Self::File {
                    path: PathBuf::from(path),
                })
            }
            "redis" => {
                let url = options.get("url").cloned().ok_or_else(|| {
                    StorageError::new("radar storage: redis{...} needs url=<redis://host:port>")
                })?;
                let prefix = options
                    .get("prefix")
                    .cloned()
                    .unwrap_or_else(|| "radar:".to_string());
                Ok(Self::Redis { url, prefix })
            }
            "memory" => Ok(Self::Memory),
            other => Err(StorageError::new(format!(
                "radar storage: unknown backend '{other}' (expected file, redis, or memory)"
            ))),
        }
    }

    /// Build the backend. Redis URLs are validated here, so a bad URL fails at construction
    /// instead of on the first poll.
    pub fn build(&self) -> Result<Arc<dyn RadarStorage>, StorageError> {
        match self {
            Self::File { path } => Ok(Arc::new(FileStorage::new(path.clone()))),
            Self::Redis { url, prefix } => {
                Ok(Arc::new(RedisStorage::new(url.clone(), prefix.clone())?))
            }
            Self::Memory => Ok(Arc::new(MemoryStorage::new())),
        }
    }
}

impl fmt::Display for StorageSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { path } => write!(formatter, "file{{path={}}}", path.display()),
            Self::Redis { url, prefix } => {
                write!(formatter, "redis{{url={url},prefix={prefix}}}")
            }
            Self::Memory => formatter.write_str("memory"),
        }
    }
}

/// Split `key=value,key=value` into a map. Values may be quoted with `"`.
fn parse_options(body: &str) -> Result<BTreeMap<String, String>, StorageError> {
    let mut options = BTreeMap::new();
    for pair in split_quoted(body, ',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            StorageError::new(format!("radar storage: option '{pair}' is not key=value"))
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(StorageError::new(
                "radar storage: option with an empty name".to_string(),
            ));
        }
        options.insert(key.to_string(), unquote(value.trim()).to_string());
    }
    Ok(options)
}

/// Split on `separator`, ignoring separators inside double quotes.
fn split_quoted(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in text.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            c if c == separator && !quoted => parts.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    parts.push(current);
    parts
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}

/// JSON file backend: `{ "<key>": "<json document>" }`, replaced atomically.
#[derive(Debug)]
pub struct FileStorage {
    path: PathBuf,
    /// Serialises read-modify-write cycles so concurrent saves cannot lose keys.
    lock: Mutex<()>,
}

impl FileStorage {
    /// Backend writing to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// The cache file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn read_map(&self) -> Result<BTreeMap<String, String>, StorageError> {
        let bytes = match tokio::fs::read(&self.path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => {
                return Err(StorageError::new(format!(
                    "radar storage: cannot read {}: {error}",
                    self.path.display()
                )))
            }
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(BTreeMap::new());
        }
        serde_json::from_slice(&bytes).map_err(|error| {
            StorageError::new(format!(
                "radar storage: {} is not a JSON cache object: {error}",
                self.path.display()
            ))
        })
    }

    async fn write_map(&self, map: &BTreeMap<String, String>) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.map_err(|error| {
                    StorageError::new(format!(
                        "radar storage: cannot create {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let bytes = serde_json::to_vec_pretty(map).map_err(|error| {
            StorageError::new(format!("radar storage: cannot encode cache: {error}"))
        })?;
        static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "radar-cache.json".to_string());
        let temporary = self.path.with_file_name(format!(
            ".{file_name}.tmp.{}.{sequence}",
            std::process::id()
        ));
        tokio::fs::write(&temporary, &bytes)
            .await
            .map_err(|error| {
                StorageError::new(format!(
                    "radar storage: cannot write {}: {error}",
                    temporary.display()
                ))
            })?;
        if let Err(error) = tokio::fs::rename(&temporary, &self.path).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(StorageError::new(format!(
                "radar storage: cannot replace {}: {error}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl RadarStorage for FileStorage {
    async fn save(&self, key: &str, json: &str) -> Result<(), StorageError> {
        let _guard = self.lock.lock().await;
        let mut map = self.read_map().await?;
        map.insert(key.to_string(), json.to_string());
        self.write_map(&map).await
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        let map = self.read_map().await?;
        Ok(map.get(key).cloned())
    }

    async fn save_all(&self, entries: &BTreeMap<String, String>) -> Result<(), StorageError> {
        let _guard = self.lock.lock().await;
        let mut map = self.read_map().await?;
        for (key, json) in entries {
            map.insert(key.clone(), json.clone());
        }
        self.write_map(&map).await
    }

    fn describe(&self) -> String {
        format!("file:{}", self.path.display())
    }
}

/// Process-local backend; useful for tests and for deployments that do not want a cache file.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    entries: Mutex<BTreeMap<String, String>>,
}

impl MemoryStorage {
    /// Empty in-memory backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored keys.
    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Whether nothing is stored.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[async_trait]
impl RadarStorage for MemoryStorage {
    async fn save(&self, key: &str, json: &str) -> Result<(), StorageError> {
        self.entries
            .lock()
            .await
            .insert(key.to_string(), json.to_string());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self.entries.lock().await.get(key).cloned())
    }

    fn describe(&self) -> String {
        "memory".to_string()
    }
}

/// Minimal RESP client: `SET`/`GET` only, one TCP connection per operation.
#[derive(Debug)]
pub struct RedisStorage {
    url: String,
    host: String,
    port: u16,
    prefix: String,
}

impl RedisStorage {
    /// Validate and describe a Redis backend.
    pub fn new(url: impl Into<String>, prefix: impl Into<String>) -> Result<Self, StorageError> {
        let url = url.into();
        let (host, port) = parse_redis_url(&url)?;
        Ok(Self {
            url,
            host,
            port,
            prefix: prefix.into(),
        })
    }

    /// The configured URL (credentials, if any, are not part of it).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The key prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    async fn connect(&self) -> Result<BufReader<TcpStream>, StorageError> {
        let connect = TcpStream::connect((self.host.as_str(), self.port));
        let stream = tokio::time::timeout(REDIS_TIMEOUT, connect)
            .await
            .map_err(|_| {
                StorageError::new(format!(
                    "radar storage: redis connect to {}:{} timed out",
                    self.host, self.port
                ))
            })?
            .map_err(|error| {
                StorageError::new(format!(
                    "radar storage: redis connect to {}:{} failed: {error}",
                    self.host, self.port
                ))
            })?;
        let _ = stream.set_nodelay(true);
        Ok(BufReader::new(stream))
    }

    async fn round_trip(&self, arguments: &[&str]) -> Result<Reply, StorageError> {
        let mut reader = self.connect().await?;
        let mut request = format!("*{}\r\n", arguments.len());
        for argument in arguments {
            request.push_str(&format!("${}\r\n", argument.len()));
            request.push_str(argument);
            request.push_str("\r\n");
        }
        let write = async {
            reader.get_mut().write_all(request.as_bytes()).await?;
            reader.get_mut().flush().await
        };
        tokio::time::timeout(REDIS_TIMEOUT, write)
            .await
            .map_err(|_| {
                StorageError::new(format!(
                    "radar storage: redis write to {}:{} timed out",
                    self.host, self.port
                ))
            })?
            .map_err(|error| {
                StorageError::new(format!("radar storage: redis write failed: {error}"))
            })?;
        let reply = tokio::time::timeout(REDIS_TIMEOUT, read_reply(&mut reader))
            .await
            .map_err(|_| {
                StorageError::new(format!(
                    "radar storage: redis read from {}:{} timed out",
                    self.host, self.port
                ))
            })??;
        match reply {
            Reply::Error(message) => Err(StorageError::new(format!(
                "radar storage: redis error: {message}"
            ))),
            other => Ok(other),
        }
    }
}

#[async_trait]
impl RadarStorage for RedisStorage {
    async fn save(&self, key: &str, json: &str) -> Result<(), StorageError> {
        let key = self.key(key);
        match self.round_trip(&["SET", &key, json]).await? {
            Reply::Simple(_) | Reply::Integer(_) => Ok(()),
            other => Err(StorageError::new(format!(
                "radar storage: unexpected SET reply {other:?}"
            ))),
        }
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        let key = self.key(key);
        match self.round_trip(&["GET", &key]).await? {
            Reply::Bulk(None) => Ok(None),
            Reply::Bulk(Some(bytes)) => String::from_utf8(bytes).map(Some).map_err(|error| {
                StorageError::new(format!("radar storage: non-UTF-8 value: {error}"))
            }),
            other => Err(StorageError::new(format!(
                "radar storage: unexpected GET reply {other:?}"
            ))),
        }
    }

    fn describe(&self) -> String {
        format!("redis:{}:{}", self.host, self.port)
    }
}

/// Parse `redis://[user:password@]host[:port][/db]`. TLS (`rediss://`) is rejected: the backend
/// speaks plaintext RESP only.
fn parse_redis_url(url: &str) -> Result<(String, u16), StorageError> {
    let rest = url.strip_prefix("redis://").ok_or_else(|| {
        StorageError::new(format!(
            "radar storage: redis URL '{url}' must start with redis:// (TLS is not supported)"
        ))
    })?;
    let authority = rest.split('/').next().unwrap_or_default();
    let authority = match authority.rsplit_once('@') {
        Some((_credentials, host)) => host,
        None => authority,
    };
    if authority.is_empty() {
        return Err(StorageError::new(format!(
            "radar storage: redis URL '{url}' has no host"
        )));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|_| {
                StorageError::new(format!(
                    "radar storage: redis URL '{url}' has an invalid port"
                ))
            })?;
            (host, port)
        }
        None => (authority, 6379),
    };
    if host.is_empty() {
        return Err(StorageError::new(format!(
            "radar storage: redis URL '{url}' has no host"
        )));
    }
    Ok((host.to_string(), port))
}

/// One RESP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reply {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
}

async fn read_reply(reader: &mut BufReader<TcpStream>) -> Result<Reply, StorageError> {
    let line = read_line(reader).await?;
    let (tag, rest) = line
        .split_at_checked(1)
        .ok_or_else(|| StorageError::new("radar storage: redis sent an empty reply"))?;
    match tag {
        "+" => Ok(Reply::Simple(rest.to_string())),
        "-" => Ok(Reply::Error(rest.to_string())),
        ":" => Ok(Reply::Integer(rest.parse::<i64>().map_err(|error| {
            StorageError::new(format!("radar storage: bad redis integer: {error}"))
        })?)),
        "$" => {
            let length = rest.parse::<i64>().map_err(|error| {
                StorageError::new(format!("radar storage: bad redis bulk length: {error}"))
            })?;
            if length < 0 {
                return Ok(Reply::Bulk(None));
            }
            if length > MAX_RADAR_BYTES as i64 {
                // Refuse before allocating or reading: the advertised length is attacker-controlled.
                return Err(StorageError::new(format!(
                    "radar storage: redis bulk reply of {length} bytes exceeds the {MAX_RADAR_BYTES}-byte limit"
                )));
            }
            let mut buffer = vec![0u8; length as usize];
            reader.read_exact(&mut buffer).await.map_err(|error| {
                StorageError::new(format!("radar storage: redis bulk read failed: {error}"))
            })?;
            let mut terminator = [0u8; 2];
            reader.read_exact(&mut terminator).await.map_err(|error| {
                StorageError::new(format!("radar storage: redis bulk read failed: {error}"))
            })?;
            Ok(Reply::Bulk(Some(buffer)))
        }
        other => Err(StorageError::new(format!(
            "radar storage: unknown redis reply type '{other}'"
        ))),
    }
}

async fn read_line(reader: &mut BufReader<TcpStream>) -> Result<String, StorageError> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|error| StorageError::new(format!("radar storage: redis read failed: {error}")))?;
    if read == 0 {
        return Err(StorageError::new(
            "radar storage: redis closed the connection without a reply".to_string(),
        ));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_spec_parses_each_backend() {
        assert_eq!(StorageSpec::parse("").unwrap(), StorageSpec::default());
        assert_eq!(StorageSpec::parse("memory").unwrap(), StorageSpec::Memory);
        assert_eq!(
            StorageSpec::parse("file{path=/tmp/radar.json}").unwrap(),
            StorageSpec::File {
                path: PathBuf::from("/tmp/radar.json")
            }
        );
        assert_eq!(
            StorageSpec::parse("redis{url=redis://127.0.0.1:6380,prefix=radar:}").unwrap(),
            StorageSpec::Redis {
                url: "redis://127.0.0.1:6380".to_string(),
                prefix: "radar:".to_string(),
            }
        );
    }

    #[test]
    fn storage_spec_rejects_unknown_backends_and_bad_urls() {
        assert!(StorageSpec::parse("bogus").is_err());
        assert!(StorageSpec::parse("file{path=/tmp/x.json").is_err());
        assert!(StorageSpec::parse("redis{prefix=radar:}").is_err());
        assert!(RedisStorage::new("http://127.0.0.1:6379", "radar:").is_err());
        assert!(RedisStorage::new("redis://127.0.0.1:notaport", "radar:").is_err());
    }

    #[tokio::test]
    async fn memory_storage_round_trips() {
        let storage = MemoryStorage::new();
        assert_eq!(storage.load("ddos/l7").await.unwrap(), None);
        storage.save("ddos/l7", "{\"a\":1}").await.unwrap();
        assert_eq!(
            storage.load("ddos/l7").await.unwrap().as_deref(),
            Some("{\"a\":1}")
        );
        assert!(!storage.is_empty().await);
    }
}
