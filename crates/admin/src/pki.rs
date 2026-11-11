//! Read-only local PKI material (plan task T-ADMIN-026).
//!
//! Caddy's local certificate authority persists its material in the data directory using the
//! storage layout of `caddypki`:
//!
//! ```text
//! <data-dir>/pki/authorities/<ca-id>/root.crt
//! <data-dir>/pki/authorities/<ca-id>/root.key
//! <data-dir>/pki/authorities/<ca-id>/intermediate.crt
//! <data-dir>/pki/authorities/<ca-id>/intermediate.key
//! ```
//!
//! This module reads that layout **without modifying it** and without ever provisioning anything:
//! the admin `/pki` endpoints and the `caddy-rs pki`/`trust` CLI commands only expose a CA that
//! has already been provisioned by the server's automatic HTTPS (or written by real Caddy). A
//! missing CA is a located `404`, never a lazy generation — that would be a silent state change.
//!
//! PEM certificate parsing is intentionally minimal: only the fields needed for metadata,
//! listing, export and trust are decoded (common names, validity dates, serials). Chain
//! verification, signature checks and key handling are out of scope; the TLS crate owns those.
//!
//! ## Compatibility notes
//!
//! * `GET /pki/ca/<id>` returns Caddy's `caInfo` shape. Caddy's `name` comes from the PKI app
//!   configuration (`apps.pki.certificate_authorities.<id>.name`, default `Caddy Local Authority`);
//!   the admin handler reads the active generation's PKI app and reports the configured name via
//!   [`CaMaterial::with_name`]. Without a config (for example the `caddy-rs pki` CLI commands,
//!   which only see the data directory) the CA id is reported instead, because the name is not
//!   persisted in the CA files.
//! * Caddy lazily provisions the default CA (`local`) when `/pki/ca/local` is requested and PKI is
//!   not configured. This build is read-only and returns `404` instead (documented divergence).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Environment variable used by the CLI and admin API as a data-directory override.
pub const DATA_DIR_ENV: &str = "CADDY_RS_DATA_DIR";
/// Default data directory, matching the server runtime's fallback.
pub const DEFAULT_DATA_DIR: &str = ".caddy-rs";
/// Directory (relative to the data directory) of Caddy's CA authorities.
pub const AUTHORITIES_DIRECTORY: &str = "pki/authorities";
/// Caddy's default local CA identifier.
pub const DEFAULT_CA_ID: &str = "local";
/// Caddy's default user-facing CA name (`caddypki` `defaultCAName`, substituted when a configured
/// CA does not set `name`).
pub const DEFAULT_CA_NAME: &str = "Caddy Local Authority";

const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

/// A located PKI read error.
#[derive(Debug)]
pub enum PkiError {
    /// The CA identifier is not a single safe path component.
    InvalidCaId {
        /// Offending identifier.
        id: String,
        /// Why it is invalid.
        reason: String,
    },
    /// No CA directory exists for this id (the CA was never provisioned, or the data directory is
    /// wrong).
    NotFound {
        /// Requested CA identifier.
        id: String,
        /// Directory that was checked.
        directory: PathBuf,
    },
    /// The CA directory exists but a required certificate file is missing.
    MissingCertificate {
        /// CA identifier.
        id: String,
        /// Missing file.
        path: PathBuf,
        /// Certificate role (`root` or `intermediate`).
        role: &'static str,
    },
    /// Reading CA material failed.
    Io {
        /// File or directory that failed.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// A PEM file could not be decoded.
    MalformedPem {
        /// File path.
        path: PathBuf,
        /// Diagnosis.
        message: String,
    },
    /// A decoded certificate could not be parsed.
    Certificate {
        /// File path.
        path: PathBuf,
        /// Diagnosis.
        message: String,
    },
}

impl PkiError {
    /// Whether this error means "no such CA".
    pub fn is_not_found(&self) -> bool {
        matches!(self, PkiError::NotFound { .. })
    }

    /// A user-facing hint for errors that usually mean the CA has not been provisioned yet.
    pub fn provisioning_hint(&self) -> Option<String> {
        match self {
            PkiError::NotFound { id, .. } => Some(format!(
                "no CA `{id}` was found in the data directory; the internal CA must be provisioned \
                 by the server before PKI material exists (/pki is read-only and does not create it)"
            )),
            _ => None,
        }
    }
}

impl fmt::Display for PkiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkiError::InvalidCaId { id, reason } => {
                write!(formatter, "pki: invalid CA id `{id}`: {reason}")
            }
            PkiError::NotFound { id, directory } => write!(
                formatter,
                "pki: no certificate authority configured with id `{id}` (looked in `{}`)",
                directory.display()
            ),
            PkiError::MissingCertificate { id, path, role } => write!(
                formatter,
                "pki: CA `{id}` is missing its {role} certificate at `{}`",
                path.display()
            ),
            PkiError::Io { path, source } => {
                write!(formatter, "pki: cannot read `{}`: {source}", path.display())
            }
            PkiError::MalformedPem { path, message } => {
                write!(
                    formatter,
                    "pki: invalid PEM in `{}`: {message}",
                    path.display()
                )
            }
            PkiError::Certificate { path, message } => {
                write!(
                    formatter,
                    "pki: invalid certificate in `{}`: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for PkiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PkiError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Resolve the data directory: explicit override, then `CADDY_RS_DATA_DIR`, then the configured
/// storage root, then [`DEFAULT_DATA_DIR`].
///
/// # Deliberate difference from Caddy
///
/// Caddy resolves its data directory with `caddy.AppDataDir()`: `$XDG_DATA_HOME/caddy` when that
/// variable is set, otherwise `$HOME/.local/share/caddy` on Linux (and platform equivalents such
/// as `$HOME/Library/Application Support/Caddy` on macOS and `%AppData%\Caddy` on Windows), with
/// `./caddy` as the last-resort relative fallback. caddy-rs deliberately keeps its historical
/// project convention instead: the relative `.caddy-rs` directory in the process working
/// directory (or the configured `storage.root` for `run`), overridable with `CADDY_RS_DATA_DIR`
/// or an explicit `--data-dir`. Server, admin and CLI all use this same resolver, so they agree
/// with each other; the difference from Caddy is documented in DIV-0073 and avoids migrating every
/// existing caddy-rs deployment's CA material. `CADDY_RS_DATA_DIR` is caddy-rs-specific (Caddy has
/// no data-dir environment override).
pub fn resolve_data_dir(
    explicit: Option<PathBuf>,
    config_storage_root: Option<PathBuf>,
) -> PathBuf {
    resolve_data_dir_with(
        explicit,
        std::env::var_os(DATA_DIR_ENV).map(PathBuf::from),
        config_storage_root,
    )
}

/// Testable form of [`resolve_data_dir`] with the environment value supplied explicitly.
pub fn resolve_data_dir_with(
    explicit: Option<PathBuf>,
    environment: Option<PathBuf>,
    config_storage_root: Option<PathBuf>,
) -> PathBuf {
    explicit
        .or(environment)
        .or(config_storage_root)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

/// The `pki/authorities` directory under `data_dir`.
pub fn authorities_directory(data_dir: impl AsRef<Path>) -> PathBuf {
    data_dir.as_ref().join(AUTHORITIES_DIRECTORY)
}

/// One parsed certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// DER-encoded certificate.
    pub der: Vec<u8>,
    /// Canonical PEM encoding (64-column base64, trailing newline).
    pub pem: String,
    /// Subject common name, when present.
    pub common_name: Option<String>,
    /// Issuer common name, when present.
    pub issuer_common_name: Option<String>,
    /// `notBefore` as an RFC 3339-ish UTC string (`YYYY-MM-DDTHH:MM:SSZ`), when parseable.
    pub not_before: Option<String>,
    /// `notAfter` as an RFC 3339-ish UTC string, when parseable.
    pub not_after: Option<String>,
    /// `notAfter` as Unix seconds (whole seconds).
    pub not_after_unix: Option<u64>,
    /// DNS subject alternative names from the `subjectAltName` extension, in certificate order.
    pub dns_names: Vec<String>,
    /// Serial number as lowercase hex.
    pub serial_hex: String,
}

/// A CA loaded from the on-disk layout.
#[derive(Debug, Clone)]
pub struct CaMaterial {
    id: String,
    directory: PathBuf,
    root: CertificateInfo,
    intermediates: Vec<CertificateInfo>,
    /// User-facing CA name from the active configuration (Caddy's `caInfo.name`). `None` means the
    /// caller only has the data directory, so [`CaMaterial::name`] falls back to the id.
    configured_name: Option<String>,
}

impl CaMaterial {
    /// CA identifier (storage directory name).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Directory the material was read from.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Set the user-facing CA name from configuration (Caddy's `caInfo.name` / `apps.pki` name).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.configured_name = Some(name.into());
        self
    }

    /// Caddy's `caInfo.name`: the configured PKI-app name when known, otherwise the CA id (the
    /// data-directory-only CLI commands cannot know the configuration).
    pub fn name(&self) -> &str {
        self.configured_name.as_deref().unwrap_or(&self.id)
    }

    /// The parsed root certificate.
    pub fn root(&self) -> &CertificateInfo {
        &self.root
    }

    /// The parsed intermediate chain (may be empty when only a root exists).
    pub fn intermediates(&self) -> &[CertificateInfo] {
        &self.intermediates
    }

    /// Root subject common name.
    pub fn root_common_name(&self) -> Option<&str> {
        self.root.common_name.as_deref()
    }

    /// First intermediate subject common name.
    pub fn intermediate_common_name(&self) -> Option<&str> {
        self.intermediates
            .first()
            .and_then(|certificate| certificate.common_name.as_deref())
    }

    /// Canonical PEM of the root certificate.
    pub fn root_pem(&self) -> &str {
        &self.root.pem
    }

    /// Canonical PEM of the intermediate chain (intermediates in file order, then nothing).
    pub fn intermediate_pem(&self) -> String {
        self.intermediates
            .iter()
            .map(|certificate| certificate.pem.as_str())
            .collect()
    }

    /// The chain Caddy's `/pki/ca/<id>/certificates` returns: intermediates first, root last.
    pub fn chain_pem(&self) -> String {
        let mut chain = self.intermediate_pem();
        chain.push_str(&self.root.pem);
        chain
    }

    /// Caddy's `caInfo` JSON shape (`id`, `name`, common names, PEM certificates).
    pub fn info_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name(),
            "root_common_name": self.root_common_name().unwrap_or(""),
            "intermediate_common_name": self.intermediate_common_name().unwrap_or(""),
            "root_certificate": self.root.pem,
            "intermediate_certificate": self.intermediate_pem(),
        })
    }
}

/// Summary of one CA for `pki list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaSummary {
    /// CA identifier.
    pub id: String,
    /// CA directory.
    pub directory: PathBuf,
    /// Root subject common name.
    pub root_common_name: Option<String>,
    /// First intermediate subject common name.
    pub intermediate_common_name: Option<String>,
    /// Root `notAfter` display string.
    pub root_not_after: Option<String>,
    /// Intermediate `notAfter` display string.
    pub intermediate_not_after: Option<String>,
    /// Whether an intermediate chain exists.
    pub has_intermediate: bool,
}

/// Read-only view of the PKI authorities under a Caddy data directory.
#[derive(Debug, Clone)]
pub struct PkiStore {
    data_dir: PathBuf,
}

impl PkiStore {
    /// Create a store rooted at a data directory.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    /// The configured data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The `pki/authorities` directory.
    pub fn authorities_dir(&self) -> PathBuf {
        authorities_directory(&self.data_dir)
    }

    /// List every provisioned CA, sorted by id.
    pub async fn list(&self) -> Result<Vec<CaSummary>, PkiError> {
        let authorities = self.authorities_dir();
        let mut entries = match tokio::fs::read_dir(&authorities).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(PkiError::Io {
                    path: authorities,
                    source: error,
                })
            }
        };
        let mut ids = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|error| PkiError::Io {
            path: authorities.clone(),
            source: error,
        })? {
            let file_type = entry.file_type().await.map_err(|error| PkiError::Io {
                path: entry.path(),
                source: error,
            })?;
            if file_type.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    ids.push(name.to_string());
                }
            }
        }
        ids.sort();
        let mut summaries = Vec::with_capacity(ids.len());
        for id in ids {
            let material = self.load(&id).await?;
            let intermediate = material.intermediates().first();
            summaries.push(CaSummary {
                id: material.id().to_string(),
                directory: material.directory().to_path_buf(),
                root_common_name: material.root_common_name().map(str::to_string),
                intermediate_common_name: material.intermediate_common_name().map(str::to_string),
                root_not_after: material.root().not_after.clone(),
                intermediate_not_after: intermediate
                    .and_then(|certificate| certificate.not_after.clone()),
                has_intermediate: !material.intermediates().is_empty(),
            });
        }
        Ok(summaries)
    }

    /// Load one CA by id. Never creates, generates or repairs anything.
    pub async fn load(&self, id: &str) -> Result<CaMaterial, PkiError> {
        validate_ca_id(id)?;
        let directory = self.authorities_dir().join(id);
        let metadata = tokio::fs::metadata(&directory).await;
        match metadata {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(PkiError::NotFound {
                    id: id.to_string(),
                    directory,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PkiError::NotFound {
                    id: id.to_string(),
                    directory,
                })
            }
            Err(error) => {
                return Err(PkiError::Io {
                    path: directory,
                    source: error,
                })
            }
        }

        let root_path = directory.join("root.crt");
        let root_pem = read_required(&root_path, id, "root").await?;
        let root_der = parse_pem_certificates(&root_pem, &root_path)?;
        if root_der.len() != 1 {
            return Err(PkiError::Certificate {
                path: root_path,
                message: format!(
                    "root certificate file must contain exactly one certificate (found {})",
                    root_der.len()
                ),
            });
        }
        let root = parse_certificate(&root_der[0], &root_path)?;

        let intermediate_path = directory.join("intermediate.crt");
        let intermediates = match tokio::fs::read(&intermediate_path).await {
            Ok(pem) => {
                let ders = parse_pem_certificates(&pem, &intermediate_path)?;
                let mut parsed = Vec::with_capacity(ders.len());
                for der in ders {
                    parsed.push(parse_certificate(&der, &intermediate_path)?);
                }
                parsed
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(PkiError::Io {
                    path: intermediate_path,
                    source: error,
                })
            }
        };

        Ok(CaMaterial {
            id: id.to_string(),
            directory,
            root,
            intermediates,
            configured_name: None,
        })
    }
}

fn validate_ca_id(id: &str) -> Result<(), PkiError> {
    if id.is_empty() {
        return Err(PkiError::InvalidCaId {
            id: id.to_string(),
            reason: "CA id is empty".to_string(),
        });
    }
    if id == "." || id == ".." || id.contains(['/', '\\', '\0']) {
        return Err(PkiError::InvalidCaId {
            id: id.to_string(),
            reason: "CA id must be a single path component".to_string(),
        });
    }
    Ok(())
}

async fn read_required(path: &Path, id: &str, role: &'static str) -> Result<Vec<u8>, PkiError> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(PkiError::MissingCertificate {
                id: id.to_string(),
                path: path.to_path_buf(),
                role,
            })
        }
        Err(error) => Err(PkiError::Io {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

/// Decode every `CERTIFICATE` PEM block in `pem` to DER.
pub fn parse_pem_certificates(pem: &[u8], path: &Path) -> Result<Vec<Vec<u8>>, PkiError> {
    let text = std::str::from_utf8(pem).map_err(|error| PkiError::MalformedPem {
        path: path.to_path_buf(),
        message: format!("file is not UTF-8 PEM: {error}"),
    })?;
    let mut remaining = text;
    let mut decoded = Vec::new();
    while let Some(begin) = remaining.find(BEGIN_CERTIFICATE) {
        let after_begin = &remaining[begin + BEGIN_CERTIFICATE.len()..];
        let Some(end) = after_begin.find(END_CERTIFICATE) else {
            return Err(PkiError::MalformedPem {
                path: path.to_path_buf(),
                message: "unterminated CERTIFICATE PEM block".to_string(),
            });
        };
        let body: String = after_begin[..end]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let der = BASE64
            .decode(body)
            .map_err(|error| PkiError::MalformedPem {
                path: path.to_path_buf(),
                message: format!("invalid base64 in CERTIFICATE block: {error}"),
            })?;
        decoded.push(der);
        remaining = &after_begin[end + END_CERTIFICATE.len()..];
    }
    if decoded.is_empty() {
        return Err(PkiError::MalformedPem {
            path: path.to_path_buf(),
            message: "no CERTIFICATE PEM block found".to_string(),
        });
    }
    Ok(decoded)
}

/// Canonical PEM encoding of a DER certificate.
pub fn certificate_pem(der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut pem = String::with_capacity(encoded.len() + BEGIN_CERTIFICATE.len() * 2 + 64);
    pem.push_str(BEGIN_CERTIFICATE);
    pem.push('\n');
    for chunk in encoded.as_bytes().chunks(64) {
        // base64 output is ASCII.
        // INFEASIBLE: base64 output is ASCII.
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(END_CERTIFICATE);
    pem.push('\n');
    pem
}

// -------------------------------------------------------------------------------------------------
// Minimal DER certificate parsing (CN + validity + serial only).
// -------------------------------------------------------------------------------------------------

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

impl<'a> Tlv<'a> {
    fn parse(bytes: &'a [u8]) -> Result<(Tlv<'a>, &'a [u8]), String> {
        if bytes.len() < 2 {
            return Err("truncated DER element".to_string());
        }
        let tag = bytes[0];
        let (length, header) = parse_der_length(&bytes[1..])?;
        let start = 1 + header;
        let end = start
            .checked_add(length)
            .ok_or_else(|| "DER length overflow".to_string())?;
        if end > bytes.len() {
            return Err(format!(
                "DER element length {length} exceeds remaining {} bytes",
                bytes.len() - start
            ));
        }
        Ok((
            Tlv {
                tag,
                content: &bytes[start..end],
            },
            &bytes[end..],
        ))
    }

    fn children(&self) -> Result<Vec<Tlv<'a>>, String> {
        let mut children = Vec::new();
        let mut remaining = self.content;
        while !remaining.is_empty() {
            let (child, rest) = Tlv::parse(remaining)?;
            children.push(child);
            remaining = rest;
        }
        Ok(children)
    }
}

fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize), String> {
    let Some(&first) = bytes.first() else {
        return Err("missing DER length".to_string());
    };
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || bytes.len() < 1 + count {
        return Err("unsupported DER length encoding".to_string());
    }
    let mut length = 0usize;
    for byte in &bytes[1..1 + count] {
        length = (length << 8) | *byte as usize;
    }
    Ok((length, 1 + count))
}

fn parse_certificate(der: &[u8], path: &Path) -> Result<CertificateInfo, PkiError> {
    parse_certificate_fields(der).map_err(|message| PkiError::Certificate {
        path: path.to_path_buf(),
        message,
    })
}

fn parse_certificate_fields(der: &[u8]) -> Result<CertificateInfo, String> {
    let (certificate, trailing) = Tlv::parse(der)?;
    if !trailing.is_empty() {
        return Err("trailing bytes after certificate".to_string());
    }
    if certificate.tag != 0x30 {
        return Err("certificate is not a SEQUENCE".to_string());
    }
    let parts = certificate.children()?;
    if parts.len() < 3 {
        return Err("certificate SEQUENCE is missing fields".to_string());
    }
    let tbs = &parts[0];
    if tbs.tag != 0x30 {
        return Err("tbsCertificate is not a SEQUENCE".to_string());
    }
    let mut fields = tbs.children()?.into_iter();
    let mut first = fields.next().ok_or("empty tbsCertificate")?;
    if first.tag == 0xa0 {
        // Explicit version.
        first = fields.next().ok_or("missing serial number")?;
    }
    if first.tag != 0x02 {
        return Err("tbsCertificate serial number is not an INTEGER".to_string());
    }
    let serial_hex = hex_lower(first.content);
    let _signature_algorithm = fields.next().ok_or("missing signature algorithm")?;
    let issuer = fields.next().ok_or("missing issuer")?;
    let validity = fields.next().ok_or("missing validity")?;
    let subject = fields.next().ok_or("missing subject")?;

    if validity.tag != 0x30 {
        return Err("validity is not a SEQUENCE".to_string());
    }
    let validity_fields = validity.children()?;
    if validity_fields.len() != 2 {
        return Err("validity must contain notBefore and notAfter".to_string());
    }
    let not_before = parse_asn1_time(&validity_fields[0])?;
    let not_after = parse_asn1_time(&validity_fields[1])?;

    let dns_names = find_dns_names(&tbs)?;
    let not_after_unix = not_after.as_deref().and_then(parse_rfc3339_seconds);
    Ok(CertificateInfo {
        der: der.to_vec(),
        pem: certificate_pem(der),
        common_name: find_common_name(&subject)?,
        issuer_common_name: find_common_name(&issuer)?,
        not_before,
        not_after,
        not_after_unix,
        dns_names,
        serial_hex,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn parse_asn1_time(tlv: &Tlv<'_>) -> Result<Option<String>, String> {
    let text = std::str::from_utf8(tlv.content)
        .map_err(|error| format!("certificate time is not ASCII: {error}"))?;
    match tlv.tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ (RFC 5280 says YY < 50 means 20YY, else 19YY).
            if text.len() < 12 {
                return Ok(None);
            }
            let year: u32 = text
                .get(0..2)
                .and_then(|value| value.parse().ok())
                .ok_or("invalid UTCTime year")?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            Ok(Some(format!(
                "{year:04}-{}-{}T{}:{}:{}Z",
                &text[2..4],
                &text[4..6],
                &text[6..8],
                &text[8..10],
                &text[10..12]
            )))
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ (fractional seconds are dropped).
            if text.len() < 14 {
                return Ok(None);
            }
            Ok(Some(format!(
                "{}-{}-{}T{}:{}:{}Z",
                &text[0..4],
                &text[4..6],
                &text[6..8],
                &text[8..10],
                &text[10..12],
                &text[12..14]
            )))
        }
        other => Err(format!("unsupported certificate time tag 0x{other:02x}")),
    }
}

/// Parse the fixed `YYYY-MM-DDTHH:MM:SSZ` form produced by [`parse_asn1_time`] to Unix seconds.
fn parse_rfc3339_seconds(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let number =
        |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse::<i64>().ok() };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days_from_civil algorithm.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds).ok()
}

/// Extract DNS names (GeneralName tag `[2]`) from the certificate's `subjectAltName` extension.
fn find_dns_names(tbs: &Tlv<'_>) -> Result<Vec<String>, String> {
    let fields = tbs.children()?;
    // tbsCertificate: [0] version?, serial, signature, issuer, validity, subject, spki,
    // then optional issuerUniqueID [1], subjectUniqueID [2] and extensions [3].
    let mut index = fields
        .iter()
        .position(|field| field.tag == 0xa3)
        .map(|position| position)
        .unwrap_or(fields.len());
    if index == fields.len() {
        return Ok(Vec::new());
    }
    let extensions = &fields[index];
    let mut names = Vec::new();
    for extension in extensions.children()? {
        if extension.tag != 0x30 {
            continue;
        }
        let parts = extension.children()?;
        if parts.len() < 2 {
            continue;
        }
        // subjectAltName OID = 2.5.29.17 -> 55 1d 11.
        if parts[0].tag != 0x06 || parts[0].content != [0x55, 0x1d, 0x11] {
            continue;
        }
        let value = parts.last().ok_or("subjectAltName has no value")?;
        if value.tag != 0x04 {
            continue;
        }
        let (general_names, trailing) = Tlv::parse(value.content)?;
        if !trailing.is_empty() || general_names.tag != 0x30 {
            continue;
        }
        for general_name in general_names.children()? {
            if general_name.tag == 0x82 {
                if let Ok(name) = std::str::from_utf8(general_name.content) {
                    names.push(name.to_string());
                }
            }
        }
    }
    let _ = &mut index;
    Ok(names)
}

/// Parse X.509 certificate metadata needed by the runtime inventory.
///
/// This is the same minimal parser used by the read-only `/pki` endpoints: it decodes subject and
/// issuer common names, validity, serial, and DNS subjectAltNames; it never validates signatures.
pub fn certificate_info_from_der(der: &[u8]) -> Option<CertificateInfo> {
    parse_certificate_fields(der).ok()
}

fn find_common_name(name: &Tlv<'_>) -> Result<Option<String>, String> {
    if name.tag != 0x30 {
        return Err("certificate name is not a SEQUENCE".to_string());
    }
    for set in name.children()? {
        if set.tag != 0x31 {
            continue;
        }
        for attribute in set.children()? {
            if attribute.tag != 0x30 {
                continue;
            }
            let pair = attribute.children()?;
            if pair.len() < 2 {
                continue;
            }
            // OID 2.5.4.3 (commonName) encodes as 55 04 03.
            if pair[0].tag == 0x06 && pair[0].content == [0x55, 0x04, 0x03] {
                return Ok(Some(decode_directory_string(&pair[1])?));
            }
        }
    }
    Ok(None)
}

fn decode_directory_string(tlv: &Tlv<'_>) -> Result<String, String> {
    match tlv.tag {
        0x0c | 0x13 | 0x16 | 0x14 | 0x1a => Ok(String::from_utf8_lossy(tlv.content).into_owned()),
        0x1e => {
            // BMPString: UTF-16BE code units.
            if tlv.content.len() % 2 != 0 {
                return Err("BMPString has an odd number of bytes".to_string());
            }
            let units: Vec<u16> = tlv
                .content
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&units))
        }
        other => Err(format!("unsupported common-name string type 0x{other:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Data-directory fixture root: contains `pki/authorities/{local,staging}`.
    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn fixture_store() -> PkiStore {
        PkiStore::new(fixture_dir())
    }

    #[tokio::test]
    async fn loads_the_caddy_layout_and_exposes_metadata() {
        let store = fixture_store();
        let ca = store.load("local").await.expect("load local CA");
        assert_eq!(ca.id(), "local");
        assert_eq!(ca.name(), "local");
        assert_eq!(ca.root_common_name(), Some("caddy-rs test root"));
        assert_eq!(
            ca.intermediate_common_name(),
            Some("caddy-rs test intermediate")
        );
        assert_eq!(
            ca.root().issuer_common_name.as_deref(),
            Some("caddy-rs test root")
        );
        assert_eq!(
            ca.intermediates()[0].issuer_common_name.as_deref(),
            Some("caddy-rs test root")
        );
        assert!(ca.root().not_before.is_some(), "{:?}", ca.root());
        assert!(ca.root().not_after.is_some());
        assert!(!ca.root().serial_hex.is_empty());
        assert!(ca.root_pem().starts_with(BEGIN_CERTIFICATE));
        assert!(ca.root_pem().ends_with("-----END CERTIFICATE-----\n"));
        assert!(ca.intermediate_pem().contains("BEGIN CERTIFICATE"));
        let chain = ca.chain_pem();
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        // Intermediate first, root last (Caddy's /certificates order): the root certificate is the
        // suffix, and the chain starts with the intermediate.
        assert!(chain.ends_with(ca.root_pem()));
        assert!(chain.starts_with(&ca.intermediate_pem()));
        let info = ca.info_json();
        assert_eq!(info["id"], "local");
        assert_eq!(info["name"], "local");
        assert_eq!(info["root_common_name"], "caddy-rs test root");
        assert_eq!(
            info["intermediate_common_name"],
            "caddy-rs test intermediate"
        );
        assert!(info["root_certificate"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn lists_provisioned_cas_sorted_by_id() {
        let store = fixture_store();
        let summaries = store.list().await.expect("list");
        let ids: Vec<&str> = summaries
            .iter()
            .map(|summary| summary.id.as_str())
            .collect();
        assert_eq!(ids, vec!["local", "staging"]);
        assert_eq!(
            summaries[0].root_common_name.as_deref(),
            Some("caddy-rs test root")
        );
        assert!(summaries[0].has_intermediate);
        assert!(summaries[0].root_not_after.is_some());
        assert_eq!(
            summaries[1].root_common_name.as_deref(),
            Some("caddy-rs staging root")
        );
    }

    #[tokio::test]
    async fn missing_and_invalid_cas_produce_located_errors() {
        let store = fixture_store();
        let error = store.load("does-not-exist").await.expect_err("unknown CA");
        assert!(error.is_not_found());
        assert!(error
            .to_string()
            .contains("no certificate authority configured"));
        assert!(error.provisioning_hint().is_some());

        for id in ["", ".", "..", "a/b", "a\\b"] {
            let error = store.load(id).await.expect_err(id);
            assert!(
                matches!(error, PkiError::InvalidCaId { .. }),
                "{id}: {error}"
            );
        }

        // A CA directory missing root.crt is an incomplete CA, not a valid one.
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(directory.path().join("pki/authorities/incomplete")).unwrap();
        let store = PkiStore::new(directory.path());
        let error = store.load("incomplete").await.expect_err("incomplete CA");
        assert!(
            matches!(error, PkiError::MissingCertificate { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("root.crt"));

        // Empty authorities directory lists nothing (never an error).
        let empty = tempfile::tempdir().expect("tempdir");
        assert!(PkiStore::new(empty.path()).list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_pem_is_a_located_error() {
        let directory = tempfile::tempdir().expect("tempdir");
        let ca_dir = directory.path().join("pki/authorities/broken");
        std::fs::create_dir_all(&ca_dir).unwrap();
        std::fs::write(ca_dir.join("root.crt"), b"not a pem file\n").unwrap();
        let store = PkiStore::new(directory.path());
        let error = store.load("broken").await.expect_err("malformed");
        assert!(matches!(error, PkiError::MalformedPem { .. }), "{error}");
        assert!(error.to_string().contains("no CERTIFICATE PEM block"));

        std::fs::write(
            ca_dir.join("root.crt"),
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let error = store.load("broken").await.expect_err("bad base64");
        assert!(matches!(error, PkiError::MalformedPem { .. }), "{error}");
    }

    #[tokio::test]
    async fn root_file_must_contain_exactly_one_certificate() {
        let directory = tempfile::tempdir().expect("tempdir");
        let ca_dir = directory.path().join("pki/authorities/two");
        std::fs::create_dir_all(&ca_dir).unwrap();
        let fixture = fixture_dir().join("pki/authorities/local/root.crt");
        let first = std::fs::read(&fixture).unwrap();
        let mut doubled = first.clone();
        doubled.extend_from_slice(&first);
        std::fs::write(ca_dir.join("root.crt"), doubled).unwrap();
        let store = PkiStore::new(directory.path());
        let error = store.load("two").await.expect_err("two root certs");
        assert!(matches!(error, PkiError::Certificate { .. }), "{error}");
        assert!(error.to_string().contains("exactly one certificate"));
    }

    #[test]
    fn data_dir_resolution_prefers_explicit_then_environment_then_config() {
        let explicit = PathBuf::from("/explicit");
        let environment = PathBuf::from("/environment");
        let config = PathBuf::from("/config");
        assert_eq!(
            resolve_data_dir_with(
                Some(explicit.clone()),
                Some(environment.clone()),
                Some(config.clone())
            ),
            explicit
        );
        assert_eq!(
            resolve_data_dir_with(None, Some(environment.clone()), Some(config.clone())),
            environment
        );
        assert_eq!(
            resolve_data_dir_with(None, None, Some(config.clone())),
            config
        );
        assert_eq!(
            resolve_data_dir_with(None, None, None),
            PathBuf::from(DEFAULT_DATA_DIR)
        );
    }

    #[test]
    fn default_data_dir_is_the_documented_caddy_rs_convention() {
        // caddy-rs deliberately uses the relative `.caddy-rs` project convention instead of
        // Caddy's XDG/HOME `AppDataDir()`; see the resolve_data_dir documentation and DIV-0073.
        assert_eq!(
            resolve_data_dir_with(None, None, None),
            PathBuf::from(".caddy-rs")
        );
        assert_eq!(
            resolve_data_dir_with(None, None, Some(PathBuf::from("/configured/storage-root"))),
            PathBuf::from("/configured/storage-root")
        );
    }

    #[test]
    fn certificate_pem_rendering_is_canonical_and_round_trips() {
        let der = parse_pem_certificates(
            &std::fs::read(fixture_dir().join("pki/authorities/local/root.crt")).unwrap(),
            Path::new("root.crt"),
        )
        .unwrap()
        .remove(0);
        let pem = certificate_pem(&der);
        assert_eq!(pem.lines().next(), Some(BEGIN_CERTIFICATE));
        assert!(pem.lines().all(|line| line.len() <= 64));
        let round_tripped = parse_pem_certificates(pem.as_bytes(), Path::new("root.crt")).unwrap();
        assert_eq!(round_tripped, vec![der]);
    }
}
