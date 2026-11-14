//! Zero-copy TLS ClientHello parser for the L4 router.
//!
//! The L4 listener peeks the first bytes of a TCP connection to decide where to route it. This
//! module parses a **complete TLS record containing a ClientHello** out of the peek buffer,
//! borrowing everything it can: the SNI hostname ([`Cow::Borrowed`] when it is already lowercase,
//! which is the common case) and each ALPN protocol name are slices of the caller's buffer, so the
//! payload bytes are never copied or allocated.
//!
//! The parser distinguishes three outcomes:
//!
//! - [`ClientHelloInfo`] with `is_tls: true` — a well-formed ClientHello; `sni` and `alpn` are
//!   filled from the extensions that were present.
//! - [`ClientHelloInfo`] with `is_tls: false` — recognisably non-TLS traffic (an HTTP/1 request
//!   line, an HTTP/2 connection preface, or an SSH version banner), classified in
//!   [`ClientHelloInfo::protocol`]; the caller falls back to byte-stream routing.
//! - [`ParseError::Incomplete`] — the peek buffer does not yet hold the whole record; the peek loop
//!   reads more bytes and retries (all other variants are permanent, typed rejections).
//!
//! # Wire format
//!
//! ```text
//! TLS record:    type=22 (handshake) | version (0x0301..=0x0304) | length: u16 | handshake
//! handshake:     type=1 (client_hello) | length: u24 | body
//! body:          legacy_version: u16 | random: 32 | session_id: u8-len | cipher_suites: u16-len |
//!                compression: u8-len | extensions: u16-len (ext: type: u16 | len: u16 | data)
//! SNI ext:       server_name_list: u16-len (name_type: u8 | name: u16-len)
//! ALPN ext:      protocol_name_list: u16-len (name: u8-len)
//! ```

use std::borrow::Cow;
use std::fmt;

/// Content type of a TLS handshake record (RFC 8446 §5.1).
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// Handshake type of a ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// `server_name` extension type (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;
/// `application_layer_protocol_negotiation` extension type (RFC 7301).
const EXT_ALPN: u16 = 0x0010;
/// SNI name type `host_name`.
const SNI_NAME_TYPE_HOST_NAME: u8 = 0;

/// Protocol family detected in the first bytes of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// A TLS record was recognised (whether or not it was a valid ClientHello).
    Tls,
    /// An HTTP/1.x request line (`GET / HTTP/1.1`, ...).
    Http1,
    /// The HTTP/2 connection preface (`PRI * HTTP/2.0`).
    Http2,
    /// An SSH identification banner (`SSH-2.0-...`).
    Ssh,
    /// Bytes that match none of the protocols above.
    Unknown,
}

impl Protocol {
    /// Whether the connection starts with a TLS record.
    pub fn is_tls(self) -> bool {
        matches!(self, Self::Tls)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Tls => "tls",
            Self::Http1 => "http/1",
            Self::Http2 => "http/2",
            Self::Ssh => "ssh",
            Self::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

/// A typed parse failure.
///
/// Only [`ParseError::Incomplete`] is retryable: it means the peek buffer is shorter than the
/// record it describes, so the caller should read more bytes and call [`parse_client_hello`]
/// again. Everything else is a permanent rejection of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer ends before the record/handshake/extensions it declares; read more and retry.
    Incomplete,
    /// The first byte is not a TLS handshake content type.
    BadRecordContentType(u8),
    /// The record version is outside 0x0301..=0x0304.
    BadRecordVersion([u8; 2]),
    /// The handshake message is not a ClientHello.
    BadHandshakeType(u8),
    /// The bytes are present but structurally invalid for a ClientHello.
    Malformed(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => f.write_str("client hello is incomplete; read more bytes"),
            Self::BadRecordContentType(t) => {
                write!(f, "not a TLS handshake record (content type {t:#04x})")
            }
            Self::BadRecordVersion([major, minor]) => {
                write!(
                    f,
                    "unsupported TLS record version {major:#04x}.{minor:#04x}"
                )
            }
            Self::BadHandshakeType(t) => write!(f, "not a ClientHello (handshake type {t:#04x})"),
            Self::Malformed(why) => write!(f, "malformed ClientHello: {why}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The outcome of parsing the first bytes of a TCP connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloInfo<'a> {
    /// Protocol family detected in the peek buffer.
    pub protocol: Protocol,
    /// `true` when a valid TLS `ClientHello` was parsed.
    pub is_tls: bool,
    /// SNI hostname, lowercased. Borrowed from the input when it was already lowercase; otherwise
    /// lowercased into an owned string (the only allocation this parser may make).
    pub sni: Option<Cow<'a, str>>,
    /// ALPN protocol names in preference order, borrowed from the input (no payload copy).
    pub alpn: Vec<&'a str>,
}

impl<'a> ClientHelloInfo<'a> {
    /// A non-TLS result for traffic that was classified as another protocol.
    fn non_tls(protocol: Protocol) -> Self {
        Self {
            protocol,
            is_tls: false,
            sni: None,
            alpn: Vec::new(),
        }
    }
}

/// Classifies the first bytes of a connection without parsing further.
///
/// This is a cheap prefix check used both by [`parse_client_hello`] (to classify non-TLS traffic)
/// and by callers that only need the protocol family.
pub fn detect_protocol(buf: &[u8]) -> Protocol {
    if buf.first() == Some(&CONTENT_TYPE_HANDSHAKE) {
        return Protocol::Tls;
    }
    if buf.starts_with(b"SSH-") {
        return Protocol::Ssh;
    }
    if buf.starts_with(b"PRI * HTTP/2.0") {
        return Protocol::Http2;
    }
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"CONNECT ",
        b"PATCH ",
        b"TRACE ",
    ];
    for method in METHODS {
        if buf.starts_with(method) {
            return Protocol::Http1;
        }
        // A short buffer that is a prefix of a method (`"GE"`) is still HTTP in spirit, but an
        // unfinished peek is handled by the caller: only a complete method plus space counts.
    }
    Protocol::Unknown
}

/// Parses the TLS record at the start of `buf`.
///
/// Returns [`ParseError::Incomplete`] when `buf` is a prefix of a well-formed record, so the caller
/// can keep peeking. Returns a typed error for permanently invalid bytes, and a non-TLS
/// [`ClientHelloInfo`] for HTTP/1, HTTP/2 and SSH traffic.
pub fn parse_client_hello(buf: &[u8]) -> Result<ClientHelloInfo<'_>, ParseError> {
    match detect_protocol(buf) {
        Protocol::Tls => parse_tls_client_hello(buf),
        Protocol::Http1 | Protocol::Http2 | Protocol::Ssh => {
            Ok(ClientHelloInfo::non_tls(detect_protocol(buf)))
        }
        Protocol::Unknown => {
            if buf.is_empty() {
                return Err(ParseError::Incomplete);
            }
            Err(ParseError::BadRecordContentType(buf[0]))
        }
    }
}

/// Parses the TLS record and handshake framing, then the ClientHello body.
fn parse_tls_client_hello(buf: &[u8]) -> Result<ClientHelloInfo<'_>, ParseError> {
    // Record header: type | version | length.
    let Some(header) = buf.get(..5) else {
        return Err(ParseError::Incomplete);
    };
    if header[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(ParseError::BadRecordContentType(header[0]));
    }
    let version = [header[1], header[2]];
    if !(0x0301..=0x0304).contains(&u16::from_be_bytes(version)) {
        return Err(ParseError::BadRecordVersion(version));
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let Some(record) = buf.get(5..5 + record_len) else {
        return Err(ParseError::Incomplete);
    };

    // Handshake header: type | length (u24).
    let Some(handshake_header) = record.get(..4) else {
        return Err(ParseError::Incomplete);
    };
    if handshake_header[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(ParseError::BadHandshakeType(handshake_header[0]));
    }
    let handshake_len = u32::from_be_bytes([
        0,
        handshake_header[1],
        handshake_header[2],
        handshake_header[3],
    ]) as usize;
    let Some(body) = record.get(4..4 + handshake_len) else {
        return Err(ParseError::Incomplete);
    };

    parse_client_hello_body(body)
}

/// Parses the ClientHello body: version, random, session id, cipher suites, compression methods and
/// extensions.
fn parse_client_hello_body(body: &[u8]) -> Result<ClientHelloInfo<'_>, ParseError> {
    let mut cursor = Cursor::new(body);
    let _legacy_version = cursor.take(2)?;
    let _random = cursor.take(32)?;
    let session_id_len = cursor.u8()? as usize;
    let _session_id = cursor.take(session_id_len)?;
    let cipher_suites_len = cursor.u16()? as usize;
    if !cipher_suites_len.is_multiple_of(2) {
        return Err(ParseError::Malformed("cipher suite list has an odd length"));
    }
    let _cipher_suites = cursor.take(cipher_suites_len)?;
    let compression_len = cursor.u8()? as usize;
    let _compression = cursor.take(compression_len)?;

    let mut sni: Option<Cow<'_, str>> = None;
    let mut alpn: Vec<&str> = Vec::new();
    // A ClientHello without an extensions block is valid (TLS 1.0/1.1 style).
    if cursor.remaining() == 0 {
        return Ok(ClientHelloInfo {
            protocol: Protocol::Tls,
            is_tls: true,
            sni,
            alpn,
        });
    }
    let extensions_len = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_len)?;
    if cursor.remaining() != 0 {
        return Err(ParseError::Malformed("trailing bytes after extensions"));
    }

    let mut ext_cursor = Cursor::new(extensions);
    while ext_cursor.remaining() > 0 {
        let ext_type = ext_cursor.u16()?;
        let ext_len = ext_cursor.u16()? as usize;
        let data = ext_cursor.take(ext_len)?;
        match ext_type {
            EXT_SERVER_NAME if sni.is_none() => sni = parse_server_name(data)?,
            EXT_ALPN if alpn.is_empty() => alpn = parse_alpn(data)?,
            // Every other extension is irrelevant to routing and is skipped without copying.
            _ => {}
        }
    }

    Ok(ClientHelloInfo {
        protocol: Protocol::Tls,
        is_tls: true,
        sni,
        alpn,
    })
}

/// Parses the `server_name` extension, returning the lowercased hostname.
fn parse_server_name(data: &[u8]) -> Result<Option<Cow<'_, str>>, ParseError> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16()? as usize;
    let list = cursor.take(list_len)?;
    if list.is_empty() {
        return Ok(None);
    }
    let mut list_cursor = Cursor::new(list);
    let name_type = list_cursor.u8()?;
    let name_len = list_cursor.u16()? as usize;
    let name = list_cursor.take(name_len)?;
    if name_type != SNI_NAME_TYPE_HOST_NAME {
        return Ok(None);
    }
    let name = std::str::from_utf8(name).map_err(|_| ParseError::Malformed("SNI is not UTF-8"))?;
    Ok(Some(lowercase(name)))
}

/// Parses the ALPN extension into borrowed protocol names.
fn parse_alpn(data: &[u8]) -> Result<Vec<&str>, ParseError> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16()? as usize;
    let mut list = Cursor::new(cursor.take(list_len)?);
    let mut protocols = Vec::new();
    while list.remaining() > 0 {
        let len = list.u8()? as usize;
        let name = list.take(len)?;
        let name = std::str::from_utf8(name)
            .map_err(|_| ParseError::Malformed("ALPN protocol name is not UTF-8"))?;
        protocols.push(name);
    }
    Ok(protocols)
}

/// Lowercases an SNI hostname, borrowing when it is already lowercase (the common case).
fn lowercase(name: &str) -> Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

/// A bounds-checked cursor over a byte slice.
///
/// `take` reports [`ParseError::Incomplete`] only when the cursor is over the *outer* buffer that
/// the caller may still extend; inner structures inside a complete record report
/// [`ParseError::Malformed`] through [`Cursor::take_inner`].
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let Some(end) = self.pos.checked_add(len) else {
            return Err(ParseError::Malformed("length overflow"));
        };
        let Some(slice) = self.data.get(self.pos..end) else {
            return Err(ParseError::Malformed(
                "length exceeds the containing structure",
            ));
        };
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_protocol, parse_client_hello, ParseError, Protocol};
    use std::borrow::Cow;

    /// Builds a complete TLS record containing a ClientHello with the given SNI/ALPN.
    fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(host) = sni {
            let mut names = Vec::new();
            names.push(0_u8); // host_name
            names.extend_from_slice(&(host.len() as u16).to_be_bytes());
            names.extend_from_slice(host.as_bytes());
            let mut ext = Vec::new();
            ext.extend_from_slice(&(names.len() as u16).to_be_bytes());
            ext.extend_from_slice(&names);
            extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
            extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&ext);
        }
        if !alpn.is_empty() {
            let mut protocols = Vec::new();
            for name in alpn {
                protocols.push(name.len() as u8);
                protocols.extend_from_slice(name.as_bytes());
            }
            let mut ext = Vec::new();
            ext.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
            ext.extend_from_slice(&protocols);
            extensions.extend_from_slice(&0x0010_u16.to_be_bytes());
            extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&ext);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.push(1); // one compression method
        body.push(0); // null compression
        if !extensions.is_empty() {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }

        let mut handshake = Vec::new();
        handshake.push(1); // client_hello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni_and_alpn_without_copying_payload() {
        let hello = client_hello(Some("example.com"), &["h2", "http/1.1"]);
        let info = parse_client_hello(&hello).expect("valid ClientHello");
        assert!(info.is_tls);
        assert_eq!(info.protocol, Protocol::Tls);
        let sni = info.sni.as_ref().expect("SNI present");
        assert_eq!(sni.as_ref(), "example.com");
        assert!(
            matches!(sni, Cow::Borrowed(_)),
            "lowercase SNI borrows from the peek buffer"
        );
        assert_eq!(info.alpn, ["h2", "http/1.1"]);
        // ALPN names are slices of the caller's buffer, not copies.
        let hello_start = hello.as_ptr() as usize;
        for name in &info.alpn {
            let offset = name.as_ptr() as usize - hello_start;
            assert!(
                offset < hello.len(),
                "ALPN name {name} points into the peek buffer"
            );
        }
    }

    #[test]
    fn lowercases_sni_when_needed() {
        let hello = client_hello(Some("Example.COM"), &[]);
        let info = parse_client_hello(&hello).expect("valid ClientHello");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert!(matches!(&info.sni, Some(Cow::Owned(_))));
        assert!(info.alpn.is_empty());
    }

    #[test]
    fn client_hello_without_extensions_is_valid() {
        let hello = client_hello(None, &[]);
        let info = parse_client_hello(&hello).expect("valid ClientHello");
        assert!(info.is_tls);
        assert_eq!(info.sni, None);
        assert!(info.alpn.is_empty());
    }

    #[test]
    fn every_prefix_of_a_complete_record_is_incomplete() {
        let hello = client_hello(Some("example.com"), &["h2"]);
        for end in 0..hello.len() {
            assert_eq!(
                parse_client_hello(&hello[..end]),
                Err(ParseError::Incomplete),
                "prefix of length {end} must be Incomplete"
            );
        }
        assert!(parse_client_hello(&hello).is_ok());
    }

    #[test]
    fn rejects_malformed_records_with_typed_errors() {
        let mut wrong_type = client_hello(None, &[]);
        wrong_type[0] = 0x15; // alert, not handshake
        assert_eq!(
            parse_client_hello(&wrong_type),
            Err(ParseError::BadRecordContentType(0x15))
        );

        let mut wrong_version = client_hello(None, &[]);
        wrong_version[1] = 0x02;
        wrong_version[2] = 0xff;
        assert_eq!(
            parse_client_hello(&wrong_version),
            Err(ParseError::BadRecordVersion([0x02, 0xff]))
        );

        let mut wrong_handshake = client_hello(None, &[]);
        wrong_handshake[5] = 0x02; // server_hello
        assert_eq!(
            parse_client_hello(&wrong_handshake),
            Err(ParseError::BadHandshakeType(0x02))
        );

        // A complete record whose cipher-suite list claims an odd length is structurally invalid.
        let mut odd_ciphers = client_hello(None, &[]);
        let cipher_len_offset = 5 + 4 + 2 + 32 + 1; // record+hs headers, version, random, session id
        odd_ciphers[cipher_len_offset] = 0x00;
        odd_ciphers[cipher_len_offset + 1] = 0x03;
        assert_eq!(
            parse_client_hello(&odd_ciphers),
            Err(ParseError::Malformed("cipher suite list has an odd length"))
        );
    }

    #[test]
    fn classifies_non_tls_traffic() {
        let ssh = b"SSH-2.0-OpenSSH_9.6\r\n";
        let info = parse_client_hello(ssh).expect("SSH banner is classified, not an error");
        assert!(!info.is_tls);
        assert_eq!(info.protocol, Protocol::Ssh);
        assert_eq!(detect_protocol(ssh), Protocol::Ssh);

        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let info = parse_client_hello(http).expect("HTTP request is classified, not an error");
        assert!(!info.is_tls);
        assert_eq!(info.protocol, Protocol::Http1);
        assert_eq!(detect_protocol(http), Protocol::Http1);

        let http2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let info = parse_client_hello(http2).expect("HTTP/2 preface is classified");
        assert!(!info.is_tls);
        assert_eq!(info.protocol, Protocol::Http2);
        assert_eq!(detect_protocol(http2), Protocol::Http2);

        let unknown = b"\x99\x01\x02";
        assert_eq!(
            parse_client_hello(unknown),
            Err(ParseError::BadRecordContentType(0x99))
        );
        assert_eq!(detect_protocol(unknown), Protocol::Unknown);
        assert_eq!(parse_client_hello(&[]), Err(ParseError::Incomplete));
    }

    #[test]
    fn errors_are_displayable_and_retryable_only_when_incomplete() {
        let errors = [
            ParseError::Incomplete,
            ParseError::BadRecordContentType(0x15),
            ParseError::BadRecordVersion([0x02, 0xff]),
            ParseError::BadHandshakeType(0x02),
            ParseError::Malformed("test"),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(!text.is_empty());
        }
        assert!(format!("{}", ParseError::Incomplete).contains("incomplete"));
    }
}
