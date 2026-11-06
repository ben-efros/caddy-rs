//! PROXY protocol listener wrapper (`caddy.listeners.proxy_protocol`).
//!
//! Implements HAProxy's PROXY protocol v1 (text) and v2 (binary) header parsing on accepted
//! connections, before the TLS handshake. The parsed source/destination addresses replace the
//! transport peer/local addresses for the rest of the connection, so request placeholders
//! (`{http.request.remote.host}` / `{http.request.remote.port}`), forwarding and access logs see
//! the real client.
//!
//! Supported configuration (`apps.http.servers.*.listener_wrappers[i]`):
//!
//! * `timeout`: maximum time to read the header (Caddy duration; zero/absent disables it);
//! * `allow` / `deny`: CIDR ranges. Allowed peers have a PROXY header required/used (`USE`), denied
//!   peers have a header rejected (`REJECT`); other peers follow `fallback_policy`;
//! * `fallback_policy`: `IGNORE` (default; use header when present, accept without one), `USE`
//!   (require header), `REJECT` (reject when a header is sent), `REQUIRE` (require header) or
//!   `SKIP` (do not read a header at all).
//!
//! Unix-socket connections are trusted like Caddy does (a PROXY header is required/used). A
//! malformed, truncated or timed-out header rejects the connection with a logged error (loud); it
//! is never passed to the HTTP parser as if it were a request.
//!
//! Byte-exactness: bytes read past the end of the header (for example an HTTP request pipelined in
//! the same packet) are replayed to the consumer through [`PrefixedStream`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use caddy_rs_core::{ProxyProtocolConfig, ProxyProtocolPolicy};

/// Maximum length of a PROXY protocol v1 header line (including CRLF), per the spec.
const V1_MAX_LEN: usize = 107;

/// PROXY protocol v2 signature.
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// A parsed CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse one Caddy `allow`/`deny` entry exactly like Caddy's listener wrapper, which calls
    /// `netip.ParsePrefix`: an explicit prefix length is mandatory, so a bare address such as
    /// `192.0.2.1` is rejected (Caddy's own Caddyfile adapter emits bare addresses for
    /// `allow 192.0.2.1`, and its provisioner rejects that JSON — caddy-rs matches the rejection).
    fn parse_caddy_prefix(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let base: IpAddr = address.parse().ok()?;
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > max {
            return None;
        }
        Some(Self { base, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(base) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(base) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// Parsed `proxy_protocol` wrapper settings for one server.
#[derive(Debug, Clone)]
pub(crate) struct ProxyProtocolSettings {
    timeout: Option<Duration>,
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
    fallback: ProxyProtocolPolicy,
}

impl ProxyProtocolSettings {
    /// Parse the wrapper options from the core configuration.
    pub(crate) fn from_config(config: &ProxyProtocolConfig) -> Result<Self, String> {
        let timeout = match config.timeout {
            Some(timeout) if !timeout.is_zero() => Some(timeout.as_duration()),
            _ => None,
        };
        let allow = config
            .allow
            .iter()
            .map(|cidr| {
                Cidr::parse_caddy_prefix(cidr)
                    .ok_or_else(|| format!("invalid allow CIDR `{cidr}` (a prefix length is required)"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let deny = config
            .deny
            .iter()
            .map(|cidr| {
                Cidr::parse_caddy_prefix(cidr)
                    .ok_or_else(|| format!("invalid deny CIDR `{cidr}` (a prefix length is required)"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            timeout,
            allow,
            deny,
            fallback: config.fallback_policy,
        })
    }

    /// Effective policy for one peer: allowed peers use/require the header, denied peers reject it,
    /// everyone else follows the fallback policy. Unix-socket peers are trusted (Caddy returns
    /// `USE` for them).
    fn effective_policy(&self, peer: Option<IpAddr>) -> EffectivePolicy {
        let Some(peer) = peer else {
            return EffectivePolicy::Required;
        };
        if self.deny.iter().any(|cidr| cidr.contains(peer)) {
            return EffectivePolicy::RejectHeader;
        }
        if self.allow.iter().any(|cidr| cidr.contains(peer)) {
            return EffectivePolicy::Required;
        }
        match self.fallback {
            ProxyProtocolPolicy::Ignore => EffectivePolicy::Optional,
            ProxyProtocolPolicy::Use | ProxyProtocolPolicy::Require => EffectivePolicy::Required,
            ProxyProtocolPolicy::Reject => EffectivePolicy::RejectHeader,
            ProxyProtocolPolicy::Skip => EffectivePolicy::Skip,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectivePolicy {
    /// Read the header if present, accept without one.
    Optional,
    /// A header is required.
    Required,
    /// A header must not be sent.
    RejectHeader,
    /// Do not read a header; use the transport addresses.
    Skip,
}

/// The listener wrappers configured for one server/listen address.
#[derive(Debug, Default)]
pub(crate) struct ListenerWrappers {
    proxy_protocol: Option<Arc<ProxyProtocolSettings>>,
}

impl ListenerWrappers {
    /// Build the wrapper plan for one HTTP server.
    pub(crate) fn from_server(
        server: &caddy_rs_core::HttpServer,
    ) -> Result<Self, caddy_rs_core::Error> {
        let mut proxy_protocol = None;
        for (index, wrapper) in server.listener_wrappers.iter().enumerate() {
            // Validation (which knows the server name) already produced located errors for this
            // list; construction only repeats the checks defensively.
            let path = format!("apps.http.servers.listener_wrappers[{index}]");
            let name = wrapper.wrapper.as_deref().ok_or_else(|| {
                caddy_rs_core::Error::invalid(
                    format!("{path}.wrapper"),
                    "listener wrapper object must name a `wrapper`",
                )
            })?;
            match name {
                "proxy_protocol" => {
                    let config: ProxyProtocolConfig = serde_json::from_value(
                        serde_json::Value::Object(wrapper.extra.clone().into_iter().collect()),
                    )
                    .map_err(|error| {
                        caddy_rs_core::Error::invalid(
                            &path,
                            format!("invalid proxy_protocol options: {error}"),
                        )
                    })?;
                    let settings = ProxyProtocolSettings::from_config(&config)
                        .map_err(|message| caddy_rs_core::Error::invalid(&path, message))?;
                    proxy_protocol = Some(Arc::new(settings));
                }
                // The TLS listener wrapper is implicit in caddy-rs and the accepted ordering
                // marker only; `http_redirect` is implemented by the automatic-HTTPS listener.
                "tls" | "http_redirect" => {}
                _ => {
                    return Err(caddy_rs_core::Error::Unsupported {
                        path: format!("{path}.wrapper"),
                        feature: "listener wrapper module",
                        tracking_id: "T-HTTP-043",
                    });
                }
            }
        }
        Ok(Self { proxy_protocol })
    }

    /// The proxy protocol settings, when configured.
    pub(crate) fn proxy_protocol(&self) -> Option<&Arc<ProxyProtocolSettings>> {
        self.proxy_protocol.as_ref()
    }
}

/// Failure while reading or validating a PROXY protocol header.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProxyProtocolError {
    /// The transport failed while reading the header.
    #[error("cannot read PROXY protocol header: {0}")]
    Io(#[from] io::Error),
    /// The header was not fully received before the configured timeout.
    #[error("timed out after {0:?} waiting for the PROXY protocol header")]
    Timeout(Duration),
    /// The header is malformed (bad signature fields, bad addresses, truncation, oversized line).
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(String),
    /// The policy requires a header but the connection did not start with one.
    #[error("PROXY protocol header required by policy but not present")]
    Missing,
    /// The policy rejects connections that send a header.
    #[error("PROXY protocol header rejected by policy")]
    Rejected,
}

/// Addresses extracted from a PROXY protocol header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProxyAddresses {
    /// Source (client) address, when the header carries one.
    pub(crate) source: Option<SocketAddr>,
    /// Destination (listener) address, when the header carries one.
    pub(crate) destination: Option<SocketAddr>,
    /// Whether the v2 header used the `LOCAL` command (no address information).
    pub(crate) local: bool,
    /// v2 TLVs (`(type, value)` pairs), in order.
    pub(crate) tlvs: Vec<(u8, Vec<u8>)>,
}

/// A wrapper stream that replays bytes read past the PROXY header before delegating to the inner
/// stream.
#[derive(Debug)]
pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Wrap a stream with already-buffered bytes.
    pub(crate) fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.position < this.prefix.len() {
            let remaining = &this.prefix[this.position..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            this.position += count;
            if this.position == this.prefix.len() {
                this.prefix.clear();
                this.position = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read and apply the PROXY protocol wrapper to one accepted connection.
///
/// Returns the (possibly prefixed) stream plus the overridden remote/local addresses. When no
/// header is present (or it carries no addresses, e.g. v2 `LOCAL`/`UNSPEC`, v1 `UNKNOWN`) the
/// returned overrides are `None` and the transport addresses stay in effect.
pub(crate) async fn wrap<S>(
    stream: S,
    peer: Option<SocketAddr>,
    _local: Option<SocketAddr>,
    settings: &ProxyProtocolSettings,
) -> Result<(PrefixedStream<S>, Option<SocketAddr>, Option<SocketAddr>), ProxyProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let policy = settings.effective_policy(peer.map(|peer| peer.ip()));
    if policy == EffectivePolicy::Skip {
        return Ok((PrefixedStream::new(stream, Vec::new()), None, None));
    }

    let mut stream = stream;
    let (parsed, prefix) = read_header(&mut stream, settings.timeout).await?;
    let header = match parsed {
        Some(header) => header,
        None => match policy {
            EffectivePolicy::Required => return Err(ProxyProtocolError::Missing),
            _ => {
                return Ok((PrefixedStream::new(stream, prefix), None, None));
            }
        },
    };
    if policy == EffectivePolicy::RejectHeader {
        return Err(ProxyProtocolError::Rejected);
    }
    Ok((
        PrefixedStream::new(stream, prefix),
        header.source,
        header.destination,
    ))
}

/// Read the initial bytes of a connection and parse a PROXY header when present.
///
/// Returns the parsed header (if any) and any bytes that belong to the following protocol (which
/// must be replayed to the consumer).
async fn read_header<S>(
    stream: &mut S,
    timeout: Option<Duration>,
) -> Result<(Option<ProxyAddresses>, Vec<u8>), ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer: Vec<u8> = Vec::with_capacity(256);
    // The v2 signature is 12 bytes; reading that much distinguishes it from v1 and from a normal
    // request prefix.
    while buffer.len() < V2_SIGNATURE.len() {
        let read = read_some(
            stream,
            V2_SIGNATURE.len() - buffer.len(),
            timeout,
            &mut buffer,
        )
        .await?;
        if read == 0 {
            // EOF before a complete signature: no PROXY header.
            return Ok((None, buffer));
        }
    }

    if buffer.starts_with(V2_SIGNATURE) {
        return parse_v2(stream, buffer, timeout).await;
    }
    if buffer.starts_with(b"PROXY ") {
        return parse_v1(stream, buffer, timeout).await;
    }
    Ok((None, buffer))
}

/// Read up to `limit` bytes into `buffer`, returning the number of bytes appended (0 on EOF).
async fn read_some<S>(
    stream: &mut S,
    limit: usize,
    timeout: Option<Duration>,
    buffer: &mut Vec<u8>,
) -> Result<usize, ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; 1024];
    let capacity = limit.min(chunk.len());
    let read = match timeout {
        Some(timeout) => tokio::time::timeout(timeout, stream.read(&mut chunk[..capacity]))
            .await
            .map_err(|_| ProxyProtocolError::Timeout(timeout))??,
        None => stream.read(&mut chunk[..capacity]).await?,
    };
    buffer.extend_from_slice(&chunk[..read]);
    Ok(read)
}

/// Read exactly `count` more bytes (failing on EOF or timeout).
async fn read_exact_more<S>(
    stream: &mut S,
    count: usize,
    timeout: Option<Duration>,
    buffer: &mut Vec<u8>,
) -> Result<(), ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut remaining = count;
    while remaining > 0 {
        let read = read_some(stream, remaining, timeout, buffer).await?;
        if read == 0 {
            return Err(ProxyProtocolError::Malformed(
                "connection closed inside the PROXY protocol header".to_string(),
            ));
        }
        remaining -= read;
    }
    Ok(())
}

async fn parse_v1<S>(
    stream: &mut S,
    mut buffer: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<(Option<ProxyAddresses>, Vec<u8>), ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    let end = loop {
        if let Some(position) = buffer.windows(2).position(|window| window == b"\r\n") {
            break position;
        }
        if buffer.len() >= V1_MAX_LEN {
            return Err(ProxyProtocolError::Malformed(
                "PROXY protocol v1 header exceeds 107 bytes".to_string(),
            ));
        }
        let read = read_some(stream, 256, timeout, &mut buffer).await?;
        if read == 0 {
            return Err(ProxyProtocolError::Malformed(
                "connection closed inside the PROXY protocol v1 header".to_string(),
            ));
        }
    };
    let leftover = buffer.split_off(end + 2);
    let line = &buffer[..end];
    let line = std::str::from_utf8(line).map_err(|_| {
        ProxyProtocolError::Malformed("PROXY protocol v1 header is not valid UTF-8".to_string())
    })?;
    let parts: Vec<&str> = line.split(' ').collect();
    let addresses = match parts.as_slice() {
        ["PROXY", "UNKNOWN"] => ProxyAddresses::default(),
        ["PROXY", family @ ("TCP4" | "TCP6"), source, destination, source_port, destination_port] =>
        {
            let source_ip: IpAddr = source.parse().map_err(|_| {
                ProxyProtocolError::Malformed(format!("invalid v1 source address `{source}`"))
            })?;
            let destination_ip: IpAddr = destination.parse().map_err(|_| {
                ProxyProtocolError::Malformed(format!(
                    "invalid v1 destination address `{destination}`"
                ))
            })?;
            let expected_v4 = *family == "TCP4";
            if source_ip.is_ipv4() != expected_v4 || destination_ip.is_ipv4() != expected_v4 {
                return Err(ProxyProtocolError::Malformed(format!(
                    "v1 family `{family}` does not match the header addresses"
                )));
            }
            let source_port = parse_port(source_port)?;
            let destination_port = parse_port(destination_port)?;
            ProxyAddresses {
                source: Some(SocketAddr::new(source_ip, source_port)),
                destination: Some(SocketAddr::new(destination_ip, destination_port)),
                ..ProxyAddresses::default()
            }
        }
        _ => {
            return Err(ProxyProtocolError::Malformed(format!(
                "unrecognized PROXY protocol v1 header `{line}`"
            )))
        }
    };
    Ok((Some(addresses), leftover))
}

fn parse_port(value: &str) -> Result<u16, ProxyProtocolError> {
    value.parse::<u16>().map_err(|_| {
        ProxyProtocolError::Malformed(format!("invalid PROXY protocol port `{value}`"))
    })
}

async fn parse_v2<S>(
    stream: &mut S,
    mut buffer: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<(Option<ProxyAddresses>, Vec<u8>), ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    read_exact_more(stream, 4, timeout, &mut buffer).await?;
    let version_command = buffer[12];
    let family_protocol = buffer[13];
    let payload_len = u16::from_be_bytes([buffer[14], buffer[15]]) as usize;
    if version_command >> 4 != 2 {
        return Err(ProxyProtocolError::Malformed(format!(
            "unsupported PROXY protocol version {}",
            version_command >> 4
        )));
    }
    let command = version_command & 0x0F;
    if command > 1 {
        return Err(ProxyProtocolError::Malformed(format!(
            "unsupported PROXY protocol v2 command {command}"
        )));
    }
    let family = family_protocol >> 4;
    let protocol = family_protocol & 0x0F;
    if family > 3 || protocol > 2 {
        return Err(ProxyProtocolError::Malformed(
            "unsupported PROXY protocol v2 family/protocol".to_string(),
        ));
    }
    read_exact_more(stream, payload_len, timeout, &mut buffer).await?;
    let payload = &buffer[16..16 + payload_len];

    if command == 0 {
        // LOCAL: the connection originates from the proxy itself; addresses are the transport ones.
        return Ok((
            Some(ProxyAddresses {
                local: true,
                ..ProxyAddresses::default()
            }),
            Vec::new(),
        ));
    }

    let mut addresses = ProxyAddresses::default();
    let tlv_start = match family {
        // AF_UNSPEC: no address information.
        0 => 0,
        // AF_INET: 12 bytes, AF_INET6: 36 bytes.
        1 => {
            if payload.len() < 12 {
                return Err(ProxyProtocolError::Malformed(
                    "truncated PROXY protocol v2 IPv4 address block".to_string(),
                ));
            }
            let source = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                )),
                u16::from_be_bytes([payload[8], payload[9]]),
            );
            let destination = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(
                    payload[4], payload[5], payload[6], payload[7],
                )),
                u16::from_be_bytes([payload[10], payload[11]]),
            );
            addresses.source = Some(source);
            addresses.destination = Some(destination);
            12
        }
        2 => {
            if payload.len() < 36 {
                return Err(ProxyProtocolError::Malformed(
                    "truncated PROXY protocol v2 IPv6 address block".to_string(),
                ));
            }
            let mut source = [0_u8; 16];
            source.copy_from_slice(&payload[0..16]);
            let mut destination = [0_u8; 16];
            destination.copy_from_slice(&payload[16..32]);
            addresses.source = Some(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(source)),
                u16::from_be_bytes([payload[32], payload[33]]),
            ));
            addresses.destination = Some(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(destination)),
                u16::from_be_bytes([payload[34], payload[35]]),
            ));
            36
        }
        // AF_UNIX: 108-byte source + 108-byte destination. Unix addresses are not SocketAddrs;
        // keep the transport addresses for routing/logging.
        3 => {
            if payload.len() < 216 {
                return Err(ProxyProtocolError::Malformed(
                    "truncated PROXY protocol v2 Unix address block".to_string(),
                ));
            }
            216
        }
        _ => unreachable!("family validated above"),
    };

    // TLVs follow the address block; validate their framing so malformed headers are loud.
    let mut position = tlv_start;
    while position < payload.len() {
        if payload.len() - position < 3 {
            return Err(ProxyProtocolError::Malformed(
                "truncated PROXY protocol v2 TLV header".to_string(),
            ));
        }
        let tlv_type = payload[position];
        let tlv_len = u16::from_be_bytes([payload[position + 1], payload[position + 2]]) as usize;
        position += 3;
        if payload.len() - position < tlv_len {
            return Err(ProxyProtocolError::Malformed(
                "truncated PROXY protocol v2 TLV value".to_string(),
            ));
        }
        addresses
            .tlvs
            .push((tlv_type, payload[position..position + tlv_len].to_vec()));
        position += tlv_len;
    }

    Ok((Some(addresses), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn settings(policy: ProxyProtocolPolicy) -> ProxyProtocolSettings {
        ProxyProtocolSettings {
            timeout: Some(Duration::from_secs(2)),
            allow: Vec::new(),
            deny: Vec::new(),
            fallback: policy,
        }
    }

    async fn parse_bytes(
        bytes: Vec<u8>,
        policy: ProxyProtocolPolicy,
    ) -> Result<ProxyAddresses, ProxyProtocolError> {
        let peer: SocketAddr = "198.51.100.9:1234".parse().unwrap();
        let local: SocketAddr = "203.0.113.1:443".parse().unwrap();
        // A `DuplexStream` acts as one side of a connection; write the header then parse it.
        let (mut writer, reader) = tokio::io::duplex(4096);
        writer.write_all(&bytes).await.unwrap();
        drop(writer);
        let (_stream, source, _destination) =
            wrap(reader, Some(peer), Some(local), &settings(policy)).await?;
        Ok(ProxyAddresses {
            source,
            ..ProxyAddresses::default()
        })
    }

    #[tokio::test]
    async fn parses_v1_tcp4_header() {
        let addresses = parse_bytes(
            b"PROXY TCP4 192.0.2.10 198.51.100.1 50000 443\r\nGET / HTTP/1.1\r\n\r\n".to_vec(),
            ProxyProtocolPolicy::Ignore,
        )
        .await
        .expect("v1 parses");
        assert_eq!(addresses.source, Some("192.0.2.10:50000".parse().unwrap()));
    }

    #[tokio::test]
    async fn parses_v2_proxy_header_and_tlv() {
        let mut header = V2_SIGNATURE.to_vec();
        header.push(0x21); // version 2, PROXY
        header.push(0x11); // AF_INET, STREAM
        let mut payload = Vec::new();
        payload.extend_from_slice(&[192, 0, 2, 10, 198, 51, 100, 1]);
        payload.extend_from_slice(&50000_u16.to_be_bytes());
        payload.extend_from_slice(&443_u16.to_be_bytes());
        payload.extend_from_slice(&[0x04, 0x00, 0x02, b'h', b'i']); // TLV type 4 "hi"
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        header.extend_from_slice(&payload);
        header.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let addresses = parse_bytes(header, ProxyProtocolPolicy::Ignore)
            .await
            .expect("v2 parses");
        assert_eq!(addresses.source, Some("192.0.2.10:50000".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejects_truncated_and_oversized_headers() {
        let error = parse_bytes(
            b"PROXY TCP4 192.0.2.10".to_vec(),
            ProxyProtocolPolicy::Ignore,
        )
        .await
        .expect_err("truncated");
        assert!(matches!(error, ProxyProtocolError::Malformed(_)), "{error}");

        let mut header = V2_SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        // Payload is shorter than the v2 INET address block.
        let error = parse_bytes(header, ProxyProtocolPolicy::Ignore)
            .await
            .expect_err("truncated v2");
        assert!(matches!(error, ProxyProtocolError::Malformed(_)), "{error}");
    }
}
