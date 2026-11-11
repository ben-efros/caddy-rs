//! Minimal DNS client for dynamic upstream discovery.
//!
//! The offline workspace has no DNS-resolver crate available, so this module implements just
//! enough of RFC 1035 to serve Caddy's dynamic upstream modules: A, AAAA and SRV lookups over
//! UDP (with TCP fallback for truncated responses), optional custom resolver addresses, timeouts,
//! response-ID validation and name decompression.
//!
//! `DnsResolver` is the injection point for tests: production code uses [`SystemDnsResolver`]
//! (options from `/etc/resolv.conf`), tests provide a deterministic fake.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Which IP families an A/AAAA lookup should request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// `ip4` — A records only.
    V4Only,
    /// `ip6` — AAAA records only.
    V6Only,
    /// `ip` — both families.
    Both,
}

/// Transport used to reach a DNS resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverNetwork {
    /// DNS over UDP (with TCP retry on truncation).
    Udp,
    /// DNS over TCP.
    Tcp,
}

/// One configured DNS resolver address (Caddy `resolver.addresses`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverAddress {
    /// Resolver transport.
    pub network: ResolverNetwork,
    /// Resolver socket address.
    pub address: SocketAddr,
}

impl ResolverAddress {
    /// Parse one resolver address: `[udp/|tcp/]host[:port]`, default `udp/...:53`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("resolver address is empty".to_string());
        }
        let (network, rest) = match spec.split_once('/') {
            Some(("udp", rest)) => (ResolverNetwork::Udp, rest),
            Some(("tcp", rest)) => (ResolverNetwork::Tcp, rest),
            Some((other, _)) => {
                return Err(format!(
                    "unsupported resolver network `{other}` (supported: udp, tcp)"
                ))
            }
            None => (ResolverNetwork::Udp, spec),
        };
        let address = parse_host_port(rest, 53)?;
        Ok(Self { network, address })
    }
}

/// Parse `host[:port]` into a socket address, defaulting the port when omitted.
fn parse_host_port(value: &str, default_port: u16) -> Result<SocketAddr, String> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    // A hostname resolver address would need name resolution itself; reject it loudly instead of
    // pretending the configuration works. Operators can use the IP of their resolver.
    Err(format!(
        "invalid DNS resolver address `{value}` (an IP address with optional port is required)"
    ))
}

/// One SRV record as returned by the resolver (before Caddy's ordering).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Target host name.
    pub target: String,
    /// Service port.
    pub port: u16,
    /// RFC 2782 priority (lower is preferred).
    pub priority: u16,
    /// RFC 2782 weight within a priority.
    pub weight: u16,
}

/// DNS lookup interface used by the dynamic upstream modules.
#[async_trait]
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    /// Resolve `name` to addresses of the requested families.
    async fn lookup_ip(
        &self,
        name: &str,
        version: IpVersion,
        resolvers: &[ResolverAddress],
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, String>;

    /// Resolve an SRV query for `name` (already in RFC 2782 `_service._proto.name` form when the
    /// caller configured service/proto separately).
    async fn lookup_srv(
        &self,
        name: &str,
        resolvers: &[ResolverAddress],
        timeout: Duration,
    ) -> Result<Vec<SrvRecord>, String>;
}

/// Resolver using the system DNS configuration (`/etc/resolv.conf`).
#[derive(Debug, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn lookup_ip(
        &self,
        name: &str,
        version: IpVersion,
        resolvers: &[ResolverAddress],
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, String> {
        let resolvers = effective_resolvers(resolvers)?;
        let mut addresses = Vec::new();
        if version != IpVersion::V6Only {
            match query_ip(&resolvers, name, QTYPE_A, timeout).await {
                Ok(mut found) => addresses.append(&mut found),
                Err(error) if version == IpVersion::Both => {
                    // Keep trying AAAA even when A fails, like Go's LookupIP.
                    let _ = error;
                }
                Err(error) => return Err(error),
            }
        }
        if version != IpVersion::V4Only {
            match query_ip(&resolvers, name, QTYPE_AAAA, timeout).await {
                Ok(mut found) => addresses.append(&mut found),
                Err(error) => {
                    if version == IpVersion::V6Only {
                        return Err(error);
                    }
                }
            }
        }
        if addresses.is_empty() {
            return Err(format!("lookup {name}: no addresses found"));
        }
        Ok(addresses)
    }

    async fn lookup_srv(
        &self,
        name: &str,
        resolvers: &[ResolverAddress],
        timeout: Duration,
    ) -> Result<Vec<SrvRecord>, String> {
        let resolvers = effective_resolvers(resolvers)?;
        query_srv(&resolvers, name, timeout).await
    }
}

fn effective_resolvers(configured: &[ResolverAddress]) -> Result<Vec<ResolverAddress>, String> {
    if !configured.is_empty() {
        return Ok(configured.to_vec());
    }
    system_resolvers()
}

/// Parse nameserver entries from `/etc/resolv.conf`.
fn system_resolvers() -> Result<Vec<ResolverAddress>, String> {
    let contents = std::fs::read_to_string("/etc/resolv.conf")
        .map_err(|error| format!("reading /etc/resolv.conf: {error}"))?;
    let mut resolvers = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let spec = rest.trim();
        if spec.is_empty() {
            continue;
        }
        if let Ok(address) = parse_host_port(spec, 53) {
            resolvers.push(ResolverAddress {
                network: ResolverNetwork::Udp,
                address,
            });
        }
    }
    if resolvers.is_empty() {
        return Err("no nameservers configured in /etc/resolv.conf".to_string());
    }
    Ok(resolvers)
}

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;
const QTYPE_SRV: u16 = 33;
const QCLASS_IN: u16 = 1;

/// Query A/AAAA records, following a CNAME chain when the response carries no addresses.
async fn query_ip(
    resolvers: &[ResolverAddress],
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    let mut current = name.to_string();
    for _ in 0..8 {
        let response = query_first_resolver(resolvers, &current, qtype, timeout).await?;
        let parsed = parse_ip_response(&response, qtype)?;
        if !parsed.addresses.is_empty() {
            return Ok(parsed.addresses);
        }
        match parsed.cname {
            Some(target) => current = target,
            None => return Ok(Vec::new()),
        }
    }
    Err(format!("lookup {name}: CNAME chain too long"))
}

async fn query_srv(
    resolvers: &[ResolverAddress],
    name: &str,
    timeout: Duration,
) -> Result<Vec<SrvRecord>, String> {
    let mut current = name.to_string();
    for _ in 0..8 {
        let response = query_first_resolver(resolvers, &current, QTYPE_SRV, timeout).await?;
        let parsed = parse_srv_response(&response)?;
        if !parsed.records.is_empty() {
            return Ok(parsed.records);
        }
        match parsed.cname {
            Some(target) => current = target,
            None => return Ok(Vec::new()),
        }
    }
    Err(format!("lookup SRV {name}: CNAME chain too long"))
}

async fn query_first_resolver(
    resolvers: &[ResolverAddress],
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut last_error = String::new();
    for resolver in resolvers {
        match send_query(resolver, name, qtype, timeout).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn next_query_id() -> u16 {
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Build a DNS query message for `name`/`qtype`.
fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(32 + name.len());
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
    query.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err("DNS name is empty".to_string());
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS label in `{name}`"));
        }
        // INFEASIBLE: the label length was checked to be at most 63 just above.
        query.push(u8::try_from(label.len()).expect("label length checked"));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(query)
}

async fn send_query(
    resolver: &ResolverAddress,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let id = next_query_id();
    let query = encode_query(id, name, qtype)?;
    let response = match resolver.network {
        ResolverNetwork::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|error| format!("binding DNS UDP socket: {error}"))?;
            socket
                .connect(resolver.address)
                .await
                .map_err(|error| format!("connecting DNS UDP socket: {error}"))?;
            socket
                .send(&query)
                .await
                .map_err(|error| format!("sending DNS query: {error}"))?;
            let mut buffer = vec![0_u8; 4096];
            let len = tokio::time::timeout(timeout, socket.recv(&mut buffer))
                .await
                .map_err(|_| format!("DNS query timed out after {timeout:?}"))?
                .map_err(|error| format!("receiving DNS response: {error}"))?;
            let mut response = buffer[..len].to_vec();
            if response.len() >= 4 && response[2] & 0x02 != 0 {
                // TC (truncated) — retry over TCP.
                response = send_tcp_query(&resolver.address, &query, timeout).await?;
            }
            response
        }
        ResolverNetwork::Tcp => send_tcp_query(&resolver.address, &query, timeout).await?,
    };
    if response.len() < 12 {
        return Err("DNS response is truncated".to_string());
    }
    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != id {
        return Err(format!(
            "DNS response id {response_id} does not match query id {id}"
        ));
    }
    Ok(response)
}

async fn send_tcp_query(
    address: &SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let exchange = async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|error| format!("connecting DNS TCP socket: {error}"))?;
        let len = u16::try_from(query.len()).map_err(|_| "DNS query too large".to_string())?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|error| format!("writing DNS query: {error}"))?;
        stream
            .write_all(query)
            .await
            .map_err(|error| format!("writing DNS query: {error}"))?;
        let mut length = [0_u8; 2];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|error| format!("reading DNS response length: {error}"))?;
        let length = usize::from(u16::from_be_bytes(length));
        let mut response = vec![0_u8; length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| format!("reading DNS response: {error}"))?;
        Ok::<_, String>(response)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| format!("DNS query timed out after {timeout:?}"))?
}

#[derive(Debug)]
struct IpResponse {
    addresses: Vec<IpAddr>,
    cname: Option<String>,
}

#[derive(Debug)]
struct SrvResponse {
    records: Vec<SrvRecord>,
    cname: Option<String>,
}

fn parse_ip_response(message: &[u8], qtype: u16) -> Result<IpResponse, String> {
    let mut parser = DnsParser::new(message)?;
    let mut addresses = Vec::new();
    let mut cname = None;
    for answer in parser.answers()? {
        match answer.rtype {
            QTYPE_A if qtype == QTYPE_A && answer.rdata.len() == 4 => {
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    answer.rdata[0],
                    answer.rdata[1],
                    answer.rdata[2],
                    answer.rdata[3],
                )));
            }
            QTYPE_AAAA if qtype == QTYPE_AAAA && answer.rdata.len() == 16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(answer.rdata);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            QTYPE_CNAME if cname.is_none() => {
                cname = Some(decode_name_at(message, answer.rdata_start)?.0);
            }
            _ => {}
        }
    }
    Ok(IpResponse { addresses, cname })
}

fn parse_srv_response(message: &[u8]) -> Result<SrvResponse, String> {
    let mut parser = DnsParser::new(message)?;
    let mut records = Vec::new();
    let mut cname = None;
    for answer in parser.answers()? {
        match answer.rtype {
            QTYPE_SRV if answer.rdata.len() >= 6 => {
                let priority = u16::from_be_bytes([answer.rdata[0], answer.rdata[1]]);
                let weight = u16::from_be_bytes([answer.rdata[2], answer.rdata[3]]);
                let port = u16::from_be_bytes([answer.rdata[4], answer.rdata[5]]);
                let target = decode_name_at(message, answer.rdata_start + 6)?.0;
                records.push(SrvRecord {
                    target,
                    port,
                    priority,
                    weight,
                });
            }
            QTYPE_CNAME if cname.is_none() => {
                cname = Some(decode_name_at(message, answer.rdata_start)?.0);
            }
            _ => {}
        }
    }
    Ok(SrvResponse { records, cname })
}

struct Answer<'a> {
    rtype: u16,
    rdata: &'a [u8],
    /// Absolute offset of `rdata` in the message (compression pointers are message-relative).
    rdata_start: usize,
}

struct DnsParser<'a> {
    message: &'a [u8],
    cursor: usize,
    qdcount: u16,
    ancount: u16,
}

impl<'a> DnsParser<'a> {
    fn new(message: &'a [u8]) -> Result<Self, String> {
        if message.len() < 12 {
            return Err("DNS response is truncated".to_string());
        }
        let flags = u16::from_be_bytes([message[2], message[3]]);
        let rcode = flags & 0x000f;
        if rcode != 0 {
            return Err(format!("DNS server returned error code {rcode}"));
        }
        let qdcount = u16::from_be_bytes([message[4], message[5]]);
        let ancount = u16::from_be_bytes([message[6], message[7]]);
        Ok(Self {
            message,
            cursor: 12,
            qdcount,
            ancount,
        })
    }

    fn answers(&mut self) -> Result<Vec<Answer<'a>>, String> {
        for _ in 0..self.qdcount {
            self.skip_name()?;
            self.cursor += 4;
            if self.cursor > self.message.len() {
                return Err("DNS question is truncated".to_string());
            }
        }
        let label = self.message;
        let mut answers = Vec::new();
        for _ in 0..self.ancount {
            let _name = self.read_name()?;
            if self.cursor + 10 > label.len() {
                return Err("DNS answer is truncated".to_string());
            }
            let rtype = u16::from_be_bytes([label[self.cursor], label[self.cursor + 1]]);
            let rdlength = usize::from(u16::from_be_bytes([
                label[self.cursor + 8],
                label[self.cursor + 9],
            ]));
            self.cursor += 10;
            let rdata_start = self.cursor;
            if rdata_start + rdlength > label.len() {
                return Err("DNS answer rdata is truncated".to_string());
            }
            self.cursor += rdlength;
            answers.push(Answer {
                rtype,
                rdata: &label[rdata_start..rdata_start + rdlength],
                rdata_start,
            });
        }
        Ok(answers)
    }

    fn skip_name(&mut self) -> Result<(), String> {
        self.read_name().map(|_| ())
    }

    fn read_name(&mut self) -> Result<String, String> {
        let (name, next) = decode_name_at(self.message, self.cursor)?;
        self.cursor = next;
        Ok(name)
    }
}

/// Decode a DNS name at an absolute message offset, following compression pointers.
fn decode_name_at(message: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = start;
    let mut jumps = 0;
    loop {
        if cursor >= message.len() {
            return Err("DNS name is truncated".to_string());
        }
        let length = message[cursor];
        if length == 0 {
            if jumps == 0 {
                next = cursor + 1;
            }
            return Ok((labels.join("."), next));
        }
        if length & 0xc0 == 0xc0 {
            if cursor + 1 >= message.len() {
                return Err("DNS compression pointer is truncated".to_string());
            }
            let pointer = usize::from(u16::from_be_bytes([
                message[cursor] & 0x3f,
                message[cursor + 1],
            ]));
            if jumps == 0 {
                next = cursor + 2;
            }
            jumps += 1;
            if jumps > 64 || pointer >= message.len() {
                return Err("DNS compression pointer loop".to_string());
            }
            cursor = pointer;
            continue;
        }
        let length = usize::from(length);
        cursor += 1;
        if cursor + length > message.len() {
            return Err("DNS label is truncated".to_string());
        }
        labels.push(String::from_utf8_lossy(&message[cursor..cursor + length]).into_owned());
        cursor += length;
        if jumps == 0 {
            next = cursor;
        }
    }
}

/// Caddy/Go SRV ordering: ascending priority, weighted randomisation within each priority.
pub fn order_srv_records(records: &mut [SrvRecord]) {
    records.sort_by_key(|record| record.priority);
    let mut index = 0;
    while index < records.len() {
        let priority = records[index].priority;
        let end = records[index..]
            .iter()
            .position(|record| record.priority != priority)
            .map(|offset| index + offset)
            .unwrap_or(records.len());
        weighted_shuffle(&mut records[index..end]);
        index = end;
    }
}

/// Shuffle records with probability proportional to their RFC 2782 weight (zero weights after
/// positive ones, in random order).
fn weighted_shuffle(records: &mut [SrvRecord]) {
    let mut rng = SimpleRng::seeded();
    for position in 0..records.len() {
        let remaining = &records[position..];
        let total_weight: u64 = remaining
            .iter()
            .map(|record| u64::from(record.weight))
            .sum();
        if total_weight == 0 {
            let offset = rng.below(remaining.len());
            records.swap(position, position + offset);
            continue;
        }
        let mut pick = rng.below_weight(total_weight);
        let mut chosen = remaining.len() - 1;
        for (offset, record) in remaining.iter().enumerate() {
            let weight = u64::from(record.weight);
            if pick < weight {
                chosen = offset;
                break;
            }
            pick -= weight;
        }
        records.swap(position, position + chosen);
    }
}

/// Small xorshift RNG so weighted ordering needs no extra dependency.
struct SimpleRng(u64);

impl SimpleRng {
    fn seeded() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Self(nanos | 1)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        (self.next() % bound as u64) as usize
    }

    fn below_weight(&mut self, total: u64) -> u64 {
        if total == 0 {
            return 0;
        }
        self.next() % total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(questions: &[(&str, u16)], answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0x1234_u16.to_be_bytes());
        message.extend_from_slice(&0x8180_u16.to_be_bytes());
        message.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        message.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        for (name, qtype) in questions {
            for label in name.trim_end_matches('.').split('.') {
                message.push(label.len() as u8);
                message.extend_from_slice(label.as_bytes());
            }
            message.push(0);
            message.extend_from_slice(&qtype.to_be_bytes());
            message.extend_from_slice(&1_u16.to_be_bytes());
        }
        for (rtype, rdata) in answers {
            // Owner name is a pointer to the question name at offset 12.
            message.extend_from_slice(&[0xc0, 12]);
            message.extend_from_slice(&rtype.to_be_bytes());
            message.extend_from_slice(&1_u16.to_be_bytes());
            message.extend_from_slice(&300_u32.to_be_bytes());
            message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            message.extend_from_slice(rdata);
        }
        message
    }

    #[test]
    fn parses_a_aaaa_and_srv_answers_with_compression() {
        let a = response(
            &[("example.com.", QTYPE_A)],
            &[(QTYPE_A, vec![192, 0, 2, 10])],
        );
        let parsed = parse_ip_response(&a, QTYPE_A).unwrap();
        assert_eq!(
            parsed.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );

        let aaaa = response(
            &[("example.com.", QTYPE_AAAA)],
            &[(
                QTYPE_AAAA,
                vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            )],
        );
        let parsed = parse_ip_response(&aaaa, QTYPE_AAAA).unwrap();
        assert_eq!(
            parsed.addresses,
            vec![IpAddr::V6("2001:db8::1".parse().unwrap())]
        );

        // SRV rdata: priority, weight, port, then a compressed target name.
        let mut srv_rdata = Vec::new();
        srv_rdata.extend_from_slice(&10_u16.to_be_bytes());
        srv_rdata.extend_from_slice(&5_u16.to_be_bytes());
        srv_rdata.extend_from_slice(&8080_u16.to_be_bytes());
        srv_rdata.extend_from_slice(&[0xc0, 12]);
        let srv = response(
            &[("_http._tcp.example.com.", QTYPE_SRV)],
            &[(QTYPE_SRV, srv_rdata)],
        );
        let parsed = parse_srv_response(&srv).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].priority, 10);
        assert_eq!(parsed.records[0].weight, 5);
        assert_eq!(parsed.records[0].port, 8080);
        assert_eq!(parsed.records[0].target, "_http._tcp.example.com");

        // CNAME is decoded from rdata even when it uses a compression pointer.
        let cname = response(
            &[("www.example.com.", QTYPE_A)],
            &[(QTYPE_CNAME, vec![0xc0, 12])],
        );
        let parsed = parse_ip_response(&cname, QTYPE_A).unwrap();
        assert_eq!(parsed.addresses.len(), 0);
        assert_eq!(parsed.cname.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn query_encoding_and_error_codes() {
        let query = encode_query(7, "_http._tcp.example.com", QTYPE_SRV).unwrap();
        assert_eq!(&query[..2], &7_u16.to_be_bytes());
        assert_eq!(&query[4..6], &1_u16.to_be_bytes());
        assert!(query.ends_with(&[0, 0, 33, 0, 1]));

        let mut nxdomain = response(&[("missing.example.", QTYPE_A)], &[]);
        nxdomain[3] = 0x83; // rcode 3 = NXDOMAIN
        let error = parse_ip_response(&nxdomain, QTYPE_A).unwrap_err();
        assert!(error.contains("error code 3"), "{error}");
    }

    #[tokio::test]
    async fn system_resolver_performs_a_real_udp_query() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..len];
            let mut reply = response(
                &[("example.com.", QTYPE_A)],
                &[(QTYPE_A, vec![192, 0, 2, 33])],
            );
            // Echo the query id so the client accepts the response.
            reply[..2].copy_from_slice(&query[..2]);
            socket.send_to(&reply, peer).await.unwrap();
        });
        let addresses = SystemDnsResolver
            .lookup_ip(
                "example.com",
                IpVersion::V4Only,
                &[ResolverAddress {
                    network: ResolverNetwork::Udp,
                    address,
                }],
                Duration::from_secs(2),
            )
            .await
            .expect("UDP lookup succeeds");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33))]);
        server.await.unwrap();
    }

    #[test]
    fn srv_ordering_prefers_priority_and_keeps_all_records() {
        let mut records = vec![
            SrvRecord {
                target: "a".into(),
                port: 1,
                priority: 20,
                weight: 10,
            },
            SrvRecord {
                target: "b".into(),
                port: 2,
                priority: 10,
                weight: 1,
            },
            SrvRecord {
                target: "c".into(),
                port: 3,
                priority: 10,
                weight: 100,
            },
            SrvRecord {
                target: "d".into(),
                port: 4,
                priority: 10,
                weight: 0,
            },
        ];
        order_srv_records(&mut records);
        assert_eq!(records.len(), 4);
        assert_eq!(records[3].target, "a", "higher priority value comes last");
        let mut low: Vec<&str> = records[..3]
            .iter()
            .map(|record| record.target.as_str())
            .collect();
        low.sort_unstable();
        assert_eq!(low, vec!["b", "c", "d"]);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.priority == 10)
                .map(|record| record.port)
                .max(),
            Some(4)
        );

        // Several shuffles must keep every record (weighted selection, not dropping).
        for _ in 0..20 {
            let mut shuffled = vec![
                SrvRecord {
                    target: "a".into(),
                    port: 1,
                    priority: 1,
                    weight: 1,
                },
                SrvRecord {
                    target: "b".into(),
                    port: 2,
                    priority: 1,
                    weight: 2,
                },
                SrvRecord {
                    target: "c".into(),
                    port: 3,
                    priority: 1,
                    weight: 3,
                },
            ];
            order_srv_records(&mut shuffled);
            assert_eq!(shuffled.len(), 3);
        }
    }

    #[test]
    fn resolver_address_forms() {
        assert_eq!(
            ResolverAddress::parse("8.8.8.8").unwrap(),
            ResolverAddress {
                network: ResolverNetwork::Udp,
                address: "8.8.8.8:53".parse().unwrap()
            }
        );
        assert_eq!(
            ResolverAddress::parse("tcp/[2001:db8::1]:5353")
                .unwrap()
                .network,
            ResolverNetwork::Tcp
        );
        assert!(ResolverAddress::parse("name.example").is_err());
    }
}
