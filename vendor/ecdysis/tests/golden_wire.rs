//! T-OPS-106 golden-bytes wire test.
//!
//! bincode 1.3.3 was replaced by bincode 2.0.1 with `config::legacy()` (see `src/compat.rs`).
//! A parent and child process exchange the listener registry over a pipe across an upgrade,
//! so the two versions MUST produce identical bytes. This test does not assume that; it
//! asserts it against a fixture produced by real bincode 1.3.3.
//!
//! GOLDEN_BYTES below was emitted by:
//!   bincode = "=1.3.3";  bincode::serialize(&registry).unwrap()
//! over the `registry` value built in `fixture()` with the type definitions copied verbatim
//! from upstream `src/registry.rs`. Do not regenerate it with bincode 2.x — its whole value
//! is that it came from the OLD encoder.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

use ecdysis::compat::wire_config;
use serde::{Deserialize, Serialize};

// Verbatim copies of `src/registry.rs` (upstream ecdysis 1.1.1). The real types are
// `pub(crate)`, so the test restates them; `src/compat.rs`'s tests cover the live type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
enum SockInfo {
    Unix(Option<PathBuf>),
    Tcp(SocketAddr),
    Udp(SocketAddr),
    UnboundUnixDatagram(String),
    UnixSeqpacket(Option<PathBuf>),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
struct ListenerInfo {
    fd: i32,
    sock_info: SockInfo,
}

/// 118 bytes produced by bincode 1.3.3, hex-encoded.
const GOLDEN_BYTES: &str = "05000000000000000300000000000000010f000000000000002f72756e2f63616464792e736f636b0400000001000000000000007f000001901f05000000020000000000000000000000e91406000000030000001100000000000000656364797369732d756e626f756e642d30070000000400000000";

fn fixture() -> Vec<ListenerInfo> {
    let tcp = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    let udp = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 5353));
    vec![
        ListenerInfo {
            fd: 3,
            sock_info: SockInfo::Unix(Some(PathBuf::from("/run/caddy.sock"))),
        },
        ListenerInfo {
            fd: 4,
            sock_info: SockInfo::Tcp(tcp),
        },
        ListenerInfo {
            fd: 5,
            sock_info: SockInfo::Udp(udp),
        },
        ListenerInfo {
            fd: 6,
            sock_info: SockInfo::UnboundUnixDatagram("ecdysis-unbound-0".to_string()),
        },
        ListenerInfo {
            fd: 7,
            sock_info: SockInfo::UnixSeqpacket(None),
        },
    ]
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

/// THE assertion: bincode 2.0.1 + `config::legacy()` encodes the registry to exactly the
/// bytes bincode 1.3.3 produced. This is the measurement that makes the version bump a
/// no-op on the wire.
#[test]
fn bincode2_legacy_matches_bincode1_bytes() {
    let expected = decode_hex(GOLDEN_BYTES);
    let mut out = Vec::new();
    bincode::serde::encode_into_std_write(fixture(), &mut out, wire_config())
        .expect("encode failed");
    assert_eq!(
        out,
        expected,
        "\nbincode 2.0.1 config::legacy() is NOT wire-compatible with bincode 1.3.3\n  got: {}\n  exp: {}",
        out.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        GOLDEN_BYTES,
    );
    assert_eq!(out.len(), 118);
}

/// Round trip through the 1.x bytes: bincode 2.x must decode the fixture bincode 1.3.3 wrote
/// (this is the parent-1.x -> child-2.x upgrade direction).
#[test]
fn bincode2_decodes_bincode1_bytes() {
    let bytes = decode_hex(GOLDEN_BYTES);
    let mut rd: &[u8] = &bytes;
    let decoded: Vec<ListenerInfo> =
        bincode::serde::decode_from_std_read(&mut rd, wire_config()).expect("decode failed");
    assert_eq!(decoded, fixture());
}

/// And the exact helpers ecdysis uses (`compat::serialize_into` / `deserialize_from`), i.e.
/// the functions actually on the upgrade path, not just the raw bincode calls.
#[test]
fn compat_helpers_are_wire_identical() {
    let expected = decode_hex(GOLDEN_BYTES);
    let mut out = Vec::new();
    ecdysis::compat::serialize_into(&mut out, &fixture()).expect("serialize_into failed");
    assert_eq!(out, expected);

    let mut rd: &[u8] = &out;
    let back: Vec<ListenerInfo> =
        ecdysis::compat::deserialize_from(&mut rd).expect("deserialize_from failed");
    assert_eq!(back, fixture());
}
