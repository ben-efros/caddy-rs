//! T-OPS-106c golden-bytes wire test.
//!
//! bincode 1.3.3 (the codec upstream ecdysis 1.1.1 used) was replaced by
//! `serde-wincode` 0.1.2 + `wincode` 0.6.3 (see `src/compat.rs`), because bincode is
//! BANNED from this repository: RUSTSEC-2025-0141 has `patched = []`, so no bincode version
//! can ever satisfy the audit gate. A parent and child process exchange the listener registry
//! over a pipe across an upgrade, so the old and new encoders MUST produce identical bytes.
//! This test does not assume that; it asserts it against a fixture produced by real bincode
//! 1.3.3, and the new codec has to reproduce it exactly.
//!
//! GOLDEN_BYTES below was emitted by:
//!   bincode = "=1.3.3";  bincode::serialize(&registry).unwrap()
//! over the `registry` value built in `fixture()` with the type definitions copied verbatim
//! from upstream `src/registry.rs`. The oracle came from real bincode 1.3.3; it is now
//! reproduced by `serde-wincode`. It must NEVER be regenerated from the crate under test --
//! regenerating it would make the test assert only that the crate equals itself.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

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

/// THE assertion: `serde-wincode` + wincode's default configuration encodes the registry to
/// exactly the 118 bytes bincode 1.3.3 produced. This is the measurement that makes the codec
/// swap a no-op on the wire.
#[test]
fn serde_wincode_matches_bincode1_bytes() {
    let expected = decode_hex(GOLDEN_BYTES);
    let out = <serde_wincode::SerdeCompat<Vec<ListenerInfo>> as wincode::Serialize>::serialize(
        &fixture(),
    )
    .expect("encode failed");
    assert_eq!(
        out,
        expected,
        "\nserde-wincode/wincode is NOT wire-compatible with bincode 1.3.3\n  got: {}\n  exp: {}",
        out.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        GOLDEN_BYTES,
    );
    assert_eq!(out.len(), 118);
}

/// Round trip through the 1.x bytes: the new codec must decode the fixture bincode 1.3.3
/// wrote (this is the parent-1.x -> child-new-codec upgrade direction).
#[test]
fn wincode_decodes_bincode1_bytes() {
    let bytes = decode_hex(GOLDEN_BYTES);
    let decoded =
        <serde_wincode::SerdeCompat<Vec<ListenerInfo>> as wincode::Deserialize>::deserialize(
            &bytes,
        )
        .expect("decode failed");
    assert_eq!(decoded, fixture());
}

/// And the exact helpers ecdysis uses (`compat::serialize_into` / `deserialize_from`), i.e.
/// the functions actually on the upgrade path, not just the raw codec calls.
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
