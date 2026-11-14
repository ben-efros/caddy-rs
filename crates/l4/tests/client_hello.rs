//! Behavioural tests for the zero-copy TLS ClientHello parser ([`parse_client_hello`]).
//!
//! The L4 router peeks a TCP prefix and asks this parser what the connection is: a valid TLS
//! ClientHello (with SNI and ALPN), recognisable non-TLS traffic (HTTP/1, HTTP/2, SSH), a
//! fragmented record that needs more bytes, or a permanent typed rejection.

use std::borrow::Cow;

use caddy_rs_l4::{detect_protocol, parse_client_hello, ParseError, Protocol};

/// Builds a complete TLS record with a ClientHello. `sni` is `(name_type, raw name bytes)`; `alpn`
/// holds raw protocol-name bytes (so tests can inject invalid UTF-8 and empty names).
fn build_client_hello(
    sni: Option<(u8, &[u8])>,
    alpn: &[&[u8]],
    trailing_body_bytes: &[u8],
) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some((name_type, name)) = sni {
        let mut names = vec![name_type];
        names.extend_from_slice(&(name.len() as u16).to_be_bytes());
        names.extend_from_slice(name);
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
            protocols.extend_from_slice(name);
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
        ext.extend_from_slice(&protocols);
        extensions.extend_from_slice(&0x0010_u16.to_be_bytes());
        extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // empty session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[1, 0]); // one compression method
    if !extensions.is_empty() {
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
    }
    body.extend_from_slice(trailing_body_bytes);

    let mut handshake = vec![1_u8]; // client_hello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24 length
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16_u8]; // handshake content type
    record.extend_from_slice(&[0x03, 0x01]); // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Convenience wrapper for a well-formed ClientHello with UTF-8 SNI/ALPN.
fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    let alpn: Vec<&[u8]> = alpn.iter().map(|name| name.as_bytes()).collect();
    build_client_hello(sni.map(|host| (0_u8, host.as_bytes())), &alpn, &[])
}

#[test]
fn parses_a_valid_client_hello_with_sni_and_alpn() {
    let hello = client_hello(Some("example.com"), &["h2", "http/1.1"]);
    let info = parse_client_hello(&hello).expect("valid ClientHello");
    assert!(info.is_tls);
    assert_eq!(info.protocol, Protocol::Tls);
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    assert_eq!(info.alpn, ["h2", "http/1.1"]);
}

#[test]
fn sni_is_normalised_to_lowercase_and_borrowed_when_already_lowercase() {
    let lower = client_hello(Some("example.com"), &[]);
    let info = parse_client_hello(&lower).expect("valid ClientHello");
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    let sni = info.sni.as_ref().unwrap();
    assert!(
        matches!(sni, Cow::Borrowed(_)),
        "already-lowercase SNI is not copied"
    );

    let mixed = client_hello(Some("WWW.Example.COM"), &[]);
    let info = parse_client_hello(&mixed).expect("valid ClientHello");
    assert_eq!(info.sni.as_deref(), Some("www.example.com"));
    assert!(matches!(&info.sni, Some(Cow::Owned(_))));
}

#[test]
fn alpn_names_are_borrowed_from_the_peek_buffer() {
    let hello = client_hello(Some("example.com"), &["h3", "h2", "http/1.1"]);
    let info = parse_client_hello(&hello).expect("valid ClientHello");
    let base = hello.as_ptr() as usize;
    for name in &info.alpn {
        assert!(name.as_ptr() as usize >= base);
        assert!(name.as_ptr() as usize + name.len() <= base + hello.len());
    }
}

#[test]
fn fragmented_records_report_incomplete_for_every_prefix() {
    let hello = client_hello(Some("fragmented.example"), &["h2"]);
    for end in 0..hello.len() {
        assert_eq!(
            parse_client_hello(&hello[..end]),
            Err(ParseError::Incomplete),
            "prefix of {end} bytes should be Incomplete"
        );
    }
    assert!(parse_client_hello(&hello).is_ok());
}

#[test]
fn complete_but_unusable_records_are_malformed_not_incomplete() {
    // Record length 3: the record is fully present but too short for a handshake header.
    let mut short_record = client_hello(Some("x.example"), &[]);
    short_record[3..5].copy_from_slice(&[0x00, 0x03]);
    assert_eq!(
        parse_client_hello(&short_record),
        Err(ParseError::Malformed(
            "record too short for a handshake header"
        ))
    );

    // A complete record whose handshake declares more bytes than the record holds: appending more
    // bytes (for example a second TLS record) cannot change the verdict, so it is not retryable.
    let mut fragmented = client_hello(None, &[]);
    let declared = 0x0000_00ff_u32; // 255-byte handshake
    fragmented[6..9].copy_from_slice(&declared.to_be_bytes()[1..]);
    assert_eq!(
        parse_client_hello(&fragmented),
        Err(ParseError::Malformed(
            "handshake exceeds the record payload; ClientHello fragmented across TLS records is unsupported"
        ))
    );
    let mut with_second_record = fragmented.clone();
    with_second_record.extend_from_slice(&client_hello(Some("example.com"), &["h2"]));
    assert_eq!(
        parse_client_hello(&with_second_record),
        Err(ParseError::Malformed(
            "handshake exceeds the record payload; ClientHello fragmented across TLS records is unsupported"
        )),
        "the parser deliberately does not reassemble a ClientHello split across records"
    );
}

#[test]
fn malformed_records_are_typed_errors() {
    let mut wrong_content_type = client_hello(None, &[]);
    wrong_content_type[0] = 0x17; // application_data
    assert_eq!(
        parse_client_hello(&wrong_content_type),
        Err(ParseError::BadRecordContentType(0x17))
    );

    let mut wrong_version = client_hello(None, &[]);
    wrong_version[1..3].copy_from_slice(&[0x01, 0x00]);
    assert_eq!(
        parse_client_hello(&wrong_version),
        Err(ParseError::BadRecordVersion([0x01, 0x00]))
    );

    let mut wrong_handshake = client_hello(None, &[]);
    wrong_handshake[5] = 11; // certificate
    assert_eq!(
        parse_client_hello(&wrong_handshake),
        Err(ParseError::BadHandshakeType(11))
    );

    let mut odd_cipher_list = client_hello(None, &[]);
    // record(5) + handshake header(4) + version(2) + random(32) + session id length(1) = 44
    odd_cipher_list[44..46].copy_from_slice(&[0x00, 0x03]);
    assert_eq!(
        parse_client_hello(&odd_cipher_list),
        Err(ParseError::Malformed("cipher suite list has an odd length"))
    );

    // Bytes after the declared extensions block are structurally invalid.
    let trailing = build_client_hello(Some((0, b"x.example")), &[], &[0x00]);
    assert_eq!(
        parse_client_hello(&trailing),
        Err(ParseError::Malformed("trailing bytes after extensions"))
    );
}

#[test]
fn rejects_non_utf8_sni_and_alpn() {
    let invalid_sni = build_client_hello(Some((0, &[0xff, 0xfe])), &[], &[]);
    assert_eq!(
        parse_client_hello(&invalid_sni),
        Err(ParseError::Malformed("SNI is not UTF-8"))
    );

    let invalid_alpn = build_client_hello(None, &[b"\xff"], &[]);
    assert_eq!(
        parse_client_hello(&invalid_alpn),
        Err(ParseError::Malformed("ALPN protocol name is not UTF-8"))
    );
}

#[test]
fn edge_cases_in_sni_and_alpn_extensions() {
    // A non-host_name SNI entry is not an error, but it yields no hostname.
    let other_name_type = build_client_hello(Some((1, b"x.example")), &[], &[]);
    let info = parse_client_hello(&other_name_type).expect("unknown SNI name type is tolerated");
    assert!(info.is_tls);
    assert_eq!(info.sni, None);

    // An empty ALPN protocol name is legal on the wire and is preserved as an empty slice.
    let empty_alpn = build_client_hello(None, &[b""], &[]);
    let info = parse_client_hello(&empty_alpn).expect("empty ALPN name is tolerated");
    assert_eq!(info.alpn, [""]);
}

#[test]
fn classifies_non_tls_input_as_not_tls() {
    for (bytes, protocol) in [
        (
            &b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"[..],
            Protocol::Ssh,
        ),
        (
            &b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            Protocol::Http1,
        ),
        (
            &b"POST /submit HTTP/1.0\r\nContent-Length: 0\r\n\r\n"[..],
            Protocol::Http1,
        ),
        (&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..], Protocol::Http2),
    ] {
        let info = parse_client_hello(bytes).expect("recognisable non-TLS protocol is classified");
        assert!(!info.is_tls, "{protocol} must not be reported as TLS");
        assert_eq!(info.protocol, protocol);
        assert!(info.sni.is_none());
        assert!(info.alpn.is_empty());
        assert_eq!(detect_protocol(bytes), protocol);
    }
}

#[test]
fn rejects_unknown_non_tls_bytes_with_a_typed_error() {
    assert_eq!(parse_client_hello(&[]), Err(ParseError::Incomplete));
    assert_eq!(
        parse_client_hello(&[0x00]),
        Err(ParseError::BadRecordContentType(0x00))
    );
    assert_eq!(
        parse_client_hello(&[0xff; 8]),
        Err(ParseError::BadRecordContentType(0xff))
    );
    assert_eq!(detect_protocol(&[0xff; 8]), Protocol::Unknown);
}

#[test]
fn parse_error_is_a_std_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<ParseError>();
    let message = ParseError::Malformed("reason").to_string();
    assert!(message.contains("reason"));
}
