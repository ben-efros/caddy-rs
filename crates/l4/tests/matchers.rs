//! End-to-end matching on real TCP streams: peek, match, route, and hand every byte on.
//!
//! These tests open real `TcpListener`/`TcpStream` pairs (loopback) so the peek loop, the matchers
//! and the prefix replay are exercised over the same code path a listener uses, not over in-memory
//! buffers only. Each fixture ClientHello is built with the encoding from T-L4-002's parser tests:
//! the SNI extension carries `list_len(2) | name_type(1) | name_len(2) | name`, and the ALPN
//! extension `list_len(2) | [len(1) | name]*`.

use std::net::SocketAddr;

use caddy_rs_l4::actions::SniAction;
use caddy_rs_l4::client_hello::Protocol;
use caddy_rs_l4::context::{sniff, PeekLimits, Sniffed, StreamContext};
use caddy_rs_l4::matchers::{
    matcher, ConnectionMeta, EvaluateContext, IpMatcher, IpRange, L7Matcher, L7Protocol,
    MatchOutcome, MatcherSet, SniPattern, TlsMatcher,
};
use caddy_rs_l4::router::{RouteDefinition, SniRouter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Builds the minimal ClientHello described in the module docs.
fn client_hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
    let mut extensions = Vec::new();
    let host = sni.as_bytes();
    let mut names = vec![0_u8]; // host_name
    names.extend_from_slice(&(host.len() as u16).to_be_bytes());
    names.extend_from_slice(host);
    let mut ext = Vec::new();
    ext.extend_from_slice(&(names.len() as u16).to_be_bytes());
    ext.extend_from_slice(&names);
    extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
    extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ext);

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
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0); // empty session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![1_u8];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16_u8];
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Accepts one connection, returning it with its peer address.
async fn accept_one(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    let (stream, peer) = listener.accept().await.expect("accept");
    (stream, peer)
}

#[tokio::test]
async fn the_tls_matcher_routes_real_streams_by_sni_and_alpn() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(&client_hello("api.example.com", &["h2"]))
            .await
            .expect("write hello");
        stream
            .write_all(b"rest-of-session")
            .await
            .expect("write tail");
        stream
    });

    let (stream, peer) = accept_one(&listener).await;
    let mut ctx = StreamContext::new(stream).with_peer(peer);
    ctx.peek_tls_record().await.expect("peek ClientHello");
    assert!(matches!(sniff(ctx.buffered()), Sniffed::Tls { .. }));

    let meta = ConnectionMeta {
        peer: Some(peer.ip()),
        asn: Some(64500),
    };
    let h2_route = MatcherSet::all(vec![
        matcher(TlsMatcher::any().with_sni(SniPattern::parse("*.example.com").unwrap())),
        matcher(TlsMatcher::any().with_alpn([String::from("h2")])),
    ]);
    assert!(ctx
        .evaluate_set(&h2_route, &meta)
        .await
        .expect("no consumption")
        .is_match());

    let h3_route = matcher(TlsMatcher::any().with_alpn([String::from("h3")]));
    let outcome = ctx
        .evaluate_set(&MatcherSet::all(vec![h3_route]), &meta)
        .await
        .expect("no consumption");
    assert!(!outcome.is_match());

    // Matching must leave the connection byte-identical, so the handler sees the ClientHello
    // followed by everything the client sends next: the replay is contiguous with the socket.
    let hello = client_hello("api.example.com", &["h2"]);
    let tail = b"rest-of-session";
    let mut prefixed = ctx.into_prefixed_stream();
    let mut prefix = vec![0_u8; hello.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        prefixed.read_exact(&mut prefix),
    )
    .await
    .expect("replayed prefix must not block")
    .expect("replay");
    assert_eq!(prefix, hello, "the handler must see the ClientHello first");
    let mut rest = vec![0_u8; tail.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        prefixed.read_exact(&mut rest),
    )
    .await
    .expect("the socket continues after the replay")
    .expect("read tail");
    assert_eq!(&rest, tail, "the replay is contiguous with the socket");
    drop(prefixed);
    client.abort();
    let _ = client.await;
}

#[tokio::test]
async fn a_real_ssh_banner_is_matched_without_waiting_for_a_full_peek() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n".to_vec();
    let expected = banner.clone();
    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(&banner).await.expect("write banner");
        // Keep the connection open: a matcher must not wait for EOF either.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        stream
    });

    let (stream, peer) = accept_one(&listener).await;
    let mut ctx = StreamContext::with_limits(
        stream,
        PeekLimits {
            max_peek_bytes: 16 * 1024,
            timeout: Some(std::time::Duration::from_secs(30)),
        },
    )
    .with_peer(peer);
    let started = std::time::Instant::now();
    ctx.peek_available(expected.len())
        .await
        .expect("peek banner");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "an SSH banner must not wait for the peek deadline"
    );
    let meta = ConnectionMeta::default();
    let ssh = MatcherSet::all(vec![matcher(L7Matcher::new(L7Protocol::Ssh))]);
    assert!(ctx
        .evaluate_set(&ssh, &meta)
        .await
        .expect("no consumption")
        .is_match());
    let tls = MatcherSet::all(vec![matcher(TlsMatcher::any())]);
    assert!(!ctx
        .evaluate_set(&tls, &meta)
        .await
        .expect("no consumption")
        .is_match());
    assert_eq!(ctx.buffered(), expected.as_slice());
    drop(client);
}

#[tokio::test]
async fn ip_and_protocol_matchers_compose_on_a_real_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /health HTTP/1.1\r\n")
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        stream
    });

    let (stream, peer) = accept_one(&listener).await;
    let mut ctx = StreamContext::with_limits(stream, PeekLimits::bytes(16 * 1024)).with_peer(peer);
    tokio::time::timeout(std::time::Duration::from_secs(10), ctx.peek_available(18))
        .await
        .expect("peek must not block")
        .expect("peek request line");
    let meta = ConnectionMeta {
        peer: Some(peer.ip()),
        asn: None,
    };
    let loopback = IpMatcher::new().with_range(IpRange::parse("127.0.0.0/8").unwrap());
    let http = L7Matcher::new(L7Protocol::Http);
    let set = MatcherSet::all(vec![matcher(loopback), matcher(http)]);
    assert!(ctx
        .evaluate_set(&set, &meta)
        .await
        .expect("no consumption")
        .is_match());
    // `not` negates its member: the loopback peer is *not* in 10.0.0.0/8, so the negated set is a
    // match; negating the matcher that does contain it is a non-match.
    let elsewhere = IpMatcher::new().with_range(IpRange::parse("10.0.0.0/8").unwrap());
    assert!(ctx
        .evaluate_set(&MatcherSet::not(matcher(elsewhere)), &meta)
        .await
        .expect("no consumption")
        .is_match());
    assert!(!ctx
        .evaluate_set(
            &MatcherSet::not(matcher(
                IpMatcher::new().with_range(IpRange::parse("127.0.0.0/8").unwrap())
            )),
            &meta
        )
        .await
        .expect("no consumption")
        .is_match());
    drop(client);
}

#[tokio::test]
async fn snilookup_and_matching_agree_on_the_same_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(&client_hello("db.example.com", &["h2"]))
            .await
            .expect("write hello");
        stream
    });

    let router = SniRouter::new(
        vec![
            RouteDefinition::new(
                "db.example.com",
                SniAction::Terminate(
                    caddy_rs_l4::actions::TerminateConfig::new("db.example.com").unwrap(),
                ),
            )
            .unwrap(),
            RouteDefinition::new(
                "*.example.com",
                SniAction::Passthrough(
                    caddy_rs_l4::actions::PassthroughConfig::new("upstream.example.com:443")
                        .unwrap(),
                ),
            )
            .unwrap(),
        ],
        SniAction::Fallback(caddy_rs_l4::actions::FallbackConfig::new(
            caddy_rs_l4::actions::FallbackReason::NoRoute,
        )),
    )
    .expect("router");

    let (stream, peer) = accept_one(&listener).await;
    let mut ctx = StreamContext::new(stream).with_peer(peer);
    ctx.peek_tls_record().await.expect("peek ClientHello");
    let Sniffed::Tls { info } = sniff(ctx.buffered()) else {
        panic!("expected a TLS ClientHello");
    };
    assert!(info.is_tls);
    let sni = info.sni.as_deref().expect("SNI");
    // The router and the tls matcher must agree on which route owns this connection.
    let route = router.lookup(Some(sni));
    assert_eq!(route.action().kind(), "terminate");
    let matcher_set = MatcherSet::all(vec![matcher(
        TlsMatcher::any().with_sni(SniPattern::parse("db.example.com").unwrap()),
    )]);
    assert!(ctx
        .evaluate_set(&matcher_set, &ConnectionMeta::default())
        .await
        .expect("no consumption")
        .is_match());
    let outcome: MatchOutcome = ctx
        .evaluate_set(
            &MatcherSet::all(vec![matcher(TlsMatcher::any())]),
            &ConnectionMeta::default(),
        )
        .await
        .expect("no consumption");
    assert!(outcome.is_match());
    drop(client);
}

#[tokio::test]
async fn protocol_families_are_classified_from_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let h2_client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("write preface");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        stream
    });
    let (stream, peer) = accept_one(&listener).await;
    let mut ctx = StreamContext::new(stream).with_peer(peer);
    ctx.peek_available(24).await.expect("peek preface");
    let h2 = MatcherSet::all(vec![matcher(L7Matcher::new(L7Protocol::Http2))]);
    assert!(ctx
        .evaluate_set(&h2, &ConnectionMeta::default())
        .await
        .expect("no consumption")
        .is_match());
    let ssh = MatcherSet::all(vec![matcher(L7Matcher::new(L7Protocol::Ssh))]);
    assert!(!ctx
        .evaluate_set(&ssh, &ConnectionMeta::default())
        .await
        .expect("no consumption")
        .is_match());
    assert_eq!(
        sniff(ctx.buffered()),
        Sniffed::NonTls {
            protocol: Protocol::Http2
        }
    );
    drop(h2_client);
}
