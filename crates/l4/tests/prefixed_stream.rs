//! Behavioural tests for [`PrefixedStream`] and [`BufferPool`].
//!
//! The L4 router peeks a TCP prefix (a TLS ClientHello) and must replay it into the handler
//! pipeline. These tests cover the replay contract (partial reads, whole-prefix reads, EOF,
//! writes/shutdown delegation), the fixed-size pool's reuse and bound, and both under concurrent
//! use.

use std::sync::{Arc, Mutex};

use tokio::sync::Barrier;

use bytes::{Bytes, BytesMut};
use caddy_rs_l4::{BufferPool, PrefixedStream, POOL_BUFFER_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn prefixed_stream_replays_a_partial_prefix_then_the_upstream() {
    let (mut client, server) = tokio::io::duplex(64);
    let mut stream = PrefixedStream::new(Bytes::from_static(b"PRE"), server);
    client.write_all(b"FIX").await.unwrap();
    client.shutdown().await.unwrap();

    // A caller buffer smaller than the prefix consumes it over several reads, in order.
    let mut small = [0_u8; 2];
    assert_eq!(stream.read(&mut small).await.unwrap(), 2);
    assert_eq!(&small, b"PR");
    assert_eq!(stream.remaining_prefix(), b"E".as_slice());
    assert!(!stream.prefix_consumed());

    assert_eq!(stream.read(&mut [0_u8; 8]).await.unwrap(), 1);
    assert!(stream.prefix_consumed());

    // Only after the prefix is drained does the upstream get polled.
    let mut rest = [0_u8; 3];
    stream.read_exact(&mut rest).await.unwrap();
    assert_eq!(&rest, b"FIX");
    assert_eq!(stream.read(&mut [0_u8; 1]).await.unwrap(), 0); // upstream EOF
}

#[tokio::test]
async fn prefixed_stream_serves_the_whole_prefix_in_one_read() {
    let (mut client, server) = tokio::io::duplex(64);
    client.write_all(b"upstream").await.unwrap();
    client.shutdown().await.unwrap();
    let mut stream = PrefixedStream::new(Bytes::from_static(b"prefix-"), server);

    let mut buffer = [0_u8; 32];
    let n = stream.read(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..n], b"prefix-");
    assert!(stream.prefix_consumed());
    assert_eq!(stream.remaining_prefix(), b"".as_slice());

    let n = stream.read(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..n], b"upstream");
    assert_eq!(stream.read(&mut buffer).await.unwrap(), 0);
}

#[tokio::test]
async fn prefixed_stream_handles_eof_with_no_prefix_and_prefix_only() {
    // No prefix, upstream already at EOF: the read is the upstream's EOF.
    let (client, server) = tokio::io::duplex(64);
    drop(client);
    let mut empty = PrefixedStream::new(Bytes::new(), server);
    assert_eq!(empty.read(&mut [0_u8; 1]).await.unwrap(), 0);

    // Prefix with an upstream at EOF: the prefix is served, then EOF.
    let (client, server) = tokio::io::duplex(64);
    drop(client);
    let mut only_prefix = PrefixedStream::new(Bytes::from_static(b"tail"), server);
    let mut buffer = [0_u8; 16];
    assert_eq!(only_prefix.read(&mut buffer).await.unwrap(), 4);
    assert_eq!(&buffer[..4], b"tail");
    assert_eq!(only_prefix.read(&mut buffer).await.unwrap(), 0);
}

#[tokio::test]
async fn prefixed_stream_delegates_writes_and_shutdown_to_the_upstream() {
    let (mut client, server) = tokio::io::duplex(64);
    let mut stream = PrefixedStream::new(Bytes::from_static(b"peeked"), server);
    stream.write_all(b"reply").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    let mut seen = [0_u8; 5];
    client.read_exact(&mut seen).await.unwrap();
    assert_eq!(&seen, b"reply");
    assert_eq!(client.read(&mut [0_u8; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn prefixed_stream_exposes_its_parts() {
    let (_client, server) = tokio::io::duplex(16);
    let mut stream = PrefixedStream::new(Bytes::from_static(b"abc"), server);
    assert_eq!(stream.remaining_prefix(), b"abc".as_slice());
    let mut buffer = [0_u8; 8];
    assert_eq!(stream.read(&mut buffer).await.unwrap(), 3);
    let (leftover, _upstream) = stream.into_parts();
    assert!(leftover.is_empty());
}

#[tokio::test]
async fn pool_reuses_fixed_size_buffers_under_sequential_load() {
    let mut pool = BufferPool::new(8);
    for _ in 0..256 {
        let mut connection_buffer = pool.acquire();
        assert_eq!(connection_buffer.capacity(), POOL_BUFFER_SIZE);
        connection_buffer.extend_from_slice(&[7_u8; 4096]);
        connection_buffer.clear(); // the replayed prefix is drained into the handler
        assert!(pool.release(connection_buffer));
    }
    // One allocation, 255 reuses: no per-connection heap growth.
    assert_eq!(pool.created(), 1);
    assert_eq!(pool.reused(), 255);
    assert_eq!(pool.available(), 1);
}

#[tokio::test]
async fn pool_refuses_short_buffers_and_is_bounded() {
    let mut pool = BufferPool::new(2);
    assert!(!pool.release(BytesMut::with_capacity(8)));
    assert_eq!(pool.available(), 0);
    assert!(pool.release(BytesMut::with_capacity(POOL_BUFFER_SIZE)));
    assert!(pool.release(BytesMut::with_capacity(POOL_BUFFER_SIZE)));
    assert!(!pool.release(BytesMut::with_capacity(POOL_BUFFER_SIZE)));
    assert_eq!(pool.available(), 2);
    assert!(pool.is_full());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_is_reusable_across_concurrent_connections() {
    const CONNECTIONS: usize = 16;
    // One slot per live connection: every released buffer is accepted in this wave.
    const POOL_SIZE: usize = CONNECTIONS;
    let pool = Arc::new(Mutex::new(BufferPool::new(POOL_SIZE)));
    let barrier = Arc::new(Barrier::new(CONNECTIONS));
    let mut tasks = Vec::with_capacity(CONNECTIONS);

    for connection in 0..CONNECTIONS {
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            // Every connection holds a peek buffer at the same time, so allocation peaks at the
            // number of live connections and then stops growing.
            let mut buffer = pool.lock().unwrap().acquire();
            assert_eq!(buffer.capacity(), POOL_BUFFER_SIZE);
            buffer.extend_from_slice(&[connection as u8; 2048]);
            barrier.wait().await;
            buffer.clear();
            assert!(pool.lock().unwrap().release(buffer));
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    // A later wave borrows only from the pool: steady state stop allocating.
    for _ in 0..POOL_SIZE {
        let mut buffer = pool.lock().unwrap().acquire();
        assert_eq!(buffer.capacity(), POOL_BUFFER_SIZE);
        buffer.clear();
        assert!(pool.lock().unwrap().release(buffer));
    }

    let pool = pool.lock().unwrap();
    assert_eq!(pool.available(), POOL_SIZE); // bounded by the pool size
    assert_eq!(pool.created(), CONNECTIONS as u64); // one allocation per live connection, never per loop
    assert_eq!(pool.reused(), POOL_SIZE as u64); // the later wave borrowed from the pool
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefixed_streams_are_safe_under_concurrent_connections() {
    let mut tasks = Vec::new();
    for connection in 0..16_u8 {
        tasks.push(tokio::spawn(async move {
            let (mut client, server) = tokio::io::duplex(64);
            let mut stream = PrefixedStream::new(Bytes::from(vec![connection; 3]), server);
            client.write_all(&[connection; 2]).await.unwrap();
            client.shutdown().await.unwrap();

            let mut seen = Vec::new();
            stream.read_to_end(&mut seen).await.unwrap();
            assert_eq!(seen, vec![connection; 5]); // 3 prefix bytes + 2 upstream bytes, in order
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}
