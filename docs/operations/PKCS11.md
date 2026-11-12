# PKCS#11 certificate-key loader and signer

This document describes the performance characteristics and measurement procedures for the PKCS#11
certificate-key loader and signer implementation in caddy-rs. The implementation is designed to
support external key providers (TPM/HSM) as specified in ADR-0009, and is implemented in
`crates/tls/src/pkcs11.rs` and `crates/tls/src/signer.rs`.

## Offline limitations

**This measurement task (T-TLS-097) cannot be completed offline** because:

1. The `cryptoki` crate (the Rust binding to PKCS#11 FFI) is not available in the offline registry
2. The actual PKCS#11 token interaction requires a real token or SoftHSM2 instance
3. The measurement requires physical hardware or emulated token environments

The online implementation round will:
- Fetch the `cryptoki` dependency from the live registry
- Conduct measurements with SoftHSM2 and real TPMs
- Record the actual performance characteristics
- Update these defaults based on empirical data

## Performance characteristics

### Token signing latency

The PKCS#11 token signing operation is the primary performance bottleneck for TLS handshakes
when using external certificate keys. The implementation is designed to:

- Minimize blocking of the Tokio worker thread by performing signing operations on a dedicated
  thread pool with a configurable maximum concurrency
- Provide bounded latency expectations for signing operations (5-50ms for typical tokens)
- Support asynchronous signing through the `rustls` crypto provider interface

### Handshake throughput

Handshake throughput is primarily limited by:

1. **Token signing latency**: The time required to perform cryptographic operations on the token
2. **Queue depth**: The number of concurrent signing operations that can be queued
3. **Session management**: The time required to establish and maintain sessions with the token
4. **Network round-trip**: For network-based HSMs (not applicable for local tokens)

## Measurement methodology

The following measurements should be conducted with SoftHSM2 or a real TPM in a controlled
environment:

### Signing latency measurement

1. **Latency test**: Measure the average, 95th percentile, and 99th percentile signing times
   for various key sizes (RSA-2048, RSA-4096, P-256, P-384) using a representative workload
2. **Concurrency test**: Measure throughput at 1, 2, 4, and 8 concurrent connections
3. **Queue saturation test**: Measure queue depth limits and behavior when queue is saturated
4. **Timeout behavior**: Measure how the system behaves when signing operations exceed the
   configured timeout

### Handshake throughput measurement

1. **Full handshake throughput**: Measure the number of TLS handshakes completed per second
   under varying concurrent connection loads
2. **Resumed handshake throughput**: Measure the rate of resumed TLS 1.2 handshakes (which
   bypass the token) and TLS 1.3 handshakes (which use the token)
3. **Latency degradation**: Measure how throughput degrades under queue saturation and
   timeout conditions

## Default performance bounds

The implementation includes the following default performance bounds:

### Maximum sessions (`max_sessions`)
- Default: 100
- Reasoning: Balances resource usage with concurrency needs for typical deployments
- Impact: Controls the maximum number of concurrent sessions that can be opened with a token

### Handshake wait timeout (`handshake_wait`)
- Default: 5 seconds
- Reasoning: Allows sufficient time for token operations while preventing indefinite blocking
- Impact: Controls how long a TLS handshake can wait for a signing operation to complete

### Queue depth (`queue_depth`)
- Default: 1000
- Reasoning: Provides sufficient buffering for typical bursts while preventing excessive
  memory consumption
- Impact: Controls how many concurrent signing operations can be queued before rejecting
  new requests

### Queue wait timeout (`queue_wait`)
- Default: 10 seconds
- Reasoning: Allows time for tokens to become available while preventing indefinite queuing
- Impact: Controls how long a signing operation can wait in the queue before being rejected

### Sign timeout (`sign_timeout`)
- Default: 30 seconds
- Reasoning: Provides sufficient time for token signing operations while avoiding
  indefinite blocking
- Impact: Controls how long a signing operation can take before being cancelled

## Latency budget justification

Based on ADR-0009 and the PKCS#11 specification, the following latency budget is justified:

- **Token signing operations**: 5-50ms for typical tokens (TPM, SoftHSM, YubiKey)
- **Queue depth**: 1000 entries (sufficient for burst traffic)
- **Session concurrency**: 100 simultaneous sessions (typical for medium-scale deployments)
- **Timeout bounds**: 30 seconds for signing operations (reasonable for HSMs, longer for TPMs)

## Operational considerations

### Token quarantine behavior

When a token becomes unavailable or enters an error state, the implementation:
1. Marks the token as quarantined
2. Prevents new signing operations from being queued
3. Allows existing operations to complete or timeout
4. Provides recovery mechanisms through reload or restart

### Session management

The implementation:
1. Maintains a session pool for each token
2. Uses session reuse to minimize connection overhead
3. Handles session expiration and re-authentication
4. Supports multiple sessions for concurrent operations

### Resource usage

The implementation is designed to:
1. Minimize memory usage for session tracking
2. Limit CPU usage through bounded concurrency
3. Prevent deadlocks through timeout mechanisms
4. Provide clear error messages when resource limits are exceeded

## Testing procedures

All measurements should be conducted with:
- A controlled test environment with predictable token behavior
- Multiple iterations to ensure statistical significance
- Consistent hardware and software conditions
- Proper cleanup between test runs

The measurement procedures should include:
1. Latency measurement under normal conditions
2. Throughput measurement at various concurrent loads
3. Queue saturation testing
4. Timeout behavior testing
5. Recovery behavior testing

## Related tasks

- T-TLS-097: Measure and bound PKCS#11 signing latency and handshake throughput
- T-TLS-098: Operator runbook for PKCS#11 certificate keys
- T-TLS-099: Token-held ACME/CA issuance with PKCS#11 keys