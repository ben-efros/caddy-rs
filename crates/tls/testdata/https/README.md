# HTTPS listener test fixtures

These are **test-only** self-signed certificates, generated locally for the TLS server tests in
`crates/tls/src/tls_server.rs` and the end-to-end HTTPS tests in
`crates/server/tests/http_tls.rs`. They protect nothing and are trusted by no client; the tests
load them explicitly as trust roots or as the local TLS server identity.

| File | SANs | Purpose |
|---|---|---|
| `example.com.pem` / `.key` | `example.com`, `www.example.com` | default SNI certificate / HTTP/1.1 and h2 requests |
| `other.example.pem` / `.key` | `other.example` | second SNI name to prove certificate selection |

Both are ECDSA P-256, `CA:FALSE`, valid 2025-01-01 through 2035-01-01 so the suite stays valid
without regenerating. Regenerate with OpenSSL 3.5+:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout example.com.key -out example.com.pem \
  -not_before 20250101000000Z -not_after 20350101000000Z \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
```
