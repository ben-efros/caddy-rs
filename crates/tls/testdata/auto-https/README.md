# Automatic-HTTPS test fixtures

**Test-only** CA material for the fake local ACME CA used by
`crates/tls/src/automatic_https.rs` and `crates/server/tests/http_auto_https.rs`. It protects
nothing and is trusted only by tests, which load `ca.pem` into their rustls client root store.

- `ca.pem` — self-signed ECDSA P-256 root CA (`CN=caddy-rs auto-HTTPS test CA`, CA:TRUE).
- `ca.key` — its PKCS#8 private key; the fake CA uses it to sign the CSR produced by the real
  `AcmeIssuer` finalize step so the resulting leaf certificate is usable for a real TLS handshake.

Regenerate with the local OpenSSL binary:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.key.sec1
openssl pkcs8 -topk8 -nocrypt -in ca.key.sec1 -out ca.key
openssl req -x509 -new -key ca.key -out ca.pem -days 3650 \
  -subj "/CN=caddy-rs auto-HTTPS test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
rm ca.key.sec1
```
