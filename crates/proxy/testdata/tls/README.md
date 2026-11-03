# TLS upstream test fixtures

`localhost-*` and `unrelated-cert.pem` are copied from `crates/tls/testdata/acme/` (see that
README for provenance and regeneration instructions). The `client-*` fixtures were generated for
the proxy mTLS tests with local OpenSSL. They are all **test-only** certificates: they protect
nothing and are trusted by no real client; the proxy TLS tests load them explicitly as trust
roots, server identities, or client identities.

- `localhost-cert.pem` / `localhost-key.pem`: ECDSA P-256 certificate for `DNS:localhost` and
  `IP:127.0.0.1` (CA:FALSE), used by the loopback HTTPS upstream tests.
- `unrelated-cert.pem`: a different self-signed certificate used to prove that an upstream whose
  certificate does not chain to the configured root is rejected.

- `client-ca-cert.pem`: CA certificate used by mTLS test servers to verify client certificates.
- `client-cert.pem` / `client-key.pem`: client identity (DNS:caddy-rs-test-client, clientAuth EKU)
  signed by `client-ca-cert.pem`, used by the upstream client-certificate tests.

Regenerate the client fixtures with:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /tmp/ca-key.pem -out client-ca-cert.pem -days 3650 \
  -subj "/CN=caddy-rs proxy test client CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client-key.pem -out /tmp/client.csr -subj "/CN=caddy-rs proxy test client"
openssl x509 -req -in /tmp/client.csr -CA client-ca-cert.pem -CAkey /tmp/ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 3650 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:caddy-rs-test-client\n')
```
