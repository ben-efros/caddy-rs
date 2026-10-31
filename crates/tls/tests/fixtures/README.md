# TLS test fixtures

`caddy-data/` mirrors the certificate layout Caddy (via CertMagic) writes below its data
directory:

```
certificates/<issuer-key>/<name>/<name>.crt   PEM chain, leaf first
certificates/<issuer-key>/<name>/<name>.key   PEM private key
certificates/<issuer-key>/<name>/<name>.json  CertMagic certificate metadata
```

The certificates and private keys here are **self-signed test material generated for these
tests only**. They must never be used for anything else; they are not secrets.

Validity periods are fixed so the tests can assert exact Unix timestamps:

| Certificate | notBefore | notAfter | Unix `not_after_unix` |
|---|---|---|---|
| `acme-v02.api.letsencrypt.org-directory/example.com` (leaf, CA chain in `.crt`) | 2026-01-01T00:00:00Z | 2026-04-01T00:00:00Z | 1775001600 |
| `local/wildcard_.example.net` | 2026-01-15T00:00:00Z | 2026-07-15T00:00:00Z | 1784073600 |

Regenerate with OpenSSL (the `-not_before`/`-not_after` flags require OpenSSL 3.5+):

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
  -subj "/CN=caddy-rs test root" -not_before 20250101000000Z -not_after 20300101000000Z \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -nodes -keyout example.com.key -out leaf.csr -subj "/CN=example.com"
# sign with SANs example.com,www.example.com and the validity above, then concatenate
# leaf + CA into example.com.crt.
```
