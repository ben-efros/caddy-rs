# Private-key type fixtures (T-TLS-089)

Self-signed certificates with `DNS:localhost` and matching private keys used by the
per-algorithm TLS tests. Each certificate was generated with OpenSSL 3 from its key with:

```sh
openssl req -new -x509 -key <key> -out <cert> -days 3650 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' -sha256
```

| Pair | Key encoding / algorithm | Expected by caddy-rs |
|---|---|---|
| `rsa2048-pkcs1` | PKCS#1 `RSA PRIVATE KEY`, RSA-2048 | accepted |
| `rsa2048-pkcs8` | PKCS#8 `PRIVATE KEY`, RSA-2048 | accepted |
| `rsa4096` | PKCS#8 `PRIVATE KEY`, RSA-4096 | accepted |
| `p256-sec1` | SEC1 `EC PRIVATE KEY`, prime256v1 | accepted |
| `p256-pkcs8` | PKCS#8 `PRIVATE KEY`, prime256v1 | accepted |
| `p384` | PKCS#8 `PRIVATE KEY`, secp384r1 | accepted |
| `p521-sec1` | SEC1 `EC PRIVATE KEY`, secp521r1 | accepted (aws-lc-rs) |
| `p521-pkcs8` | PKCS#8 `PRIVATE KEY`, secp521r1 | accepted (aws-lc-rs) |
| `ed25519` | PKCS#8 `PRIVATE KEY`, Ed25519 | accepted |
| `rsa1024` | PKCS#8 `PRIVATE KEY`, RSA-1024 | rejected: aws-lc-rs requires 2048..=8192 bits (Caddy accepts) |
| `rsa1024-pkcs1` | PKCS#1 `RSA PRIVATE KEY`, RSA-1024 (same key as `rsa1024`) | rejected: aws-lc-rs requires 2048..=8192 bits (Caddy accepts) |
| `secp256k1` | SEC1 `EC PRIVATE KEY`, secp256k1 | rejected: `x509: unsupported elliptic curve` |
| `brainpool-p256-sec1` | SEC1 `EC PRIVATE KEY`, brainpoolP256r1 | rejected: `x509: unsupported elliptic curve` |
| `brainpool-p384-pkcs8` | PKCS#8 `PRIVATE KEY`, brainpoolP384r1 | rejected: `x509: unsupported elliptic curve` |
| `ed448` | PKCS#8 `PRIVATE KEY`, Ed448 | rejected: Ed448 not implemented |
| `dsa` | PKCS#8 `PRIVATE KEY`, DSA | rejected: DSA not implemented |
| `encrypted-p256` | `ENCRYPTED PRIVATE KEY` (AES-256-CBC, P-256) | rejected: encrypted keys unsupported |

`encrypted-p256.key` is the encrypted form of `p256-sec1.key`; its certificate is the same
`p256-sec1.pem`. The passphrase is `fixture` (never needed by the tests, which only assert the
rejection).

`rsa1024-pkcs1.key` is the PKCS#1 (`openssl rsa -traditional`) form of `rsa1024.key` and shares
`rsa1024.pem`. Both encodings must reach the same size rejection, so the RSA-1024 test covers the
PKCS#1 label and the PKCS#8 algorithm-OID paths.

The unsupported-curve pairs keep a matching certificate so the key parser is reached (names are
parsed before the private key) and so the oracle comparison is meaningful. All certificates carry
`subjectAltName=DNS:localhost`, like the accepted fixtures.
