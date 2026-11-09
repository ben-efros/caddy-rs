# Manual-certificate test fixtures

These are **test-only** self-signed certificates and private keys generated for the
`caddy-rs-pm-certificates` and `caddy-rs-pm-config` tests. They are not trusted by any deployment,
are committed only so the tests can run offline, and must never be used to serve real traffic.

| Fixture | Purpose |
|---|---|
| `manual-valid.*` | RSA leaf covering `manual.example.com` and `www.manual.example.com`, valid for the test clock |
| `manual-valid-rsa-pkcs1.key.pem` | The same RSA key in PKCS#1 form |
| `manual-ec.*` | P-256 leaf/key |
| `manual-wildcard.*` | `*.wild.example.com` wildcard leaf |
| `manual-cn-only.*` | Certificate with CN but no SAN |
| `manual-chain.*` | Leaf plus intermediate chain |
| `manual-expired.*`, `manual-future.*` | Expired / not-yet-valid leaves |
| `manual-wrong-san.*` | Valid key pair for a different name |
| `manual-other.*` | A second key for mismatch tests |
