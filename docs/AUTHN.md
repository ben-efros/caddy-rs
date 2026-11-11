# Authentication (`caddy-rs-authn`)

The authentication service issues HS256 JWT access tokens and rotating opaque refresh tokens, and
verifies passwords (argon2id, bcrypt fallback) and TOTP codes. TOTP configuration and replay
handling are documented separately in [TOTP.md](TOTP.md).

## JWT signing secret

Every deployment must choose a signing-key source explicitly; there is no silent fallback.

| `JwtSecretSource` | Behaviour |
| --- | --- |
| `Master(String)` | The 32-byte key is `SHA-256` of the UTF-8 secret. The same secret always yields the same key. Use for deployments that inject secrets from a manager. |
| `File(path)` | A random 32-byte key persisted at `path`, so sessions survive restarts. Created owner-only (`0600`) on first start. |
| `Ephemeral` | A fresh random key per start (legacy, local development only): every restart invalidates all sessions. |

`File` fails closed rather than starting with a different key, because a silent fallback would
invalidate every session without telling anyone. The rules for `path`:

- **It must be a regular file.** A symlink at the final path component is refused, with an error
  that names the configured path only. The file is opened and its descriptor compared with the path
  metadata afterwards, so a swap between the check and the open is detected instead of trusted.
- **An existing file must contain exactly 32 bytes.** A non-empty file of any other length is a
  configuration error: it is never repaired, truncated or overwritten. The error names the path and
  the observed length, and the operator must either delete the file (a new secret is generated on
  the next start, invalidating existing sessions) or configure a master secret instead.
- **A zero-byte file is repaired.** It is the unusable leftover of a crash between create and write,
  so it is replaced with a fresh random secret. Repair is reserved for that case.

The file path must be on a filesystem that supports atomic rename and hard links; the install
writes an owner-only sibling temp file, links it into place without clobbering a concurrently
installed secret, and re-reads what is on disk so two processes racing on first start converge on
one key.
