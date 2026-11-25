# SEC-MEDIUM summary — what changed, what is configurable, what can break an upgrade

This is the index for the five medium-severity hardening notes. The per-area notes are
authoritative for behaviour, tests and the proposed program-repository register text:

| Area | Note |
|---|---|
| Admin API and listeners | [SEC-MEDIUM-ADMIN-SERVER.md](SEC-MEDIUM-ADMIN-SERVER.md) |
| HTTP handlers (`basic_auth`, `file_server`, `templates`) | [SEC-MEDIUM-HTTP.md](SEC-MEDIUM-HTTP.md) |
| Reverse proxy and layer4 | [SEC-MEDIUM-PROXY.md](SEC-MEDIUM-PROXY.md) |
| TLS and certificates | [SEC-MEDIUM-TLS.md](SEC-MEDIUM-TLS.md) |
| Authentication library and proxy manager | [SEC-MEDIUM-AUTHN-PM.md](SEC-MEDIUM-AUTHN-PM.md) |

The register numbering in those notes is not yet unified: the proxy note uses `DIV-NNNN`
placeholders, the admin note uses `SEC-MEDIUM-ADMIN-SERVER-A*` labels, the HTTP note uses prose,
and the TLS note amends the existing DIV-0087. Whoever merges them into
`BEHAVIOR-DIVERGENCES.md` assigns the numbers.

## Policy applied

* Hardening that does not change what stock Caddy v2.11.9 does for a valid configuration is
  unconditional.
* Hardening that does change stock behaviour is the **default**, and `"stock_compat": true`
  restores stock behaviour for that item. The difference is documented in the area note.
* Components with no stock Caddy equivalent (`caddy-rs-authn`, the proxy manager) are always
  hardened; `stock_compat` does not apply.

## New configuration surface

| Field | Where | Meaning | Default |
|---|---|---|---|
| `dial_allow` | `reverse_proxy` handler (JSON) and `reverse_proxy { dial_allow ... }` (Caddyfile) | IP/CIDR and `unix//absolute/prefix` entries that a request-derived dial may reach | empty: loopback, link-local, metadata, CGNAT and all unix targets are refused for request-derived dials |
| `trusted_proxies_strict` | server (JSON) | `false` restores Caddy's left-most `X-Forwarded-For` client IP | absent = strict (right-most untrusted); the Caddyfile can only emit `true`, so Caddyfile users restore stock with `stock_compat` |
| `env_allow` | `templates` handler | exact environment variable names templates may read; `[]` denies all | absent = stock (any variable) |
| `insecure_accept_any_client_cert` | TLS `client_authentication` (JSON) / `client_auth` subdirective (Caddyfile) | explicit acknowledgement that `request`/`require` verifies nothing | absent: such a policy without an exact-leaf pin fails to load; rejected under `stock_compat` |
| `AuthnConfig::login_throttle` | `caddy-rs-authn` (library) | failures before lockout, lockout start/maximum, tracked-key bound | 5 failures, 30 s doubling to 15 min |
| `AuthnConfig::allow_weak_argon2_params` | `caddy-rs-authn` (library) | permit Argon2 parameters below the OWASP minimum (tests, constrained hardware) | `false` |
| `PM_BOOTSTRAP_ADMIN_TOTP_SECRET` | proxy-manager environment | base32 TOTP secret (at least 128 bits) for the bootstrap administrator; `install` checks one code once and never stores it | unset |

The admin limits (64 MiB body, upload slots, connection caps, timeouts) are constants, not
configuration; see the admin note.

## Behaviour gated by `stock_compat`

`"stock_compat": true` restores stock behaviour for: the `trusted_proxies_strict` default, the
dial guard, the random `cookie` load-balancing secret, the `basic_auth` wait cap and per-client
cap, the admin request-body cap and upload slots, the admin unix-socket liveness probe, and the
`request`/`require` client-auth acknowledgement. It does **not** relax the unconditional items
below. The authoritative list is the `stock_compat` row of
[CONFIGURATION.md](../CONFIGURATION.md).

## Unconditional hardening (stock-equal or pure hardening)

Admin `Host` check on every request (Caddy `checkHost` parity, including HTTP/2 `:authority`),
TLS-handshake and PROXY-header deadlines, admin timeouts and connection caps, admin socket staging
and inode-checked cleanup, `basic_auth` hash offload and credential cache, `file_server` streaming
(range/HEAD/304 no longer load the file, `O_NOFOLLOW` open, handle-based validators), browse
listing honouring `hide`, IPv4-mapped IPv6 canonicalisation, DNS spoof resistance, generic 502
bodies, bounded L4 dial and FastCGI head, OCSP signature/freshness verification, bounded ACME/OCSP
bodies, redacting `Debug` for key-bearing types, internal-CA root `pathlen:1`, and all authn/pm
changes.

## Defaults that can break an existing deployment

* A client-auth policy with mode `request` or `require` and no exact-leaf pin no longer loads.
  Pin leaves, switch to `require_and_verify`, add `insecure_accept_any_client_cert: true`, or set
  `stock_compat`.
* Behind a CDN with `trusted_proxies` covering only the load balancer, the client IP is now the CDN
  edge, not the user. Add the CDN ranges to `trusted_proxies`.
* Request-derived `reverse_proxy` dials to loopback, link-local or unix targets are refused unless
  listed in `dial_allow`. Operator-controlled dials (literals, `{env.*}`) are unaffected.
* `basic_auth` can answer 503 (pool busy) or 429 (one client has too many uncached verifications);
  put real client IPs in place with `trusted_proxies` when behind a proxy.
* Admin: a foreign `Host` is refused even without an `Origin`; an HTTP/1.1 request without `Host`
  is a 400; bodies above 64 MiB get 413; a second process refuses to take over a live admin unix
  socket (an upgrade child is exempt).
* OCSP staples that fail signature or freshness verification are no longer stapled; responders
  that sign with SHA-1 or RSA-PSS lose stapling (documented divergence from Go's library).
* Proxy manager: bootstrap passwords must be at least 8 characters; `PM_BOOTSTRAP_ADMIN_TOTP` alone
  is refused (use the secret plus a code at `install`); header/upstream fields containing `{`, `}`
  or control characters are rejected, including values already stored.
* `caddy-rs-authn` public API: new `User` and `AuthnConfig` fields, `AuthError` is
  `#[non_exhaustive]`, and `UserStore` gained `modify_user` and an epoch-checked
  `store_refresh_token`; custom stores must implement them.

## Known limits (documented, not fixed)

* RFC 1918 and ULA ranges stay reachable by request-derived dials; the guard covers loopback,
  link-local, metadata and CGNAT only.
* An intermediate directory swapped for a symlink during a `file_server` request is still followed
  (only the final component uses `O_NOFOLLOW`).
* Revoked managed certificates are not re-issued automatically; the staple is evicted and an ERROR
  is logged.
* A symlinked `file_server` `root` is refused (pre-existing).
* Name constraints for the internal CA are not implemented.
* Native Windows: the workspace does not build there (`libc`, `sd-notify`); the Windows-specific
  `file_server` path hardening belongs to the separate HIGH-severity change set.
