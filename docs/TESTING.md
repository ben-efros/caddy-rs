# Testing

```sh
cargo test --offline --workspace      # offline build (sandbox)
cargo test --workspace                # normal online build (after removing the httpdate patch)
```

Test layers:

| Layer | Location | What it protects |
|---|---|---|
| Unit | `#[cfg(test)]` in each crate | config model round-trip, validation paths, lifecycle/drain, matchers, handlers, balancers, health checks, certificate cache/renewal, admin routing |
| Adapter parity | `crates/config/tests/upstream_adapt.rs` | exact JSON equality with Caddy v2.11.9's golden `caddyfile_adapt` fixtures |
| Adapter contract | `crates/config/tests/local_adapt.rs` | exact JSON for locally authored fixtures + the adapted config must validate |
| Runtime end-to-end | `crates/server/tests/http_runtime.rs` | real TCP listeners, HTTP requests, host routing, reload, admin `/load`, 400 on invalid config |
| CLI | `crates/cli/tests/cli.rs` | compiled binary: version, module list, adapt, validate exit codes |
| Differential | `crates/config/tests/` | runs the upstream fixture corpus against `caddy-rs adapt` and classifies pass/mismatch/unsupported |
| GeoIP provider | `crates/http/tests/geoip.rs` | ASN/country lookups, one-database-only configurations, unknown addresses, the no-database fallback, counters and provider selection, all against real MaxMind DB fixtures |

## GeoIP fixtures

`crates/http/tests/fixtures/` holds two MaxMind DB files, copied unmodified from the official
[`maxmind/MaxMind-DB`](https://github.com/maxmind/MaxMind-DB) test data
(`test-data/GeoIP2-ISP-Test.mmdb` and `test-data/GeoIP2-Country-Test.mmdb`):

| File | Records used | Addresses asserted |
|---|---|---|
| `GeoIP2-ISP-Test.mmdb` | ASN (`autonomous_system_number`) | `1.128.0.1` → 1221, `89.160.20.112` → 29518 |
| `GeoIP2-Country-Test.mmdb` | country (`country.iso_code`) | `2.125.160.216` → GB, `89.160.20.112` → SE |

They are **committed rather than generated**, so the tests exercise the real MaxMind DB binary
format through a real parser; a hand-built fake would only prove that the fake round-trips. They
are synthetic test databases, not production GeoIP data: MaxMind, Inc. licenses them under
Apache-2.0 OR MIT (at your option), so they carry no GeoLite2/GeoIP2 EULA obligations. Details and
the licence links are in `crates/http/tests/fixtures/README.md`. Do not replace them with a
production DB-IP or MaxMind download: those are tens of megabytes and, for MaxMind,
licence-encumbered.

Rules:

1. A behaviour change that affects adapted JSON must update or add a fixture in the same commit.
2. A deliberate divergence from Caddy must be recorded in the compatibility documentation
   shipped with the project before or with the change.
3. Tests must name the input on failure (paths, ids), not print a bare "failed".
