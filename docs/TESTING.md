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

Rules:

1. A behaviour change that affects adapted JSON must update or add a fixture in the same commit.
2. A deliberate divergence from Caddy must be recorded in the compatibility documentation
   shipped with the project before or with the change.
3. Tests must name the input on failure (paths, ids), not print a bare "failed".
