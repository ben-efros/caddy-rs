# NOTICE

caddy-rs is an independent Rust implementation inspired by and compatible with
[Caddy](https://github.com/caddyserver/caddy) v2 (`external/caddy` in the program repository).

- Caddy is Copyright the Caddy authors and contributors, licensed under Apache-2.0.
- This repository's implementation is original Rust code licensed under Apache-2.0. It contains no
  copied Caddy source; compatibility fixtures derived from Caddy's integration tests are marked.
- The `httpdate` crate is vendored under `vendor/httpdate` because the offline build sandbox cannot
  fetch crates. It is a minimal reimplementation of the public API surface used by `hyper`
  (upstream: MIT OR Apache-2.0). It should be replaced by the crates.io release when the build is
  online.
