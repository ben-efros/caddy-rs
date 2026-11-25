# NOTICE

caddy-rs is an independent Rust implementation inspired by and compatible with
[Caddy](https://github.com/caddyserver/caddy) v2, tested against the upstream v2.11.9 release.

- Caddy is Copyright the Caddy authors and contributors, licensed under Apache-2.0.
- This repository's implementation is original Rust code licensed under Apache-2.0. It contains no
  copied Caddy source; compatibility fixtures derived from Caddy's integration tests are marked.
- The `httpdate` crate is vendored under `vendor/httpdate` to make offline builds possible. It is a minimal reimplementation of the public API surface used by `hyper`
  (upstream: MIT OR Apache-2.0). It should be replaced by the crates.io release when the build is
  online.

## Test vectors derived from other projects

The request-path validation corpus in `crates/http/tests/file_server_path_validation.rs` (and the
`windows = true` tables in `crates/http/src/file_server.rs`) uses test *inputs and expected outcomes*
taken from a survey of other Rust static-file servers and their path-traversal advisories. The
vectors are facts about inputs and outcomes, rewritten for this code base rather than copied
verbatim; credit is given here as the licences ask.

- tower-http (`ServeDir`), MIT, Copyright (c) Tower Contributors: Windows reserved device names,
  drive-prefix and percent-encoded drive vectors, invalid UTF-8 and NUL handling, "file used as a
  directory", directory redirect vectors.
- hyper-staticfile, MIT: percent-notation decoding, `..` normalisation, trailing-slash redirect and
  sanitised-redirect vectors; RUSTSEC-2022-0069.
- warp (`fs::sanitize_path`), MIT, Copyright (c) Sean McArthur: backslash and drive-letter vectors;
  RUSTSEC-2022-0082.
- actix-files (`PathBufWrap`), MIT OR Apache-2.0: segment rules (`*`, trailing `<`/`>`, drive letters).
- static-web-server, MIT OR Apache-2.0: encoded-path, short-name (8.3) alias and symlink vectors.
- Rocket (`Segments::to_path_buf`), MIT OR Apache-2.0: segment rejection rules.
