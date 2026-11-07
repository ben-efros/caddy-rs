# Contributing

Thanks for taking a look. This is an independent implementation, and contributions that make it
match Caddy's documented behaviour more closely are especially welcome.

## Before you start

- Build and test locally: `cargo build --release` and `cargo test --workspace`.
- Formatting is enforced: `cargo fmt --all --check`. New code should also be clean under
  `cargo clippy --all-targets`.
- Configuration behaviour is the compatibility surface. If a change alters accepted configuration,
  emitted JSON or runtime behaviour, it needs a test that proves the new behaviour and a note in the
  compatibility documentation when the behaviour intentionally differs from Caddy.

## Making a change

1. Keep the diff focused; one behaviour change per pull request is easier to review and to verify.
2. Add or update tests. A configuration this build does not support must fail with a located error
   naming the field, and a test must assert that.
3. Run the full suite before opening the pull request:

   ```sh
   cargo fmt --all --check
   cargo test --workspace
   ```

4. Describe what changed and why. If the behaviour differs from Caddy, say how.

## Style

- Rust 2021, `rustfmt` defaults.
- Most crates declare `#![forbid(unsafe_code)]`; keep new code within that constraint where the
  crate does.
- Errors that reach a user should name the configuration path or the input that caused them.
- Prefer documentation comments on public items; the crate docs are part of the user-facing surface.

## Reporting problems

Open an issue with the configuration you used (redact secrets), the command you ran, and what you
expected versus what happened. For anything security-sensitive, follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.
