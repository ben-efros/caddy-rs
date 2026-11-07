## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The behaviour this fixes or adds, and how you know it matches Caddy. -->

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo test --workspace --locked` (say which crates if scoped)
- [ ] `cargo clippy --workspace --all-targets` has no new warnings
- [ ] If configuration or emitted JSON changed: compatibility docs and a test/fixture are updated,
      and anything that differs from Caddy is registered as a divergence rather than approximated
- [ ] If runtime behaviour changed: the change is covered by a test, not just by inspection

## Security

- [ ] No secrets, credentials or private keys in the diff (test fixtures are clearly throwaway)
- [ ] New dependencies are justified, pinned, and pass `cargo audit`
- [ ] Input from the network is treated as untrusted (sizes bounded, errors typed, no panics)
