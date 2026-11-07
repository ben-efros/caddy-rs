# Releasing

A release is a git tag plus the binary archives that CI builds from it. This page describes how a
release is produced, what each artefact contains, and how to verify it before publishing.

## Artefacts

Each release publishes one archive per platform, plus a checksum file:

| Archive | Platform | Linkage |
|---|---|---|
| `caddy-rs-<version>-x86_64-glibc.tar.gz` | Linux x86_64 | glibc, dynamically linked |
| `caddy-rs-<version>-aarch64-glibc.tar.gz` | Linux arm64 | glibc, dynamically linked |
| `caddy-rs-<version>-x86_64-static.tar.gz` | Linux x86_64 | **fully static**, size-optimised |
| `caddy-rs-<version>-aarch64-static.tar.gz` | Linux arm64 | **fully static**, size-optimised |
| `caddy-rs-<version>-x86_64-static-minimal.tar.gz` | Linux x86_64 | **static, minimal** (no HTTP/3, compression, templates) |
| `caddy-rs-<version>-aarch64-static-minimal.tar.gz` | Linux arm64 | **static, minimal** (no HTTP/3, compression, templates) |
| `caddy-rs-<version>-aarch64-macos.tar.gz` | macOS arm64 | dynamic |

Every archive contains the `caddy-rs` binary, `LICENSE`, `NOTICE.md` and `README.md`.
`SHA256SUMS` covers all archives in the release.

The **minimal** archives are built from the same targets with `--no-default-features`, which leaves
out HTTP/3, the compression handler and the templates handler — a 6.5 MiB binary instead of 19.7 MiB.
A configuration that asks for one of those features is still rejected with a located error naming the
feature, so a minimal build cannot silently accept a configuration it cannot serve.

The static archives are built with the `release-minimal` profile (`opt-level = "z"`, fat LTO,
`panic = "abort"`, stripped symbols), so they are the smallest binaries produced. They have no libc
dependency: they run on any Linux kernel of the target architecture, including Alpine and minimal
container images.

## Version numbering

Tags are `vMAJOR.MINOR.PATCH`, optionally with a pre-release suffix (`v0.1.0-trial.1`). A tag on the
default branch produces the published release; the workflow can also be dispatched manually with a
version string, which builds the same artefacts without creating a tag.

## Cutting a release

1. **Confirm the tree is green.**

   ```sh
   cargo fmt --all --check
   cargo test --workspace
   ```

2. **Check the version.** `Cargo.toml` carries `version` under `[workspace.package]`; bump it in the
   same commit that updates `Cargo.lock`:

   ```sh
   cargo set-version --workspace 0.1.0          # or edit Cargo.toml directly
   cargo check --workspace                      # refreshes Cargo.lock
   git commit -am "release: v0.1.0"
   ```

3. **Build the artefacts locally first** — at least the target you are on, to catch packaging
   mistakes before CI spends the matrix:

   ```sh
   cargo build --locked --profile release -p caddy-rs
   strip target/release/caddy-rs
   target/release/caddy-rs version
   ```

4. **Tag and push.** The tag drives the workflow:

   ```sh
   git tag -a v0.1.0 -m "caddy-rs v0.1.0"
   git push origin v0.1.0
   ```

5. **Watch the run.** `.github/workflows/release.yml` builds all seven targets, packages each one,
   appends to `SHA256SUMS`, and publishes a GitHub release with the archives attached.

   ```sh
   gh run watch --repo ben-efros/caddy-rs
   ```

6. **Verify the published release.** Download one archive and check it:

   ```sh
   sha256sum -c caddy-rs-v0.1.0-x86_64-static.tar.gz.sha256
   tar -tzf caddy-rs-v0.1.0-x86_64-static.tar.gz
   file caddy-rs                     # "statically linked" for the musl archives
   ```

## Building a target by hand

The same commands the workflow runs, for one platform:

```sh
# glibc
cargo build --locked --release --target x86_64-unknown-linux-gnu -p caddy-rs

# fully static
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --locked --profile release-minimal --target x86_64-unknown-linux-musl -p caddy-rs
```

Cross-architectural builds use the same commands with `aarch64-unknown-linux-musl` (or
`aarch64-unknown-linux-gnu`) and a cross linker, or run natively on an arm64 machine — which is what
the workflow does, so no cross toolchain is required in CI.

## Installing from a release

```sh
curl -LO https://github.com/ben-efros/caddy-rs/releases/download/v0.1.0/caddy-rs-v0.1.0-x86_64-static.tar.gz
curl -LO https://github.com/ben-efros/caddy-rs/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf caddy-rs-v0.1.0-x86_64-static.tar.gz
sudo install -m 0755 caddy-rs /usr/local/bin/caddy-rs
caddy-rs version
```

A container image is not published yet; the static archive is the portable option and runs on a
distroless or `scratch` base image.

## Release checklist

- [ ] `cargo fmt --all --check` and `cargo test --workspace` pass.
- [ ] Workspace version and `Cargo.lock` updated together.
- [ ] `caddy-rs version` reports the release version and the Caddy baseline.
- [ ] At least one archive built and smoke-tested locally.
- [ ] Tag pushed; workflow green on all seven targets.
- [ ] `SHA256SUMS` verified against a downloaded archive.
- [ ] Release notes mention any behaviour change since the previous tag.
