# caddy-rs on Windows

`caddy-rs` (the web server and reverse proxy) and `caddy-rs-pm` (the proxy manager) build and run
natively on Windows 10/11 and Windows Server 2019+ (`x86_64-pc-windows-msvc`). This page says what is
supported, how to build and run it, how secrets are protected without POSIX permissions, and what is
**not** available yet.

## Status

| Component | Windows |
|---|---|
| `caddy-rs run`, `validate`, `adapt`, `reload`, `stop`, `fmt`, `respond`, `file-server`, `reverse-proxy` | Supported |
| HTTP/1.1, HTTP/2, HTTP/3 (QUIC), automatic HTTPS, ACME, internal CA | Supported |
| `file_server`, `reverse_proxy`, `try_files`, `templates`, `encode`, `headers`, `basic_auth` | Supported |
| Admin API (TCP loopback) | Supported (see *Admin API exposure*) |
| `caddy-rs-pm serve` and its web UI | Supported |
| Running as a Windows service (`install`/`uninstall`) | **Not yet**: those commands generate systemd units. Use a service wrapper such as NSSM or WinSW meanwhile. |
| `caddy-rs trust` / `untrust` (system trust store) | **Not yet** on Windows (use `certutil -addstore` with the exported root). |
| `unix//path` listeners, Unix-domain admin socket, systemd socket activation, `bind-fds`, graceful binary upgrade (`ecdysis`) | Not applicable on Windows; refused with a clear error or ignored (see `docs/compatibility/PATHS-SYMLINKS-WINDOWS.md`). |

## Building

You need the Rust toolchain pinned in `rust-toolchain.toml` and the MSVC build tools.

```powershell
# AWS-LC (the crypto library) needs NASM on Windows. Either install NASM, or let it use the
# prebuilt objects it ships:
$env:AWS_LC_SYS_PREBUILT_NASM = "1"

cargo build --release -p caddy-rs -p caddy-rs-pm-cli
```

Build or test the workspace with `--exclude ecdysis`: that vendored crate implements graceful binary
upgrade (a default-off feature) and is Unix-only.

```powershell
cargo test --workspace --exclude ecdysis
```

## Running

```powershell
.\target\release\caddy-rs.exe run --config .\Caddyfile --adapter caddyfile
.\target\release\caddy-rs-pm.exe serve --listen 127.0.0.1:8181 --admin-url http://127.0.0.1:2019
```

Ctrl+C, Ctrl+Break, closing the console and a system shutdown all request a graceful stop; a second
signal forces shutdown, exactly like `SIGINT`/`SIGTERM` on Unix.

## Where things live

Like Caddy on Windows, data and configuration default to **`%AppData%\Caddy`** (certificates, the
internal CA, `autosave.json`). If `%AppData%` is unset it falls back to
`%UserProfile%\AppData\Roaming\Caddy`. `XDG_DATA_HOME`/`XDG_CONFIG_HOME` and `CADDY_RS_DATA_DIR` are
still honoured as explicit overrides. Without these the older fallback would have been `.\caddy` in the
directory the server was started from, which is why this matters: private keys must not land beside
served files.

For a machine-wide service, choose a directory only the service account and administrators can use, for
example `C:\ProgramData\caddy-rs`, with `--data-dir` / `CADDY_RS_DATA_DIR`. The server creates it
private if it does not exist.

## How secrets are protected without `chmod`

Windows has no mode bits, and a new file inherits the access list of its parent. Under `%ProgramData%`
or a drive root that list grants read access to `BUILTIN\Users`, so a plain "create the file" would have
left private keys readable by every local user. caddy-rs therefore:

* **Creates** private keys, the internal CA, ACME account keys, the JWT signing key, the proxy manager's
  state and the autosaved configuration with a *protected* access list that grants full control to
  exactly three principals — the user running the process, `NT AUTHORITY\SYSTEM` and
  `BUILTIN\Administrators` — and nothing is inherited. The list is set by the create call itself, so
  there is no moment when the file is readable by anyone else. Directories carry the grant as
  inheritable, so files made inside them are private from their first byte.
* **Tightens** secrets and directories an earlier version left open, when it reads or rewrites them.
* **Checks** before trusting: the data directory, the autosave file, the JWT signing key and every
  imported Caddyfile must be owned by the current user, SYSTEM or Administrators and must not be
  writable (and, for secrets, readable) by another principal; otherwise start-up refuses with a message
  that includes the `icacls` command that fixes it.
* **Does not treat shared drive roots as unsafe.** `C:\` and `ProgramData` let every user create folders;
  that cannot replace a directory that already exists and is private, so only rights to *delete or
  replace entries, or change permissions,* make an ancestor unsafe.

Your machine's `%TEMP%` may grant other accounts access (for example a sandbox account's group). A
configuration directory placed there is then refused by design; use a private directory.

## Admin API exposure

The admin API listens on TCP loopback (`localhost:2019` by default). Unlike Linux, where it can sit on a
Unix socket readable only by its owner, **any local user or process on the machine can reach a TCP
loopback port.** On a shared or multi-user Windows host:

* set `admin off` and manage the server by restarting it, or
* expose the admin API only through the remote listener protected by mutual TLS (`admin.remote` and
  `admin.identity` in the JSON configuration), or
* run the server on a machine where only trusted accounts can log in.

The admin API accepts configuration, so reaching it is equivalent to controlling the server.

## Paths and `file_server`

`file_server` refuses Windows-specific path tricks: `\` parent references, drive prefixes (`C:`), UNC
and rooted paths, alternate data streams (`file.txt:stream`), names ending in a dot or space (which the
OS silently strips), reserved device names (`CON`, `NUL`, `COM1`, …) and characters Windows cannot
store. It also follows directory junctions and symbolic links only when their real target is inside the
served root (`symlinks within_root`, the default). Details and the full list are in
`docs/compatibility/PATHS-SYMLINKS-WINDOWS.md`.

Creating symbolic links on Windows needs either Developer Mode or an elevated prompt; directory
junctions (`mklink /J`) need neither.

## Known limitations

* No native Windows service installation yet (use NSSM/WinSW).
* No system trust-store installation for the internal CA yet.
* The proxy manager's `install` writes a systemd unit and is not meaningful on Windows.
* `unix//` listeners are rejected; use a TCP address.
* When the server refuses a large upload early (413/503) and closes, Windows may reset the connection so the client sees a reset instead of the status code.
* Tests need a private `%TEMP%` and a private checkout (this is deliberate: the data directory checks reject locations other accounts can modify).
