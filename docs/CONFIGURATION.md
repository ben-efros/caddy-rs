# Configuration

caddy-rs accepts the two configuration formats Caddy accepts. Both describe the same model; the
Caddyfile is adapted into JSON before it is loaded.

## Two formats

| Format | Use it for | Adapter |
|---|---|---|
| Caddyfile | Hand-written configuration, the format Caddy documents | `--adapter caddyfile` |
| JSON | Generated configuration, exact control over every field | `--adapter json` |

```sh
# Convert a Caddyfile to JSON (what the server will load)
caddy-rs adapt --config ./Caddyfile --adapter caddyfile --pretty > caddy.json

# Validate either form without starting the server
caddy-rs validate --config ./Caddyfile --adapter caddyfile
```

An invalid configuration fails with the JSON path of the offending field, for example
`apps.http.servers.srv0.routes[0].handle[0]`, before any listener changes.

## Caddyfile

A Caddyfile starts with an optional global options block, followed by site blocks:

```caddyfile
{
	email admin@example.com
}

example.com {
	encode gzip zstd
	reverse_proxy 10.0.0.5:8080 10.0.0.6:8080 {
		lb_policy least_conn
		health_uri /healthz
	}
}
```

Supported directives are listed in [FEATURES.md](FEATURES.md); directive semantics follow the
upstream documentation at <https://caddyserver.com/docs/>.

Placeholders:

- `{env.VAR}` resolves an environment variable inside a configuration value.
- `{$VAR}` resolves an environment variable while the Caddyfile is being parsed.

## JSON

The JSON form mirrors Caddy's: a top-level object with optional `admin`, `storage`, `logging` and
`apps`, where `apps.http` holds servers and `apps.tls` holds certificate automation.

| Key | Meaning |
|---|---|
| `admin` | Admin endpoint: `{"disabled": true}` to turn it off, `{"listen": "localhost:2019"}` to move it, plus `origins`/`enforce_origin` |
| `storage` | Certificate and account storage. `{"module": "file_system", "root": "/var/lib/caddy"}` or the S3 backend |
| `apps.http` | HTTP servers (`servers`), global `http_port`/`https_port`, `grace_period`, `shutdown_delay`, `metrics` |
| `apps.tls` | Certificate automation policies, issuers, certificate loading, connection policies, certificate storage |
| `logging` | Log sinks, encoders, levels, sampling and filters |

A server entry combines `listen`, `routes`, optional `tls_connection_policies`, `automatic_https`,
`trusted_proxies`, `listener_wrappers` and limits:

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [{
            "handle": [{ "handler": "static_response", "body": "hello" }]
          }]
        }
      }
    }
  }
}
```

## Applying configuration at runtime

A running server accepts a new configuration through its admin API; the load is atomic and a
rejected configuration leaves the previous one serving.

```sh
curl -X POST http://localhost:2019/load \
  -H 'Content-Type: application/json' \
  --data-binary @caddy.json
```

`caddy-rs reload` performs the same operation from the command line, and `caddy-rs stop` asks a
running server to shut down.

## Where to look next

- [FEATURES.md](FEATURES.md) — every handler, matcher and option this build supports.
- [CLI.md](CLI.md) — commands, flags and exit codes.
- [INSTALL.md](INSTALL.md) — building, offline builds, and where state is stored.
- <https://caddyserver.com/docs/> — upstream documentation for the configuration model.
