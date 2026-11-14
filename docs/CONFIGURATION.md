# Configuration

caddy-rs runs one configuration at a time. You can write that configuration as a Caddyfile, which
the built-in adapter converts to JSON, or as native Caddy JSON. Both forms describe the same
object: the adapter is a translator, not a second runtime.

## The two configuration layers

Native JSON is the runtime format. The process decodes it into the typed configuration model,
validates every module reference, provisions the generation, and only then starts serving. A JSON
document can express everything the server supports.

A Caddyfile is the concise, human-facing form. The adapter parses it (including global options,
snippets, imports, matchers and directive ordering) and emits the JSON that the runtime consumes.
Use `caddy-rs adapt` to see and keep the result:

```sh
caddy-rs adapt --config Caddyfile --pretty
```

For example, this Caddyfile:

```caddyfile
{
    email admin@example.com
}

example.com {
    root * /srv/www
    encode zstd gzip
    file_server browse
}
```

adapts to JSON with an `apps.http.servers.srv0` object, a `:443` listener, a route matching the
`example.com` host, and a handler chain containing `vars` (for `root`), `encode`, `file_server`
and `subroute` wrappers. The exact JSON is what you would write by hand for the same behaviour.

`adapt` selects the adapter from `--adapter` when given, otherwise from a file name that starts
with `Caddyfile`. The supported adapters are `caddyfile` and `json`; `json` passes the document
through unchanged.

## Validate before you run

`run` validates before binding a socket, and you can perform the same check without serving:

```sh
caddy-rs validate --config Caddyfile
# Valid configuration
```

`validate` adapts and decodes the configuration, runs the full validation pass, and provisions the
modules the way `run` would (without binding listeners or obtaining certificates). A configuration
that passes `validate` therefore does not fail later for a module-shape reason.

Errors are located. JSON errors name the exact key or index; Caddyfile errors name the line
(`Caddyfile line N`, or `file:line` for an imported file). For example, a route whose handler name
is misspelled produces:

```text
caddy-rs: error[module.unknown]: `caddy.json` is not a valid configuration: unknown HTTP handler module `revers_proxy` at `apps.http.servers.srv0.routes[0].handle[0].handler` (did you mean `reverse_proxy`?)
```

The `error[...]` token is stable for scripting; the message after it names the offending input.
Validation reports the first error it finds, not a list.

## A tour of the JSON shape

The top level accepts five keys. Unknown top-level keys and unknown app names are rejected by
validation; each module's own fields are validated against its schema.

| Key | Purpose |
|---|---|
| `admin` | The management endpoint. `listen` defaults to `localhost:2019`; `disabled: true` turns it off; `enforce_origin` with `origins` restricts cross-origin requests. |
| `logging` | Structured logging targets. `logs.<name>` selects a writer, encoder, level, sampling and include/exclude filters, and the `default` log is where access entries normally go. |
| `storage` | The certificate and ACME storage backend. It is a module object: `{"module": "file_system", "root": "/var/lib/caddy-rs"}` selects the filesystem backend and its root. |
| `apps` | Applications keyed by module name. |
| `stock_compat` | caddy-rs extension: boolean stock-compatibility profile, default `false` when absent; a non-boolean value is a located error. See [Compatibility modes](#compatibility-modes). |

`apps.http` holds the HTTP app: `http_port` and `https_port` (defaults 80 and 443),
`grace_period` and `shutdown_delay`, the experimental `metrics` object, and `servers`. Each entry
in `servers` is a server with listeners, routes, TLS connection policies, per-server logging and
error routes.

`apps.tls` holds certificate management: `certificates` for manually loaded keys, `automation` for
issuance policies, and `session_tickets`. An automation policy lists `subjects`, one or more
`issuers` (`acme` or `internal`), an optional `key_type`, and optional `storage`.

`apps.pki` defines local certificate authorities under `certificate_authorities`, keyed by CA ID
(`local` is the implicit default). The `http`, `tls` and `pki` apps are the ones this build
validates; any other app name is an error.

Here is a complete configuration that serves `example.com` from `/srv/www`:

```json
{
  "admin": {
    "listen": "localhost:2019"
  },
  "storage": {
    "module": "file_system",
    "root": "/var/lib/caddy-rs"
  },
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "@id": "site",
              "match": [{ "host": ["example.com"] }],
              "handle": [
                {
                  "handler": "encode",
                  "encodings": { "zstd": {}, "gzip": {} }
                },
                {
                  "handler": "file_server",
                  "root": "/srv/www",
                  "browse": true
                }
              ],
              "terminal": true
            }
          ]
        }
      }
    },
    "tls": {
      "automation": {
        "policies": [
          {
            "subjects": ["example.com"],
            "issuers": [{ "module": "acme" }]
          }
        ]
      }
    }
  },
  "logging": {
    "logs": {
      "default": {
        "writer": { "output": "stderr" },
        "encoder": { "format": "json" },
        "level": "INFO"
      }
    }
  }
}
```

Durations in JSON are either Caddy duration strings (`"5s"`, `"250ms"`, `"1m30s"`, `"2d"`) or
integer nanoseconds. Modules are named by their short JSON key in a `handler` field or as the key
of a module map; the qualified module ID (for example `http.handlers.reverse_proxy`) is not the
JSON spelling. Full per-area details are in [FEATURES.md](FEATURES.md).

## Compatibility modes

Three independent switches tune how closely this build reproduces stock Caddy v2.11.9.
`--adapt-mode` governs configuration *acceptance*, `stock_compat` selects the compatibility
*profile*, and `server_identity` overrides the two identity surfaces. None of them changes the JSON
runtime format.

| Switch | Forms | Default | Scope in this build |
|---|---|---|---|
| `--adapt-mode` | `adapt`, `validate`, `run`: `compatible`, `warn`, `strict` | `compatible` | Caddyfile acceptance of deprecated directive spellings only. `compatible` accepts them and prints Caddy's deprecation warning, `warn` adds warnings for future ambiguity gates, `strict` rejects them with a located error naming both spellings. It is a caddy-rs extension (`DIV-0112`), is ignored by the JSON adapter, and never relaxes a security rejection. |
| `stock_compat` | JSON top-level `"stock_compat": true\|false`; Caddyfile global option `stock_compat` (bare = true, `stock_compat true`/`false` as written) | `false` (absent field = `false`) | One value per configuration. It restores the whole compatibility profile in one generation: stock file/glob import policy (`crates/config/src/adapter.rs`, `crates/config/src/parser.rs`), an inert implicit security profile with no added headers and no fingerprint stripping (`crates/http/src/security_profile.rs`, `crates/proxy/src/handler.rs`), stock identity when `server_identity` is absent (`crates/core/src/identity.rs`, `crates/server/src/runtime.rs`), and verbatim query logging (`crates/admin/src/logging_config.rs`). An explicit `server_identity` and a per-sink `redaction.query_parameters` list still win. See status below. |
| `server_identity` | JSON `apps.http.servers.<name>.server_identity`; Caddyfile `servers { server_identity <mode> }` | `default` when absent | The HTTP `Server` response header and the FastCGI `SERVER_SOFTWARE` parameter. Values: `default`, `name-only`, `compatible`, `none`, or any other non-empty string as a custom identity (validated as an HTTP header value, located error otherwise). |

| `server_identity` | HTTP `Server` header | FastCGI `SERVER_SOFTWARE` |
|---|---|---|
| `default` | `caddy-rs/<build version>` | `caddy-rs/<build version>` |
| `name-only` | `Caddy` | `Caddy` |
| `compatible` | `Caddy` | `Caddy/2.11.9` |
| `none` | not sent | not sent |
| custom string | the string | the string |

Precedence, highest first:

1. An explicit `server_identity` (including explicit `default`) always wins for the `Server` and
   FastCGI surfaces.
2. `stock_compat true`: an absent `server_identity` resolves to `compatible`.
3. Secure default (`stock_compat false`, the default): an absent `server_identity` in a
   configuration containing a `reverse_proxy` handler suppresses the HTTP `Server` header (FastCGI
   still reports `caddy-rs/<version>`); without a `reverse_proxy` handler both surfaces keep
   `caddy-rs/<version>`.
4. `--adapt-mode` and `stock_compat` are independent: the mode governs deprecated spellings, the
   switch governs stock compatibility, and neither implies the other.

Status and portability: `stock_compat` is a caddy-rs extension (`DIV-0130`). Every configuration
apply (process start and each reload) logs one INFO event with the structured field
`stock_compat = true|false` and a message naming the consequence, before the listeners start; it is
filtered by the configured logging settings like any other log line. Stock Caddy v2.11.9 itself
rejects the Caddyfile option as an unknown global option and silently ignores the JSON key, so a
configuration carrying it is not portable to stock. The four `stock_compat` surfaces named in its
row are implemented and covered by `crates/server/tests/http_stock_compat.rs`
(`stock_compat_true_makes_the_profile_inert`, `stock_compat_true_resolves_the_stock_caddy_identity`);
the always-on credential-header redaction (`Cookie`, `Set-Cookie`, `Authorization`,
`Proxy-Authorization`) is unaffected by the verbatim-query-logging row. An explicit
`server_identity` and a per-sink `redaction.query_parameters` list still take precedence.
`server_identity` values are parsed and validated at config load and their mapping is defined in
`crates/core/src/identity.rs`.

The normative table is
[STOCK-COMPAT.md](https://github.com/ben-efros/caddy-rs-project/blob/main/docs/compatibility/STOCK-COMPAT.md);
each divergence id is registered in
[BEHAVIOR-DIVERGENCES.md](https://github.com/ben-efros/caddy-rs-project/blob/main/docs/compatibility/BEHAVIOR-DIVERGENCES.md).
`--adapt-mode` is described in [CLI.md](CLI.md).

## Environment placeholders

Caddyfiles support two kinds of environment substitution, at different times.

`{$NAME}` is replaced when the Caddyfile is parsed, before lexing. `{$NAME:default}` supplies a
fallback when the variable is unset:

```caddyfile
:{$PORT:8080} {
    respond "Hello {$GREETING:world}"
}
```

Expansion is one level deep: a value that itself contains `{$OTHER}` is not expanded again.
Malformed forms such as `{$}` or `{$NAME` are left as literal text.

`{env.NAME}` is a request-time placeholder, evaluated by handlers and matchers for each request.
It expands to the process environment variable and to an empty string when unset:

```caddyfile
example.com {
    respond "Served by {env.HOSTNAME}"
}
```

The two forms are independent: `{$NAME}` affects the configuration the adapter emits, while
`{env.NAME}` stays in the configuration and is read at request time.

## Where to find a directive

This build implements a documented subset of Caddy's configuration surface. The upstream
documentation remains the reference for directive names, block syntax and semantics; use it to
look a directive up, then check [FEATURES.md](FEATURES.md) for the behaviour implemented here.

| Topic | Documentation |
|---|---|
| Caddyfile concepts (sites, snippets, imports, matchers) | <https://caddyserver.com/docs/caddyfile> |
| Caddyfile directives | <https://caddyserver.com/docs/caddyfile/directives> |
| Caddyfile global options | <https://caddyserver.com/docs/caddyfile/options> |
| JSON configuration structure | <https://caddyserver.com/docs/json/> |
| Admin API | <https://caddyserver.com/docs/api> |
| Command line | <https://caddyserver.com/docs/command-line> |

The upstream pages document Caddy itself. This build documents the exact surface it implements in
[FEATURES.md](FEATURES.md); use that page as the authority when the two differ.

## Load a configuration at runtime

The admin API accepts a full native JSON document at `POST /load`. The process validates,
provisions and atomically activates it; on failure the previous generation keeps serving.

```sh
curl --fail-with-body \
  -X POST "http://localhost:2019/load" \
  -H "Content-Type: application/json" \
  --data-binary @caddy.json
```

To load a Caddyfile, adapt it first (or let `reload` do both steps):

```sh
caddy-rs reload --config Caddyfile
```

`reload` validates the configuration locally, then posts the adapted JSON to the admin endpoint.
`POST /stop` deactivates the running configuration; in the CLI `run` process it terminates the
process.

Posting a document identical to the running configuration is a no-op. Send
`Cache-Control: must-revalidate` to force a full reload. Targeted changes can also use
`/config/<path>` and `/id/<id>` with `POST`, `PUT`, `PATCH` and `DELETE`, which apply the same
validation and rollback rules to a subtree. See [FEATURES.md](FEATURES.md#admin-api) for the full
endpoint list.
