# Adapter compatibility fixtures

- `upstream/*.caddyfiletest` are copied unmodified from Caddy v2.11.7
  (`external/caddy/caddytest/integration/caddyfile_adapt/` in the program repository), which is
  Apache-2.0. They are the differential oracle: `caddy-rs adapt` must produce JSON semantically
  identical to Caddy's expected output for every fixture in this directory.
- `local/*.caddyfile` + `local/*.json` are fixtures authored for directives whose upstream fixture
  covers more surface than this build supports yet. Each pair states the exact JSON this build
  emits; a change to the pair is a reviewed compatibility-contract change.

Adding a fixture here is a claim of compatibility. Only add one when the adapter output matches.
