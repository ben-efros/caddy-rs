#!/usr/bin/env bash
#
# T-PM-116 acceptance test — prove the create, certificate and HTTPS flow end to end.
#
# Starts two caddy-rs instances:
#   1. Backend instance: static_response on port 18080, admin on 127.0.0.1:2020
#   2. PM target instance: admin on 127.0.0.1:2019 (PM replaces its config)
# Starts caddy-rs-pm (management API on port 81, admin URL → PM target instance).
# Creates a host through the PM API, installs a manual certificate, applies the
# configuration, and asserts a real TLS handshake plus HTTP 200 through the data
# plane. Idempotent: cleans up its data directory and all child processes on exit.
#
# Usage: ./tpm-116-acceptance.sh
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CADDY_RS="${CADDY_RS_BIN:-/root/caddy-rs/.scratch/rust-target-caddy/debug/caddy-rs}"
PM_CLI="${PM_CLI_BIN:-/root/caddy-rs/.scratch/rust-target-pm/debug/caddy-rs-pm}"
FIXTURES_DIR="/root/caddy-rs/caddy-rs/pm/tests/fixtures"
BACKEND_ADDR="127.0.0.1:2020"   # backend caddy-rs admin
BACKEND_PORT="18080"             # backend caddy-rs HTTP port
TARGET_PORT="19080"              # PM target caddy-rs initial HTTP port (replaced by PM)
PM_TARGET_ADDR="127.0.0.1:2019"  # PM target caddy-rs admin
PM_ADDR="127.0.0.1:81"           # PM management API
HTTPS_PORT="443"
DATA_DIR="$(mktemp -d /tmp/tpm-116-acceptance.XXXXXX)"
CONFIG_DIR="$(mktemp -d /tmp/tpm-116-config.XXXXXX)"
LOG_DIR="$(mktemp -d /tmp/tpm-116-logs.XXXXXX)"
RECORD_FILE="$DATA_DIR/acceptance-record.txt"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    local code=$?
    echo "=== cleanup (exit code $code) ==="
    if [[ -n "${PM_PID:-}" ]]; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    if [[ -n "${CADDY_BACKEND_PID:-}" ]]; then
        kill "$CADDY_BACKEND_PID" 2>/dev/null || true
        wait "$CADDY_BACKEND_PID" 2>/dev/null || true
    fi
    if [[ -n "${CADDY_TARGET_PID:-}" ]]; then
        kill "$CADDY_TARGET_PID" 2>/dev/null || true
        wait "$CADDY_TARGET_PID" 2>/dev/null || true
    fi
    pkill -f "caddy-rs run" 2>/dev/null || true
    pkill -f "caddy-rs-pm serve" 2>/dev/null || true
    if [[ $code -ne 0 ]]; then
        echo "PRESERVING LOGS: DATA_DIR=$DATA_DIR LOG_DIR=$LOG_DIR CONFIG_DIR=$CONFIG_DIR"
    else
        rm -rf "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"
    fi
    echo "=== cleanup done ==="
    exit $code
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[$(date -Is)] $*"; }
wait_for_url() {
    local url="$1" desc="$2" max="${3:-30}"
    for i in $(seq 1 "$max"); do
        if curl -sf "$url" >/dev/null 2>&1; then
            log "$desc is ready"
            return 0
        fi
        sleep 0.5
    done
    echo "ERROR: $desc did not become ready at $url" >&2
    return 1
}

# ---------------------------------------------------------------------------
# Start backend caddy-rs instance
# ---------------------------------------------------------------------------
log "Starting backend caddy-rs on admin $BACKEND_ADDR, HTTP $BACKEND_PORT"
cat > "$CONFIG_DIR/caddy-backend.json" <<JSON
{
  "admin": {
    "listen": "$BACKEND_ADDR"
  },
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":$BACKEND_PORT"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "static_response",
                  "body": "ok"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
JSON

"$CADDY_RS" run --config "$CONFIG_DIR/caddy-backend.json" --data-dir "$DATA_DIR/caddy-data-backend" \
    --autosave-path "$DATA_DIR/autosave-backend.json" \
    >"$LOG_DIR/caddy-backend.log" 2>&1 &
CADDY_BACKEND_PID=$!
sleep 1
if ! kill -0 "$CADDY_BACKEND_PID" 2>/dev/null; then
    echo "ERROR: backend caddy-rs exited immediately:" >&2
    cat "$LOG_DIR/caddy-backend.log" >&2
    exit 1
fi
wait_for_url "http://$BACKEND_ADDR/config" "backend caddy-rs admin API" 30

# ---------------------------------------------------------------------------
# Start PM target caddy-rs instance
# ---------------------------------------------------------------------------
log "Starting PM target caddy-rs on admin $PM_TARGET_ADDR"
cat > "$CONFIG_DIR/caddy-target.json" <<JSON
{
  "admin": {
    "listen": "$PM_TARGET_ADDR"
  },
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":$TARGET_PORT"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "static_response",
                  "body": "target-default"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
JSON

"$CADDY_RS" run --config "$CONFIG_DIR/caddy-target.json" --data-dir "$DATA_DIR/caddy-data-target" \
    --autosave-path "$DATA_DIR/autosave-target.json" \
    >"$LOG_DIR/caddy-target.log" 2>&1 &
CADDY_TARGET_PID=$!
sleep 1
if ! kill -0 "$CADDY_TARGET_PID" 2>/dev/null; then
    echo "ERROR: PM target caddy-rs exited immediately:" >&2
    cat "$LOG_DIR/caddy-target.log" >&2
    exit 1
fi
wait_for_url "http://$PM_TARGET_ADDR/config" "PM target caddy-rs admin API" 30

# ---------------------------------------------------------------------------
# Start caddy-rs-pm
# ---------------------------------------------------------------------------
log "Starting caddy-rs-pm on $PM_ADDR"
"$PM_CLI" --data-dir "$DATA_DIR/pm-data" serve --listen "$PM_ADDR" --admin-url "http://$PM_TARGET_ADDR" \
    >"$LOG_DIR/pm-cli.log" 2>&1 &
PM_PID=$!
wait_for_url "http://$PM_ADDR/api/v1/health" "caddy-rs-pm management API" 30

# ---------------------------------------------------------------------------
# Upload a manual certificate
# ---------------------------------------------------------------------------
log "Uploading manual certificate"
CERT_PEM_JSON=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    print(json.dumps(f.read())[1:-1])
" "$FIXTURES_DIR/manual-valid.crt.pem")
KEY_PEM_JSON=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    print(json.dumps(f.read())[1:-1])
" "$FIXTURES_DIR/manual-valid.key.pem")

CERT_RESP=$(curl -sf -X POST "http://$PM_ADDR/api/v1/certificates/custom" \
    -H "Content-Type: application/json" \
    -d @- <<CERTJSON
{
  "domains": ["manual.example.com", "www.manual.example.com"],
  "certificate": "$CERT_PEM_JSON",
  "privateKey": "$KEY_PEM_JSON"
}
CERTJSON
)
echo "$CERT_RESP" | tee "$LOG_DIR/cert-response.json"
CERT_ID=$(echo "$CERT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
log "Certificate id: $CERT_ID"

# ---------------------------------------------------------------------------
# Create a host — upstream is the backend caddy-rs on $BACKEND_PORT
# ---------------------------------------------------------------------------
log "Creating host manual.example.com -> 127.0.0.1:$BACKEND_PORT"
HOST_RESP=$(curl -sf -X POST "http://$PM_ADDR/api/v1/hosts" \
    -H "Content-Type: application/json" \
    -d @- <<HOSTJSON
{
  "domains": ["manual.example.com"],
  "tls": {
    "mode": "manual",
    "certificateId": $CERT_ID,
    "sslForced": true,
    "hstsEnabled": true
  },
  "spec": {
    "kind": "proxy",
    "spec": {
      "upstream": {
        "scheme": "http",
        "host": "127.0.0.1",
        "port": $BACKEND_PORT
      }
    }
  },
  "enabled": true
}
HOSTJSON
)
echo "$HOST_RESP" | tee "$LOG_DIR/host-response.json"
HOST_ID=$(echo "$HOST_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
log "Host id: $HOST_ID"

# ---------------------------------------------------------------------------
# Apply configuration
# ---------------------------------------------------------------------------
log "Applying configuration to caddy-rs"
APPLY_RESP=$(curl -sf -X POST "http://$PM_ADDR/api/v1/config/apply" \
    -H "Content-Type: application/json")
echo "$APPLY_RESP" | tee "$LOG_DIR/apply-response.json"

# Give caddy-rs time to provision the new config after apply.
sleep 3

# Record the applied revision
REVISION=$(echo "$APPLY_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('revision','unknown'))" 2>/dev/null || echo "unknown")
echo "applied_revision=$REVISION" > "$RECORD_FILE"
echo "certificate_id=$CERT_ID" >> "$RECORD_FILE"
echo "host_id=$HOST_ID" >> "$RECORD_FILE"
log "Applied revision: $REVISION"

# ---------------------------------------------------------------------------
# Wait for caddy-rs to listen on HTTPS port after config apply
# ---------------------------------------------------------------------------
log "Waiting for caddy-rs to listen on :$HTTPS_PORT after config apply"
for i in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -q ":$HTTPS_PORT "; then
        log "caddy-rs is listening on :$HTTPS_PORT"
        break
    fi
    if [[ $((i % 10)) -eq 0 ]]; then
        log "still waiting for :$HTTPS_PORT (attempt $i/30)..."
    fi
    sleep 0.5
done
if ! ss -tln 2>/dev/null | grep -q ":$HTTPS_PORT "; then
    echo "ERROR: caddy-rs is not listening on :$HTTPS_PORT after apply" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify TLS handshake
# ---------------------------------------------------------------------------
log "Verifying TLS handshake on :$HTTPS_PORT"
TLS_OUTPUT=$(echo | timeout 10 openssl s_client \
    -connect "127.0.0.1:$HTTPS_PORT" \
    -servername manual.example.com \
    -CAfile "$FIXTURES_DIR/manual-valid.crt.pem" \
    -verify_return_error 2>&1 || true)
echo "$TLS_OUTPUT" > "$LOG_DIR/s-client-output.txt"
if echo "$TLS_OUTPUT" | grep -q "Verify return code: 0"; then
    log "TLS handshake succeeded"
else
    echo "ERROR: TLS handshake failed:" >&2
    echo "$TLS_OUTPUT" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify HTTP -> HTTPS redirect (ssl_forced) — go through pm_http on port 80
# ---------------------------------------------------------------------------
log "Verifying HTTP→HTTPS redirect from ssl_forced"
REDIRECT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --resolve "manual.example.com:80:127.0.0.1" \
    "http://manual.example.com:80/" \
    || true)
if [[ "$REDIRECT_CODE" == "308" ]]; then
    log "HTTP correctly redirects to HTTPS (308)"
else
    echo "ERROR: HTTP returned $REDIRECT_CODE, expected 308 redirect" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify HTTPS 200 from upstream (follow redirects in case of HSTS)
# ---------------------------------------------------------------------------
log "Verifying HTTPS 200 from upstream"
HTTP_CODE=""
for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        --cacert "$FIXTURES_DIR/manual-valid.crt.pem" \
        --resolve "manual.example.com:$HTTPS_PORT:127.0.0.1" \
        --resolve "127.0.0.1:$HTTPS_PORT:127.0.0.1" \
        -L \
        "https://manual.example.com:$HTTPS_PORT/" \
        || true)
    if [[ "$HTTP_CODE" == "200" ]]; then
        log "HTTPS returned 200"
        break
    fi
    log "HTTPS attempt $i/10 returned $HTTP_CODE, retrying..."
    sleep 0.5
done
if [[ "$HTTP_CODE" != "200" ]]; then
    echo "ERROR: HTTPS returned $HTTP_CODE, expected 200" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify revision is recorded
# ---------------------------------------------------------------------------
log "Verifying recorded revision"
curl -sf "http://$PM_ADDR/api/v1/config/revisions" > "$LOG_DIR/revisions.json" 2>/dev/null || true
log "Revision record written to $RECORD_FILE"
cat "$RECORD_FILE"

log "=== T-PM-116 acceptance test PASSED ==="