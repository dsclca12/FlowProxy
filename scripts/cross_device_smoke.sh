#!/usr/bin/env bash
set -euo pipefail

# Cross-device smoke test for FlowProxy.
# Requirements:
# - local tools: go, curl, jq, openssl, ssh, scp, python3
# - remote host reachable by ssh and can run the built binary

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOCAL_IP="${LOCAL_IP:-192.0.2.1}"
REMOTE_HOST="${REMOTE_HOST:-user@192.0.2.2}"
REMOTE_IP="${REMOTE_HOST##*@}"

WORK_DIR="${WORK_DIR:-/tmp/flowproxy-live}"
LOCAL_BIN="$WORK_DIR/flowproxy"
LOCAL_CTRL_DIR="$WORK_DIR/controller"
LOCAL_UPSTREAM_DIR="$WORK_DIR/upstream-b"

REMOTE_BASE="${REMOTE_BASE:-/tmp/flowproxy-live}"
REMOTE_BIN="$REMOTE_BASE/flowproxy"
REMOTE_FOLLOWER_DIR="$REMOTE_BASE/follower"

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change-me}"

CTRL_ADMIN_HTTP_PORT="${CTRL_ADMIN_HTTP_PORT:-19090}"
CTRL_ADMIN_HTTPS_PORT="${CTRL_ADMIN_HTTPS_PORT:-19444}"
CTRL_PROXY_HTTP_PORT="${CTRL_PROXY_HTTP_PORT:-18080}"
CTRL_PROXY_HTTPS_PORT="${CTRL_PROXY_HTTPS_PORT:-18443}"

FOLLOWER_ADMIN_HTTP_PORT="${FOLLOWER_ADMIN_HTTP_PORT:-59123}"
FOLLOWER_ADMIN_HTTPS_PORT="${FOLLOWER_ADMIN_HTTPS_PORT:-59443}"
FOLLOWER_PROXY_HTTP_PORT="${FOLLOWER_PROXY_HTTP_PORT:-58123}"
FOLLOWER_PROXY_HTTPS_PORT="${FOLLOWER_PROXY_HTTPS_PORT:-58443}"

UPSTREAM_PORT="${UPSTREAM_PORT:-29101}"
SYNC_INTERVAL="${SYNC_INTERVAL:-3s}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"

CTRL_COOKIE="$WORK_DIR/controller.cookie"
FOLLOWER_COOKIE="$WORK_DIR/follower.cookie"
CTRL_CA_CERT="$LOCAL_CTRL_DIR/admin-sync-ca.pem"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

log() {
  printf '[smoke] %s\n' "$*"
}

cleanup_local() {
  for p in "$CTRL_ADMIN_HTTP_PORT" "$CTRL_ADMIN_HTTPS_PORT" "$CTRL_PROXY_HTTP_PORT" "$CTRL_PROXY_HTTPS_PORT" "$UPSTREAM_PORT"; do
    pids="$(ss -ltnp 2>/dev/null | grep -E ":${p}\b" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u || true)"
    for pid in $pids; do
      kill "$pid" >/dev/null 2>&1 || true
    done
  done
}

cleanup_remote() {
  ssh "$REMOTE_HOST" "
    for p in $FOLLOWER_ADMIN_HTTP_PORT $FOLLOWER_ADMIN_HTTPS_PORT $FOLLOWER_PROXY_HTTP_PORT $FOLLOWER_PROXY_HTTPS_PORT; do
      PIDS=\$(ss -ltnp 2>/dev/null | grep -E \":\${p}\\\b\" | sed -n 's/.*pid=\\([0-9]\\+\\).*/\\1/p' | sort -u || true)
      for pid in \$PIDS; do kill \"\$pid\" >/dev/null 2>&1 || true; done
    done
  "
}

wait_http_200() {
  local url="$1"
  local retries="${2:-20}"
  local i
  for ((i = 0; i < retries; i++)); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$url" || true)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "wait_http_200 failed for $url" >&2
  return 1
}

main() {
  need_cmd go
  need_cmd curl
  need_cmd jq
  need_cmd openssl
  need_cmd ssh
  need_cmd scp
  need_cmd python3
  need_cmd ss

  mkdir -p "$WORK_DIR" "$LOCAL_UPSTREAM_DIR"

  log "building local binary"
  (cd "$ROOT_DIR" && go build -o "$LOCAL_BIN" ./cmd/flowproxy)

  log "cleaning local and remote old listeners"
  cleanup_local
  cleanup_remote

  rm -rf "$LOCAL_CTRL_DIR"
  mkdir -p "$LOCAL_CTRL_DIR/certs" "$LOCAL_CTRL_DIR/backups"

  log "starting controller"
  setsid env \
    NODE_ID=controller \
    NODE_NAME='Controller' \
    NODE_DATA_FILE="$LOCAL_CTRL_DIR/nodes.json" \
    DATA_FILE="$LOCAL_CTRL_DIR/sites.json" \
    SETTINGS_FILE="$LOCAL_CTRL_DIR/settings.json" \
    CERT_DATA_FILE="$LOCAL_CTRL_DIR/certificates.json" \
    CERT_DIR="$LOCAL_CTRL_DIR/certs" \
    ACCESS_LOG_FILE="$LOCAL_CTRL_DIR/access-logs.json" \
    BACKUP_DIR="$LOCAL_CTRL_DIR/backups" \
    ADMIN_AUTH_FILE="$LOCAL_CTRL_DIR/admin-auth.json" \
    ADMIN_ADDR="0.0.0.0:$CTRL_ADMIN_HTTP_PORT" \
    HTTP_ADDR="0.0.0.0:$CTRL_PROXY_HTTP_PORT" \
    HTTPS_ADDR="0.0.0.0:$CTRL_PROXY_HTTPS_PORT" \
    ADMIN_USERNAME="$ADMIN_USER" \
    ADMIN_PASSWORD="$ADMIN_PASS" \
    ENABLE_UI=true \
    ENABLE_AUTO_TLS=false \
    "$LOCAL_BIN" \
    > "$LOCAL_CTRL_DIR/server.log" 2>&1 < /dev/null &

  wait_http_200 "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/login.html"

  log "logging into controller and provisioning sync certificate (SAN includes $LOCAL_IP)"
  curl -s -c "$CTRL_COOKIE" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/auth/login" >/dev/null

  cert_json="$(curl -s -b "$CTRL_COOKIE" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\":\"cluster-sync-cert\",
      \"type\":\"self_signed\",
      \"domains\":[\"flowproxy.local\"],
      \"selfSigned\":{
        \"commonName\":\"$LOCAL_IP\",
        \"dnsNames\":[\"flowproxy.local\"],
        \"ipAddresses\":[\"$LOCAL_IP\"]
      }
    }" \
    "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/api/certificates")"
  cert_id="$(echo "$cert_json" | jq -r '.id')"
  [[ -n "$cert_id" && "$cert_id" != "null" ]] || { echo "failed to create cert: $cert_json" >&2; exit 1; }

  settings_resp="$(curl -s -b "$CTRL_COOKIE" \
    -H 'Content-Type: application/json' \
    -X PUT \
    -d "{\"adminTls\":{\"enabled\":true,\"httpsPort\":$CTRL_ADMIN_HTTPS_PORT,\"redirectHttp\":false,\"autoSelfSigned\":false,\"certificateId\":\"$cert_id\"}}" \
    "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/api/settings")"
  applied_cert_id="$(echo "$settings_resp" | jq -r '.adminTls.certificateId // empty')"
  [[ "$applied_cert_id" == "$cert_id" ]] || {
    echo "failed to apply adminTls certificateId, response: $settings_resp" >&2
    exit 1
  }

  code="$(curl -sk -s -o /dev/null -w '%{http_code}' "https://127.0.0.1:$CTRL_ADMIN_HTTPS_PORT/login.html" || true)"
  [[ "$code" == "200" ]] || {
    echo "controller https not ready after adminTls apply (code=$code)" >&2
    exit 1
  }

  curl -s -b "$CTRL_COOKIE" \
    "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/api/certificates/$cert_id/download?asset=cert&format=pem" \
    > "$CTRL_CA_CERT"
  openssl x509 -in "$CTRL_CA_CERT" -noout -ext subjectAltName | grep -q "$LOCAL_IP" || {
    echo "controller cert SAN does not include $LOCAL_IP" >&2
    exit 1
  }

  log "copying binary and CA cert to remote"
  scp -q "$LOCAL_BIN" "$REMOTE_HOST:$REMOTE_BIN"
  ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_FOLLOWER_DIR/certs' '$REMOTE_FOLLOWER_DIR/backups'"
  scp -q "$CTRL_CA_CERT" "$REMOTE_HOST:$REMOTE_FOLLOWER_DIR/controller-ca.pem"

  log "resetting remote follower runtime files"
  ssh "$REMOTE_HOST" "rm -f '$REMOTE_FOLLOWER_DIR'/*.json '$REMOTE_FOLLOWER_DIR'/*.cookie '$REMOTE_FOLLOWER_DIR'/server.log"

  log "starting remote follower"
  ssh "$REMOTE_HOST" "setsid env \
    NODE_ID=node-b \
    NODE_NAME='Node B' \
    NODE_DATA_FILE='$REMOTE_FOLLOWER_DIR/nodes.json' \
    DATA_FILE='$REMOTE_FOLLOWER_DIR/sites.json' \
    SETTINGS_FILE='$REMOTE_FOLLOWER_DIR/settings.json' \
    CERT_DATA_FILE='$REMOTE_FOLLOWER_DIR/certificates.json' \
    CERT_DIR='$REMOTE_FOLLOWER_DIR/certs' \
    ACCESS_LOG_FILE='$REMOTE_FOLLOWER_DIR/access-logs.json' \
    BACKUP_DIR='$REMOTE_FOLLOWER_DIR/backups' \
    ADMIN_AUTH_FILE='$REMOTE_FOLLOWER_DIR/admin-auth.json' \
    ADMIN_ADDR='0.0.0.0:$FOLLOWER_ADMIN_HTTP_PORT' \
    ADMIN_HTTPS_ADDR='0.0.0.0:$FOLLOWER_ADMIN_HTTPS_PORT' \
    ADMIN_TLS_AUTO_SELF_SIGNED=true \
    ADMIN_TLS_REDIRECT_HTTP=false \
    HTTP_ADDR='0.0.0.0:$FOLLOWER_PROXY_HTTP_PORT' \
    HTTPS_ADDR='0.0.0.0:$FOLLOWER_PROXY_HTTPS_PORT' \
    ADMIN_USERNAME='$ADMIN_USER' \
    ADMIN_PASSWORD='$ADMIN_PASS' \
    CLUSTER_SYNC_URL='https://$LOCAL_IP:$CTRL_ADMIN_HTTPS_PORT' \
    CLUSTER_SYNC_USERNAME='$ADMIN_USER' \
    CLUSTER_SYNC_PASSWORD='$ADMIN_PASS' \
    CLUSTER_SYNC_INTERVAL='$SYNC_INTERVAL' \
    SSL_CERT_FILE='$REMOTE_FOLLOWER_DIR/controller-ca.pem' \
    ENABLE_UI=true \
    ENABLE_AUTO_TLS=false \
    '$REMOTE_BIN' \
    > '$REMOTE_FOLLOWER_DIR/server.log' 2>&1 < /dev/null &"

  wait_http_200 "http://$REMOTE_IP:$FOLLOWER_ADMIN_HTTP_PORT/login.html" 25

  log "checking nodes synced on controller"
  nodes_ok=0
  for _ in $(seq 1 30); do
    nodes_tsv="$(curl -s -b "$CTRL_COOKIE" "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/api/nodes" | jq -r '.[] | [.id,.status] | @tsv')"
    if echo "$nodes_tsv" | grep -q '^controller[[:space:]]online$' && echo "$nodes_tsv" | grep -q '^node-b[[:space:]]online$'; then
      nodes_ok=1
      break
    fi
    sleep 1
  done
  [[ "$nodes_ok" == "1" ]] || {
    echo "node sync not ready, current nodes:" >&2
    echo "$nodes_tsv" >&2
    exit 1
  }

  log "checking follower read-only write protection"
  curl -s -c "$FOLLOWER_COOKIE" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "http://$REMOTE_IP:$FOLLOWER_ADMIN_HTTP_PORT/auth/login" >/dev/null

  site_status="$(curl -s -o /tmp/follower_sites_write.out -w '%{http_code}' -b "$FOLLOWER_COOKIE" \
    -H 'Content-Type: application/json' \
    -d '{"domain":"denied.local","upstream":"http://127.0.0.1:9999"}' \
    "http://$REMOTE_IP:$FOLLOWER_ADMIN_HTTP_PORT/api/sites")"
  [[ "$site_status" == "403" ]] || { echo "expected 403 for follower /api/sites write, got $site_status" >&2; exit 1; }

  cert_status="$(curl -s -o /tmp/follower_cert_write.out -w '%{http_code}' -b "$FOLLOWER_COOKIE" \
    -H 'Content-Type: application/json' \
    -d '{"type":"self_signed","domains":["denied.local"]}' \
    "http://$REMOTE_IP:$FOLLOWER_ADMIN_HTTP_PORT/api/certificates")"
  [[ "$cert_status" == "403" ]] || { echo "expected 403 for follower /api/certificates write, got $cert_status" >&2; exit 1; }

  log "starting local upstream and creating node-b site from controller"
  printf 'remote upstream\n' > "$LOCAL_UPSTREAM_DIR/index.html"
  if ! ss -ltnp 2>/dev/null | grep -q -E ":${UPSTREAM_PORT}\b"; then
    setsid python3 -m http.server "$UPSTREAM_PORT" --directory "$LOCAL_UPSTREAM_DIR" > "$LOCAL_UPSTREAM_DIR/server.log" 2>&1 < /dev/null &
    sleep 1
  fi
  curl -s "http://127.0.0.1:$UPSTREAM_PORT/" | grep -q 'remote upstream' || { echo "upstream not ready" >&2; exit 1; }

  create_site_json="$(curl -s -b "$CTRL_COOKIE" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\":\"pull-site\",
      \"nodeId\":\"node-b\",
      \"domain\":\"pull.test.local\",
      \"upstream\":\"http://$LOCAL_IP:$UPSTREAM_PORT\",
      \"upstreams\":[{\"url\":\"http://$LOCAL_IP:$UPSTREAM_PORT\",\"weight\":1}],
      \"enabled\":true,
      \"forceHttps\":false
    }" \
    "http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT/api/sites")"
  echo "$create_site_json" | jq -e '.id' >/dev/null

  sleep 5
  proxied="$(curl -s -H 'Host: pull.test.local' "http://$REMOTE_IP:$FOLLOWER_PROXY_HTTP_PORT/")"
  [[ "$proxied" == "remote upstream" ]] || {
    echo "unexpected proxy response from follower: $proxied" >&2
    exit 1
  }

  log "checking cluster sync runtime status"
  follower_sync="$(curl -s -b "$FOLLOWER_COOKIE" "http://$REMOTE_IP:$FOLLOWER_ADMIN_HTTP_PORT/api/cluster-sync")"
  echo "$follower_sync" | jq -e '.mode == "follower"' >/dev/null
  echo "$follower_sync" | jq -e '.consecutiveFailures == 0' >/dev/null
  echo "$follower_sync" | jq -e '.failCloseActive == false' >/dev/null

  log "smoke test passed"
  cat <<EOF
Controller: http://127.0.0.1:$CTRL_ADMIN_HTTP_PORT
Follower:   http://$REMOTE_IP:$FOLLOWER_ADMIN_HTTP_PORT
Follower proxy: http://$REMOTE_IP:$FOLLOWER_PROXY_HTTP_PORT (Host: pull.test.local)
EOF

  if [[ "$KEEP_RUNNING" != "1" ]]; then
    log "cleaning up listeners (KEEP_RUNNING=$KEEP_RUNNING)"
    cleanup_local
    cleanup_remote
  else
    log "keeping processes running (KEEP_RUNNING=1)"
  fi
}

main "$@"
