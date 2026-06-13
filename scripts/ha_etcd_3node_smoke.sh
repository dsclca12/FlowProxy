#!/usr/bin/env bash
set -euo pipefail

# 3-node HA smoke test:
# - etcd cluster across 3 nodes
# - FlowProxy nodes use STORAGE_BACKEND=etcd
# - verify shared control data + failover write after one etcd member down

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOCAL_IP="${LOCAL_IP:-192.0.2.1}"
HOST_B_IP="${HOST_B_IP:-192.0.2.2}"
HOST_C_IP="${HOST_C_IP:-192.0.2.3}"
HOST_B="${HOST_B:-user@${HOST_B_IP}}"
HOST_C="${HOST_C:-user@${HOST_C_IP}}"

WORK_DIR="${WORK_DIR:-/tmp/flowproxy-ha}"
LOCAL_BIN="$WORK_DIR/flowproxy"
REMOTE_BASE="${REMOTE_BASE:-/tmp/flowproxy-ha}"
REMOTE_BIN="$REMOTE_BASE/flowproxy"

ETCD_IMAGE="${ETCD_IMAGE:-quay.io/coreos/etcd:v3.5.15}"
ETCD_CLIENT_PORT="${ETCD_CLIENT_PORT:-32379}"
ETCD_PEER_PORT="${ETCD_PEER_PORT:-32380}"
ETCD_TOKEN="${ETCD_TOKEN:-flowproxy-ha-smoke}"
ETCD_PREFIX="${ETCD_PREFIX:-/flowproxy-ha-smoke-$(date +%s)}"
ETCD_ENDPOINTS="http://${LOCAL_IP}:${ETCD_CLIENT_PORT},http://${HOST_B_IP}:${ETCD_CLIENT_PORT},http://${HOST_C_IP}:${ETCD_CLIENT_PORT}"
ETCD_CLUSTER="node-a=http://${LOCAL_IP}:${ETCD_PEER_PORT},node-b=http://${HOST_B_IP}:${ETCD_PEER_PORT},node-c=http://${HOST_C_IP}:${ETCD_PEER_PORT}"

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change-me}"

NODE_A_ADMIN_PORT="${NODE_A_ADMIN_PORT:-62090}"
NODE_A_PROXY_PORT="${NODE_A_PROXY_PORT:-62080}"
NODE_B_ADMIN_PORT="${NODE_B_ADMIN_PORT:-62190}"
NODE_B_PROXY_PORT="${NODE_B_PROXY_PORT:-62180}"
NODE_C_ADMIN_PORT="${NODE_C_ADMIN_PORT:-62290}"
NODE_C_PROXY_PORT="${NODE_C_PROXY_PORT:-62280}"
UPSTREAM_PORT="${UPSTREAM_PORT:-62901}"

KEEP_RUNNING="${KEEP_RUNNING:-0}"

NODE_A_DIR="$WORK_DIR/node-a"
NODE_B_DIR="$REMOTE_BASE/node-b"
NODE_C_DIR="$REMOTE_BASE/node-c"

NODE_A_COOKIE="$WORK_DIR/node-a.cookie"
NODE_B_COOKIE="$WORK_DIR/node-b.cookie"
NODE_C_COOKIE="$WORK_DIR/node-c.cookie"

log() {
  printf '[ha-smoke] %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

wait_http_200() {
  local url="$1"
  local retries="${2:-30}"
  for ((i = 0; i < retries; i++)); do
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' "$url" || true)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "wait_http_200 failed: $url" >&2
  return 1
}

wait_etcd_healthy() {
  local endpoint="$1"
  local retries="${2:-30}"
  for ((i = 0; i < retries; i++)); do
    if curl -sf "$endpoint/health" | grep -q '"health":"true"'; then
      return 0
    fi
    sleep 1
  done
  echo "etcd not healthy: $endpoint" >&2
  return 1
}

cleanup_local() {
  for p in "$NODE_A_ADMIN_PORT" "$NODE_A_PROXY_PORT" "$UPSTREAM_PORT" "$ETCD_CLIENT_PORT" "$ETCD_PEER_PORT"; do
    pids="$(ss -ltnp 2>/dev/null | grep -E ":${p}\b" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u || true)"
    for pid in $pids; do
      kill "$pid" >/dev/null 2>&1 || true
    done
  done
  docker rm -f flowproxy-etcd >/dev/null 2>&1 || true
}

cleanup_remote() {
  local host="$1"
  local admin_port="$2"
  local proxy_port="$3"
  ssh "$host" "
    for p in $admin_port $proxy_port $ETCD_CLIENT_PORT $ETCD_PEER_PORT; do
      PIDS=\$(ss -ltnp 2>/dev/null | grep -E \":\${p}\\\b\" | sed -n 's/.*pid=\\([0-9]\\+\\).*/\\1/p' | sort -u || true)
      for pid in \$PIDS; do kill \"\$pid\" >/dev/null 2>&1 || true; done
    done
    docker rm -f flowproxy-etcd >/dev/null 2>&1 || true
  "
}

assert_local_port_free() {
  local p="$1"
  if ss -ltn 2>/dev/null | grep -q -E ":${p}\b"; then
    echo "local port already in use: $p" >&2
    return 1
  fi
}

assert_remote_port_free() {
  local host="$1"
  local p="$2"
  if ssh "$host" "ss -ltn 2>/dev/null | grep -q -E ':${p}\\\b'"; then
    echo "remote port already in use on $host: $p" >&2
    return 1
  fi
}

start_etcd_local() {
  mkdir -p "$WORK_DIR/etcd"
  docker run -d --name flowproxy-etcd \
    -p "${ETCD_CLIENT_PORT}:2379" \
    -p "${ETCD_PEER_PORT}:2380" \
    -v "$WORK_DIR/etcd:/etcd-data" \
    "$ETCD_IMAGE" \
    /usr/local/bin/etcd \
    --name node-a \
    --data-dir /etcd-data \
    --listen-peer-urls "http://0.0.0.0:2380" \
    --listen-client-urls "http://0.0.0.0:2379" \
    --initial-advertise-peer-urls "http://${LOCAL_IP}:${ETCD_PEER_PORT}" \
    --advertise-client-urls "http://${LOCAL_IP}:${ETCD_CLIENT_PORT}" \
    --initial-cluster "$ETCD_CLUSTER" \
    --initial-cluster-state new \
    --initial-cluster-token "$ETCD_TOKEN" >/dev/null
}

start_etcd_remote() {
  local host="$1"
  local name="$2"
  local ip="$3"
  ssh "$host" "
    mkdir -p '$REMOTE_BASE/etcd'
    docker run -d --name flowproxy-etcd \
      -p ${ETCD_CLIENT_PORT}:2379 \
      -p ${ETCD_PEER_PORT}:2380 \
      -v '$REMOTE_BASE/etcd:/etcd-data' \
      '$ETCD_IMAGE' \
      /usr/local/bin/etcd \
      --name $name \
      --data-dir /etcd-data \
      --listen-peer-urls 'http://0.0.0.0:2380' \
      --listen-client-urls 'http://0.0.0.0:2379' \
      --initial-advertise-peer-urls 'http://$ip:${ETCD_PEER_PORT}' \
      --advertise-client-urls 'http://$ip:${ETCD_CLIENT_PORT}' \
      --initial-cluster '$ETCD_CLUSTER' \
      --initial-cluster-state new \
      --initial-cluster-token '$ETCD_TOKEN' >/dev/null
  "
}

start_flowproxy_local() {
  mkdir -p "$NODE_A_DIR/certs" "$NODE_A_DIR/backups"
  nohup env \
    NODE_ID=node-a \
    NODE_NAME='Node A' \
    NODE_DATA_FILE="$NODE_A_DIR/nodes.json" \
    DATA_FILE="$NODE_A_DIR/sites.json" \
    SETTINGS_FILE="$NODE_A_DIR/settings.json" \
    CERT_DATA_FILE="$NODE_A_DIR/certificates.json" \
    CERT_DIR="$NODE_A_DIR/certs" \
    ACCESS_LOG_FILE="$NODE_A_DIR/access-logs.json" \
    BACKUP_DIR="$NODE_A_DIR/backups" \
    ADMIN_AUTH_FILE="$NODE_A_DIR/admin-auth.json" \
    ADMIN_ADDR="0.0.0.0:$NODE_A_ADMIN_PORT" \
    HTTP_ADDR="0.0.0.0:$NODE_A_PROXY_PORT" \
    HTTPS_ADDR="0.0.0.0:62443" \
    ADMIN_USERNAME="$ADMIN_USER" \
    ADMIN_PASSWORD="$ADMIN_PASS" \
    ENABLE_UI=true \
    ENABLE_AUTO_TLS=false \
    STORAGE_BACKEND=etcd \
    STORAGE_ETCD_ENDPOINTS="$ETCD_ENDPOINTS" \
    STORAGE_ETCD_PREFIX="$ETCD_PREFIX" \
    STORAGE_ETCD_DIAL_TIMEOUT=3s \
    "$LOCAL_BIN" \
    >"$NODE_A_DIR/server.log" 2>&1 < /dev/null &
}

start_flowproxy_remote() {
  local host="$1"
  local node_id="$2"
  local node_name="$3"
  local admin_port="$4"
  local proxy_port="$5"
  local node_dir="$6"
  ssh "$host" "mkdir -p '$node_dir/certs' '$node_dir/backups'"
  ssh "$host" "nohup env \
    NODE_ID='$node_id' \
    NODE_NAME='$node_name' \
    NODE_DATA_FILE='$node_dir/nodes.json' \
    DATA_FILE='$node_dir/sites.json' \
    SETTINGS_FILE='$node_dir/settings.json' \
    CERT_DATA_FILE='$node_dir/certificates.json' \
    CERT_DIR='$node_dir/certs' \
    ACCESS_LOG_FILE='$node_dir/access-logs.json' \
    BACKUP_DIR='$node_dir/backups' \
    ADMIN_AUTH_FILE='$node_dir/admin-auth.json' \
    ADMIN_ADDR='0.0.0.0:$admin_port' \
    HTTP_ADDR='0.0.0.0:$proxy_port' \
    HTTPS_ADDR='0.0.0.0:62443' \
    ADMIN_USERNAME='$ADMIN_USER' \
    ADMIN_PASSWORD='$ADMIN_PASS' \
    ENABLE_UI=true \
    ENABLE_AUTO_TLS=false \
    STORAGE_BACKEND=etcd \
    STORAGE_ETCD_ENDPOINTS='$ETCD_ENDPOINTS' \
    STORAGE_ETCD_PREFIX='$ETCD_PREFIX' \
    STORAGE_ETCD_DIAL_TIMEOUT=3s \
    '$REMOTE_BIN' \
    > '$node_dir/server.log' 2>&1 < /dev/null &"
}

main() {
  need_cmd go
  need_cmd curl
  need_cmd jq
  need_cmd ssh
  need_cmd scp
  need_cmd ss
  need_cmd docker
  need_cmd python3

  mkdir -p "$WORK_DIR"

  log "building flowproxy binary"
  (cd "$ROOT_DIR" && go build -o "$LOCAL_BIN" ./cmd/flowproxy)

  log "copying binary to remote hosts"
  ssh "$HOST_B" "mkdir -p '$REMOTE_BASE'"
  ssh "$HOST_C" "mkdir -p '$REMOTE_BASE'"
  scp -q "$LOCAL_BIN" "$HOST_B:$REMOTE_BIN"
  scp -q "$LOCAL_BIN" "$HOST_C:$REMOTE_BIN"

  log "cleaning old listeners/containers"
  cleanup_local
  cleanup_remote "$HOST_B" "$NODE_B_ADMIN_PORT" "$NODE_B_PROXY_PORT"
  cleanup_remote "$HOST_C" "$NODE_C_ADMIN_PORT" "$NODE_C_PROXY_PORT"
  assert_local_port_free "$NODE_A_ADMIN_PORT"
  assert_local_port_free "$NODE_A_PROXY_PORT"
  assert_local_port_free "$UPSTREAM_PORT"
  assert_remote_port_free "$HOST_B" "$NODE_B_ADMIN_PORT"
  assert_remote_port_free "$HOST_B" "$NODE_B_PROXY_PORT"
  assert_remote_port_free "$HOST_C" "$NODE_C_ADMIN_PORT"
  assert_remote_port_free "$HOST_C" "$NODE_C_PROXY_PORT"

  log "starting etcd 3-node cluster"
  start_etcd_local
  start_etcd_remote "$HOST_B" "node-b" "$HOST_B_IP"
  start_etcd_remote "$HOST_C" "node-c" "$HOST_C_IP"
  wait_etcd_healthy "http://${LOCAL_IP}:${ETCD_CLIENT_PORT}"
  wait_etcd_healthy "http://${HOST_B_IP}:${ETCD_CLIENT_PORT}"
  wait_etcd_healthy "http://${HOST_C_IP}:${ETCD_CLIENT_PORT}"

  log "starting 3 flowproxy nodes (etcd backend)"
  start_flowproxy_local
  start_flowproxy_remote "$HOST_B" "node-b" "Node B" "$NODE_B_ADMIN_PORT" "$NODE_B_PROXY_PORT" "$NODE_B_DIR"
  start_flowproxy_remote "$HOST_C" "node-c" "Node C" "$NODE_C_ADMIN_PORT" "$NODE_C_PROXY_PORT" "$NODE_C_DIR"
  wait_http_200 "http://${LOCAL_IP}:${NODE_A_ADMIN_PORT}/login.html"
  wait_http_200 "http://${HOST_B_IP}:${NODE_B_ADMIN_PORT}/login.html"
  wait_http_200 "http://${HOST_C_IP}:${NODE_C_ADMIN_PORT}/login.html"

  log "prepare local upstream"
  mkdir -p "$WORK_DIR/upstream"
  printf 'ha upstream\n' > "$WORK_DIR/upstream/index.html"
  if ! ss -ltnp 2>/dev/null | grep -q -E ":${UPSTREAM_PORT}\b"; then
    nohup python3 -m http.server "$UPSTREAM_PORT" --directory "$WORK_DIR/upstream" > "$WORK_DIR/upstream/server.log" 2>&1 < /dev/null &
    sleep 1
  fi
  curl -s "http://127.0.0.1:$UPSTREAM_PORT/" | grep -q 'ha upstream'

  log "login nodes"
  curl -s -c "$NODE_A_COOKIE" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "http://${LOCAL_IP}:${NODE_A_ADMIN_PORT}/auth/login" >/dev/null
  curl -s -c "$NODE_B_COOKIE" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "http://${HOST_B_IP}:${NODE_B_ADMIN_PORT}/auth/login" >/dev/null
  curl -s -c "$NODE_C_COOKIE" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "http://${HOST_C_IP}:${NODE_C_ADMIN_PORT}/auth/login" >/dev/null

  log "create site #1 from node-a (assigned to node-c)"
  site1="$(curl -s -b "$NODE_A_COOKIE" -H 'Content-Type: application/json' \
    -d "{
      \"name\":\"ha-site-c\",
      \"nodeId\":\"node-c\",
      \"domain\":\"ha-c.test.local\",
      \"upstream\":\"http://${LOCAL_IP}:${UPSTREAM_PORT}\",
      \"upstreams\":[{\"url\":\"http://${LOCAL_IP}:${UPSTREAM_PORT}\",\"weight\":1}],
      \"enabled\":true,
      \"forceHttps\":false
    }" \
    "http://${LOCAL_IP}:${NODE_A_ADMIN_PORT}/api/sites")"
  echo "$site1" | jq -e '.id' >/dev/null

  log "verify shared control data visible on node-b/node-c"
  curl -s -b "$NODE_B_COOKIE" "http://${HOST_B_IP}:${NODE_B_ADMIN_PORT}/api/sites" | jq -e '.[] | select(.domain=="ha-c.test.local")' >/dev/null
  curl -s -b "$NODE_C_COOKIE" "http://${HOST_C_IP}:${NODE_C_ADMIN_PORT}/api/sites" | jq -e '.[] | select(.domain=="ha-c.test.local")' >/dev/null

  log "verify node-c proxy serves site #1"
  sleep 2
  proxied1="$(curl -s -H 'Host: ha-c.test.local' "http://${HOST_C_IP}:${NODE_C_PROXY_PORT}/")"
  [[ "$proxied1" == "ha upstream" ]] || { echo "unexpected proxy result on node-c: $proxied1" >&2; exit 1; }

  log "inject failure: stop etcd member on ${HOST_C_IP}"
  ssh "$HOST_C" "docker stop flowproxy-etcd >/dev/null"
  wait_etcd_healthy "http://${LOCAL_IP}:${ETCD_CLIENT_PORT}" 20
  wait_etcd_healthy "http://${HOST_B_IP}:${ETCD_CLIENT_PORT}" 20

  log "write after failover: create site #2 from node-a (assigned to node-b)"
  site2="$(curl -s -b "$NODE_A_COOKIE" -H 'Content-Type: application/json' \
    -d "{
      \"name\":\"ha-site-b\",
      \"nodeId\":\"node-b\",
      \"domain\":\"ha-b.test.local\",
      \"upstream\":\"http://${LOCAL_IP}:${UPSTREAM_PORT}\",
      \"upstreams\":[{\"url\":\"http://${LOCAL_IP}:${UPSTREAM_PORT}\",\"weight\":1}],
      \"enabled\":true,
      \"forceHttps\":false
    }" \
    "http://${LOCAL_IP}:${NODE_A_ADMIN_PORT}/api/sites")"
  echo "$site2" | jq -e '.id' >/dev/null

  log "verify node-b can read/proxy site #2 while one etcd member is down"
  curl -s -b "$NODE_B_COOKIE" "http://${HOST_B_IP}:${NODE_B_ADMIN_PORT}/api/sites" | jq -e '.[] | select(.domain=="ha-b.test.local")' >/dev/null
  sleep 2
  proxied2="$(curl -s -H 'Host: ha-b.test.local' "http://${HOST_B_IP}:${NODE_B_PROXY_PORT}/")"
  [[ "$proxied2" == "ha upstream" ]] || { echo "unexpected proxy result on node-b: $proxied2" >&2; exit 1; }

  log "recover etcd member on ${HOST_C_IP}"
  ssh "$HOST_C" "docker start flowproxy-etcd >/dev/null"
  wait_etcd_healthy "http://${HOST_C_IP}:${ETCD_CLIENT_PORT}" 30

  log "verify node registry includes 3 nodes"
  nodes_json="$(curl -s -b "$NODE_A_COOKIE" "http://${LOCAL_IP}:${NODE_A_ADMIN_PORT}/api/nodes")"
  echo "$nodes_json" | jq -e '.[] | select(.id=="node-a")' >/dev/null
  echo "$nodes_json" | jq -e '.[] | select(.id=="node-b")' >/dev/null
  echo "$nodes_json" | jq -e '.[] | select(.id=="node-c")' >/dev/null

  log "HA etcd smoke test passed"
  cat <<EOF
ETCD endpoints:
  - http://${LOCAL_IP}:${ETCD_CLIENT_PORT}
  - http://${HOST_B_IP}:${ETCD_CLIENT_PORT}
  - http://${HOST_C_IP}:${ETCD_CLIENT_PORT}
FlowProxy admin:
  - node-a: http://${LOCAL_IP}:${NODE_A_ADMIN_PORT}
  - node-b: http://${HOST_B_IP}:${NODE_B_ADMIN_PORT}
  - node-c: http://${HOST_C_IP}:${NODE_C_ADMIN_PORT}
Shared prefix: ${ETCD_PREFIX}
EOF

  if [[ "$KEEP_RUNNING" != "1" ]]; then
    log "cleanup all listeners/containers (KEEP_RUNNING=$KEEP_RUNNING)"
    cleanup_local
    cleanup_remote "$HOST_B" "$NODE_B_ADMIN_PORT" "$NODE_B_PROXY_PORT"
    cleanup_remote "$HOST_C" "$NODE_C_ADMIN_PORT" "$NODE_C_PROXY_PORT"
  else
    log "keeping environment running (KEEP_RUNNING=1)"
  fi
}

main "$@"
