#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

DEFAULT_ADMIN_PORT=9000
DEFAULT_PROXY_HTTP_PORT=80
DEFAULT_PROXY_HTTPS_PORT=443

ADMIN_PORT_EXPLICIT=false
PROXY_HTTP_PORT_EXPLICIT=false
PROXY_HTTPS_PORT_EXPLICIT=false
if [[ -n "${ADMIN_PORT:-}" ]]; then
  ADMIN_PORT_EXPLICIT=true
fi
if [[ -n "${PROXY_HTTP_PORT:-}" ]]; then
  PROXY_HTTP_PORT_EXPLICIT=true
fi
if [[ -n "${PROXY_HTTPS_PORT:-}" ]]; then
  PROXY_HTTPS_PORT_EXPLICIT=true
fi

ADMIN_PORT="${ADMIN_PORT:-$DEFAULT_ADMIN_PORT}"
PROXY_HTTP_PORT="${PROXY_HTTP_PORT:-$DEFAULT_PROXY_HTTP_PORT}"
PROXY_HTTPS_PORT="${PROXY_HTTPS_PORT:-$DEFAULT_PROXY_HTTPS_PORT}"
ENABLE_AUTO_TLS="${ENABLE_AUTO_TLS:-false}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-}"
ENABLE_UI="${ENABLE_UI:-true}"
CONFIG_FILE="${CONFIG_FILE:-}"
SETTINGS_FILE="${SETTINGS_FILE:-./data/settings.json}"

usage() {
  cat <<USAGE
Usage: ./start.sh [options]

Options:
  --admin-port <port>   Admin Web UI/API port (default: 9000)
  --http-port <port>    Proxy HTTP listen port (default: 80)
  --https-port <port>   Proxy HTTPS listen port (default: 443)
                         Auto fallback is used when defaults are unavailable
  --auto-tls <bool>     Enable Auto TLS, true or false (default: false)
  --email <email>       Let's Encrypt email (optional)
  --enable-ui <bool>    Enable built-in admin UI, true or false (default: true)
  --config <path>       Declarative YAML config file path (optional)
  -h, --help            Show this help

Security defaults:
  Admin binds to 0.0.0.0 by default in this script.
  To expose admin on public interfaces, set ADMIN_USERNAME and ADMIN_PASSWORD.

Admin credential reset (CLI only, not Web):
  go run ./cmd/flowproxy reset-admin --username <new-user> --password <new-password>
USAGE
}

is_valid_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  ((port >= 1 && port <= 65535))
}

require_value() {
  local opt="$1"
  local maybe="${2:-}"
  if [[ -z "$maybe" || "$maybe" == --* ]]; then
    echo "Option ${opt} requires a value" >&2
    exit 1
  fi
}

trim_spaces() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

port_from_addr() {
  local raw
  raw="$(trim_spaces "$1")"
  if [[ -z "$raw" ]]; then
    return 1
  fi
  if [[ "$raw" =~ ^:([0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$raw" =~ ^([0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$raw" =~ ^\[[^]]+\]:([0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$raw" =~ :([0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

config_section_value() {
  local file="$1"
  local section="$2"
  local key="$3"
  awk -v section="$section" -v key="$key" '
    function ltrim(s) { sub(/^[ \t]+/, "", s); return s }
    function rtrim(s) { sub(/[ \t]+$/, "", s); return s }
    {
      line = $0
      sub(/\r$/, "", line)
      if (line ~ "^[ \t]*" section ":[ \t]*(#.*)?$") {
        in_section = 1
        next
      }
      if (in_section && line ~ /^[^ \t#]/) {
        in_section = 0
      }
      if (!in_section) {
        next
      }
      if (line ~ "^[ \t]*" key ":[ \t]*") {
        sub("^[ \t]*" key ":[ \t]*", "", line)
        sub(/[ \t]+#.*$/, "", line)
        line = rtrim(ltrim(line))
        if (line ~ /^".*"$/ || line ~ /^'\''.*'\''$/) {
          line = substr(line, 2, length(line) - 2)
        }
        print line
        exit
      }
    }
  ' "$file"
}

settings_json_web_port() {
  local file="$1"
  awk '
    /"webPort"[ \t]*:[ \t]*[0-9]+/ {
      line = $0
      sub(/^.*"webPort"[ \t]*:[ \t]*/, "", line)
      sub(/[^0-9].*$/, "", line)
      print line
      exit
    }
  ' "$file"
}

can_bind_port() {
  local port="$1"
  # Non-root users cannot bind privileged ports (<1024) in common Linux setups.
  if ((port < 1024 && EUID != 0)); then
    return 1
  fi
  return 0
}

is_port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[:])${port}$"
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  return 1
}

is_selected_port() {
  local port="$1"
  local selected
  for selected in "${SELECTED_PORTS[@]}"; do
    if [[ "$selected" == "$port" ]]; then
      return 0
    fi
  done
  return 1
}

resolve_port() {
  local name="$1"
  local explicit="$2"
  shift 2
  local candidates=("$@")
  local candidate
  for candidate in "${candidates[@]}"; do
    if ! is_valid_port "$candidate"; then
      continue
    fi
    if is_selected_port "$candidate"; then
      continue
    fi
    if ! can_bind_port "$candidate"; then
      continue
    fi
    if is_port_in_use "$candidate"; then
      continue
    fi
    if [[ "$explicit" == "false" && "$candidate" != "${candidates[0]}" ]]; then
      AUTO_PORT_MESSAGES+=("${name} switched to :${candidate} (default :${candidates[0]} unavailable)")
    fi
    RESOLVED_PORT="$candidate"
    return 0
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-port)
      require_value "$1" "${2:-}"
      ADMIN_PORT="$2"
      ADMIN_PORT_EXPLICIT=true
      shift 2
      ;;
    --http-port)
      require_value "$1" "${2:-}"
      PROXY_HTTP_PORT="$2"
      PROXY_HTTP_PORT_EXPLICIT=true
      shift 2
      ;;
    --https-port)
      require_value "$1" "${2:-}"
      PROXY_HTTPS_PORT="$2"
      PROXY_HTTPS_PORT_EXPLICIT=true
      shift 2
      ;;
    --auto-tls)
      require_value "$1" "${2:-}"
      ENABLE_AUTO_TLS="$2"
      shift 2
      ;;
    --email)
      require_value "$1" "${2:-}"
      LETSENCRYPT_EMAIL="$2"
      shift 2
      ;;
    --enable-ui)
      require_value "$1" "${2:-}"
      ENABLE_UI="$2"
      shift 2
      ;;
    --config)
      require_value "$1" "${2:-}"
      CONFIG_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

CONFIG_OVERRIDE_MESSAGES=()
PORT_SOURCE_MESSAGES=()
ADMIN_PORT_FROM_CONFIG=false
PROXY_HTTP_PORT_FROM_CONFIG=false
PROXY_HTTPS_PORT_FROM_CONFIG=false
ADMIN_PORT_FROM_SETTINGS=false

ADMIN_PORT_USER_EXPLICIT="$ADMIN_PORT_EXPLICIT"
PROXY_HTTP_PORT_USER_EXPLICIT="$PROXY_HTTP_PORT_EXPLICIT"
PROXY_HTTPS_PORT_USER_EXPLICIT="$PROXY_HTTPS_PORT_EXPLICIT"

EFFECTIVE_CONFIG_FILE="$CONFIG_FILE"
if [[ -z "$EFFECTIVE_CONFIG_FILE" && -f "./flowproxy.yaml" ]]; then
  EFFECTIVE_CONFIG_FILE="./flowproxy.yaml"
fi

if [[ -n "$EFFECTIVE_CONFIG_FILE" && -f "$EFFECTIVE_CONFIG_FILE" ]]; then
  raw_settings_file="$(config_section_value "$EFFECTIVE_CONFIG_FILE" "runtime" "settingsFile")"
  if [[ -n "$raw_settings_file" ]]; then
    SETTINGS_FILE="$(trim_spaces "$raw_settings_file")"
  fi

  raw_admin_addr="$(config_section_value "$EFFECTIVE_CONFIG_FILE" "runtime" "adminAddr")"
  raw_http_addr="$(config_section_value "$EFFECTIVE_CONFIG_FILE" "runtime" "httpAddr")"
  raw_https_addr="$(config_section_value "$EFFECTIVE_CONFIG_FILE" "runtime" "httpsAddr")"

  if [[ -n "$raw_admin_addr" ]]; then
    parsed_admin_port="$(port_from_addr "$raw_admin_addr" || true)"
    if ! is_valid_port "$parsed_admin_port"; then
      echo "Invalid runtime.adminAddr in ${EFFECTIVE_CONFIG_FILE}: ${raw_admin_addr}" >&2
      exit 1
    fi
    if [[ "$ADMIN_PORT_USER_EXPLICIT" == "true" ]]; then
      CONFIG_OVERRIDE_MESSAGES+=("runtime.adminAddr in ${EFFECTIVE_CONFIG_FILE} overrides --admin-port/ADMIN_PORT")
    fi
    ADMIN_PORT="$parsed_admin_port"
    ADMIN_PORT_EXPLICIT=true
    ADMIN_PORT_FROM_CONFIG=true
    PORT_SOURCE_MESSAGES+=("ADMIN_PORT uses runtime.adminAddr in ${EFFECTIVE_CONFIG_FILE}")
  fi
  if [[ -n "$raw_http_addr" ]]; then
    parsed_http_port="$(port_from_addr "$raw_http_addr" || true)"
    if ! is_valid_port "$parsed_http_port"; then
      echo "Invalid runtime.httpAddr in ${EFFECTIVE_CONFIG_FILE}: ${raw_http_addr}" >&2
      exit 1
    fi
    if [[ "$PROXY_HTTP_PORT_USER_EXPLICIT" == "true" ]]; then
      CONFIG_OVERRIDE_MESSAGES+=("runtime.httpAddr in ${EFFECTIVE_CONFIG_FILE} overrides --http-port/PROXY_HTTP_PORT")
    fi
    PROXY_HTTP_PORT="$parsed_http_port"
    PROXY_HTTP_PORT_EXPLICIT=true
    PROXY_HTTP_PORT_FROM_CONFIG=true
    PORT_SOURCE_MESSAGES+=("PROXY_HTTP_PORT uses runtime.httpAddr in ${EFFECTIVE_CONFIG_FILE}")
  fi
  if [[ -n "$raw_https_addr" ]]; then
    parsed_https_port="$(port_from_addr "$raw_https_addr" || true)"
    if ! is_valid_port "$parsed_https_port"; then
      echo "Invalid runtime.httpsAddr in ${EFFECTIVE_CONFIG_FILE}: ${raw_https_addr}" >&2
      exit 1
    fi
    if [[ "$PROXY_HTTPS_PORT_USER_EXPLICIT" == "true" ]]; then
      CONFIG_OVERRIDE_MESSAGES+=("runtime.httpsAddr in ${EFFECTIVE_CONFIG_FILE} overrides --https-port/PROXY_HTTPS_PORT")
    fi
    PROXY_HTTPS_PORT="$parsed_https_port"
    PROXY_HTTPS_PORT_EXPLICIT=true
    PROXY_HTTPS_PORT_FROM_CONFIG=true
    PORT_SOURCE_MESSAGES+=("PROXY_HTTPS_PORT uses runtime.httpsAddr in ${EFFECTIVE_CONFIG_FILE}")
  fi

  raw_settings_web_port="$(config_section_value "$EFFECTIVE_CONFIG_FILE" "settings" "webPort")"
  if [[ -n "$raw_settings_web_port" ]]; then
    parsed_settings_web_port="$(trim_spaces "$raw_settings_web_port")"
    if ! is_valid_port "$parsed_settings_web_port"; then
      echo "Invalid settings.webPort in ${EFFECTIVE_CONFIG_FILE}: ${raw_settings_web_port}" >&2
      exit 1
    fi
    if [[ "$ADMIN_PORT_USER_EXPLICIT" == "true" || "$ADMIN_PORT_FROM_CONFIG" == "true" ]]; then
      CONFIG_OVERRIDE_MESSAGES+=("settings.webPort in ${EFFECTIVE_CONFIG_FILE} overrides admin port selection")
    fi
    ADMIN_PORT="$parsed_settings_web_port"
    ADMIN_PORT_EXPLICIT=true
    ADMIN_PORT_FROM_SETTINGS=true
    PORT_SOURCE_MESSAGES+=("ADMIN_PORT uses settings.webPort in ${EFFECTIVE_CONFIG_FILE}")
  fi
fi

if [[ "$ADMIN_PORT_FROM_SETTINGS" == "false" && -f "$SETTINGS_FILE" ]]; then
  settings_file_web_port="$(settings_json_web_port "$SETTINGS_FILE" || true)"
  if [[ -n "$settings_file_web_port" ]]; then
    parsed_settings_file_web_port="$(trim_spaces "$settings_file_web_port")"
    if is_valid_port "$parsed_settings_file_web_port"; then
      if [[ "$ADMIN_PORT_USER_EXPLICIT" == "true" || "$ADMIN_PORT_FROM_CONFIG" == "true" ]]; then
        CONFIG_OVERRIDE_MESSAGES+=("settings file ${SETTINGS_FILE} webPort overrides admin port selection")
      fi
      ADMIN_PORT="$parsed_settings_file_web_port"
      ADMIN_PORT_EXPLICIT=true
      ADMIN_PORT_FROM_SETTINGS=true
      PORT_SOURCE_MESSAGES+=("ADMIN_PORT uses webPort in ${SETTINGS_FILE}")
    fi
  fi
fi

for item in "ADMIN_PORT:$ADMIN_PORT" "PROXY_HTTP_PORT:$PROXY_HTTP_PORT" "PROXY_HTTPS_PORT:$PROXY_HTTPS_PORT"; do
  key="${item%%:*}"
  value="${item##*:}"
  if ! is_valid_port "$value"; then
    echo "Invalid ${key}: $value (must be 1-65535)" >&2
    exit 1
  fi
done

SELECTED_PORTS=()
AUTO_PORT_MESSAGES=()
RESOLVED_PORT=""

if [[ "$ADMIN_PORT_EXPLICIT" == "true" ]]; then
  if ! can_bind_port "$ADMIN_PORT"; then
    echo "Cannot bind explicit ADMIN_PORT=$ADMIN_PORT (requires root or CAP_NET_BIND_SERVICE)" >&2
    exit 1
  fi
  if is_port_in_use "$ADMIN_PORT"; then
    echo "Cannot bind explicit ADMIN_PORT=$ADMIN_PORT (already in use)" >&2
    exit 1
  fi
  SELECTED_PORTS+=("$ADMIN_PORT")
else
  if ! resolve_port "ADMIN_PORT" "false" "$ADMIN_PORT" 19000 29000 39000; then
    echo "Failed to auto-select ADMIN_PORT. Please set --admin-port explicitly." >&2
    exit 1
  fi
  ADMIN_PORT="$RESOLVED_PORT"
  SELECTED_PORTS+=("$ADMIN_PORT")
fi

if [[ "$PROXY_HTTP_PORT_EXPLICIT" == "true" ]]; then
  if ! can_bind_port "$PROXY_HTTP_PORT"; then
    echo "Cannot bind explicit PROXY_HTTP_PORT=$PROXY_HTTP_PORT (requires root or CAP_NET_BIND_SERVICE)" >&2
    exit 1
  fi
  if is_selected_port "$PROXY_HTTP_PORT"; then
    echo "PROXY_HTTP_PORT duplicates another selected port: $PROXY_HTTP_PORT" >&2
    exit 1
  fi
  if is_port_in_use "$PROXY_HTTP_PORT"; then
    echo "Cannot bind explicit PROXY_HTTP_PORT=$PROXY_HTTP_PORT (already in use)" >&2
    exit 1
  fi
  SELECTED_PORTS+=("$PROXY_HTTP_PORT")
else
  if ! resolve_port "PROXY_HTTP_PORT" "false" "$PROXY_HTTP_PORT" 8080 18080 28080 38080; then
    echo "Failed to auto-select PROXY_HTTP_PORT. Please set --http-port explicitly." >&2
    exit 1
  fi
  PROXY_HTTP_PORT="$RESOLVED_PORT"
  SELECTED_PORTS+=("$PROXY_HTTP_PORT")
fi

if [[ "$PROXY_HTTPS_PORT_EXPLICIT" == "true" ]]; then
  if ! can_bind_port "$PROXY_HTTPS_PORT"; then
    echo "Cannot bind explicit PROXY_HTTPS_PORT=$PROXY_HTTPS_PORT (requires root or CAP_NET_BIND_SERVICE)" >&2
    exit 1
  fi
  if is_selected_port "$PROXY_HTTPS_PORT"; then
    echo "PROXY_HTTPS_PORT duplicates another selected port: $PROXY_HTTPS_PORT" >&2
    exit 1
  fi
  if is_port_in_use "$PROXY_HTTPS_PORT"; then
    echo "Cannot bind explicit PROXY_HTTPS_PORT=$PROXY_HTTPS_PORT (already in use)" >&2
    exit 1
  fi
  SELECTED_PORTS+=("$PROXY_HTTPS_PORT")
else
  if ! resolve_port "PROXY_HTTPS_PORT" "false" "$PROXY_HTTPS_PORT" 8443 18443 28443 38443; then
    echo "Failed to auto-select PROXY_HTTPS_PORT. Please set --https-port explicitly." >&2
    exit 1
  fi
  PROXY_HTTPS_PORT="$RESOLVED_PORT"
  SELECTED_PORTS+=("$PROXY_HTTPS_PORT")
fi

mkdir -p ./data

export ADMIN_ADDR="0.0.0.0:${ADMIN_PORT}"
export HTTP_ADDR=":${PROXY_HTTP_PORT}"
export HTTPS_ADDR=":${PROXY_HTTPS_PORT}"
export DATA_FILE="${DATA_FILE:-./data/sites.json}"
export SETTINGS_FILE
export CERT_DATA_FILE="${CERT_DATA_FILE:-./data/certificates.json}"
export CERT_DIR="${CERT_DIR:-./data/certs}"
export ENABLE_AUTO_TLS
export LETSENCRYPT_EMAIL
export ENABLE_UI
CONFIG_FILE="$EFFECTIVE_CONFIG_FILE"
export CONFIG_FILE

echo "Starting FlowProxy..."
echo "  Admin UI/API : ${ADMIN_ADDR}"
echo "  Proxy HTTP   : ${HTTP_ADDR}"
echo "  Proxy HTTPS  : ${HTTPS_ADDR}"
echo "  Auto TLS     : ${ENABLE_AUTO_TLS}"
echo "  UI Enabled   : ${ENABLE_UI}"
if [[ -n "${CONFIG_FILE}" ]]; then
  echo "  Config File  : ${CONFIG_FILE}"
fi
if [[ ${#PORT_SOURCE_MESSAGES[@]} -gt 0 ]]; then
  echo "  Port Source  :"
  for msg in "${PORT_SOURCE_MESSAGES[@]}"; do
    echo "    - ${msg}"
  done
fi
if [[ ${#AUTO_PORT_MESSAGES[@]} -gt 0 ]]; then
  echo "  Auto Port    :"
  for msg in "${AUTO_PORT_MESSAGES[@]}"; do
    echo "    - ${msg}"
  done
fi
if [[ ${#CONFIG_OVERRIDE_MESSAGES[@]} -gt 0 ]]; then
  echo "  Config Rule  :"
  for msg in "${CONFIG_OVERRIDE_MESSAGES[@]}"; do
    echo "    - ${msg}"
  done
fi

exec go run ./cmd/flowproxy
