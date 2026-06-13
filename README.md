# FlowProxy

[English](README.md) | [简体中文](README.zh-CN.md)

FlowProxy is a lightweight, single-node reverse proxy manager with a built-in HTTP engine, L4 port forwarding, and a bilingual web UI.

It is designed as a modern alternative to Nginx Proxy Manager — lighter, faster, and easier to manage — suitable for low-spec VPS, NAS devices, and home servers.

## Features

### 🔄 Reverse Proxy (L7)
- Host, wildcard domain, and path-based routing
- Multi-upstream load balancing: `round_robin`, `weighted_round_robin`, `least_conn`, `ip_hash`, `random`
- Route rules: prefix / exact / regex, with optional path rewrite
- Route condition matching: method, header, cookie, query parameters
- Route-priority based forwarding
- WebSocket upgrade passthrough
- Site-level custom entry listen port (`listenPort`)
- Request/response header transform (set/remove), auto-proxy-headers
- Site-level gzip / brotli compression for downstream responses
- Response cache with TTL, max entries, max body size, cache-key ignore params, manual purge API

### 🚦 L4 Port Forwarding
- **TCP** port forwarding (SSH, MySQL, Redis, PostgreSQL, etc.)
- **UDP** port forwarding (DNS, NTP, Syslog, etc.) with session tracking
- **TLS** passthrough forwarding
- Runs in parallel with HTTP reverse proxy, no conflict

### 🔒 Security & Access Control
- Basic Authentication per site
- IP allow/deny lists with configurable priority order
- Country-based IP auto-block (auto-updates CIDR from `ipdeny`)
- Per-site rate limiting and per-IP concurrent connection limit
- IP auto-block with auto-expiry
- HTTP method allowlist and User-Agent block rules
- Built-in security response headers

### 🛡️ Upstream Resilience
- Active health checks
- Configurable retry policy with backoff (fixed / exponential + jitter)
- Circuit breaker
- Upstream HTTPS: custom SNI, custom CA bundle, optional `InsecureSkipVerify`
- Upstream timeout controls per site

### 🚀 Canary Release
- Header / cookie match based canary routing
- Weighted canary upstream distribution

### 📊 Observability
- Runtime statistics and persistent access log APIs (retention & filter support)
- Real-time log push via WebSocket
- Prometheus metrics endpoint (`/metrics`)
- Webhook alerting: 5xx burst detection, high latency alerts

### 🔐 Admin Interface
- Built-in bilingual web UI (English / Chinese)
- Optional admin HTTPS listener: custom cert/key or auto self-signed
- Admin TLS with HTTP-to-HTTPS redirect
- CLI-based admin credential reset

### 💾 Backup & Recovery
- On-demand and scheduled ZIP backups with retention cleanup
- One-click backup download and upload

### 🌐 Cluster / HA
- **Pseudo-cluster mode**: multiple instances share control data; sites bind to nodes; each instance loads only its own `NODE_ID`
- **Controller-Follower sync**: pull-based control plane sync, follower failover across multiple controller endpoints
- **etcd backend**: lightweight HA for control data (`sites/settings/nodes/certificates`)

### 🔧 Declarative Config
- Single YAML file for runtime + settings + sites + certificates
- Suitable for git-managed deployments and headless environments

### 🧩 Additional
- Automatic HTTPS with Let's Encrypt (`autocert`)
- DNS-01 ACME challenge: Cloudflare API support, manual mode with TXT record display
- NIC binding: all listeners support `interface:port` format (e.g. `eth0:80`)

## Quick Start

### Docker

```bash
cp .env.example .env
# Edit ADMIN_USERNAME / ADMIN_PASSWORD in .env first
docker compose up -d --build
```

Open the admin UI at `http://<server-ip>:9000` and log in with the credentials from your `.env`.

> `docker-compose.yml` uses `host` networking by default. You can also run without `.env` by passing variables inline:
>
> ```bash
> ADMIN_PORT=19000 PROXY_HTTP_PORT=18080 PROXY_HTTPS_PORT=18443 \
>   ADMIN_USERNAME=admin ADMIN_PASSWORD='your-strong-password' \
>   docker compose up -d --build
> ```

### Local

```bash
./start.sh
```

The script automatically tries default ports (`:9000`, `:80`, `:443`) and falls back to development ports (`:8080`, `:8443`) if the defaults are unavailable.

Custom ports:

```bash
./start.sh --admin-port 19000 --http-port 18080 --https-port 18443
```

Direct run:

```bash
go run ./cmd/flowproxy
```

### Declarative Config

```bash
CONFIG_FILE=./flowproxy.yaml go run ./cmd/flowproxy
```

Or via the start script:

```bash
./start.sh --config ./flowproxy.yaml
```

See `config/flowproxy.example.yaml` for the full reference.

### Reset Admin Credentials

```bash
go run ./cmd/flowproxy reset-admin --username <new-user> --password <new-password>
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_ADDR` | `0.0.0.0:9000` | Admin UI/API listen address |
| `ADMIN_HTTPS_ADDR` | — | Admin HTTPS listen address (optional) |
| `ADMIN_TLS_CERTIFICATE_ID` | — | Active certificate ID for admin HTTPS |
| `ADMIN_TLS_CERT_FILE` + `ADMIN_TLS_KEY_FILE` | — | Custom cert/key for admin HTTPS |
| `ADMIN_TLS_AUTO_SELF_SIGNED` | `true` | Auto-generate self-signed cert for admin HTTPS |
| `ADMIN_TLS_REDIRECT_HTTP` | `false` | Redirect admin HTTP to HTTPS |
| `ADMIN_USERNAME` + `ADMIN_PASSWORD` | — | Admin credentials (required for public listeners) |
| `ADMIN_AUTH_FILE` | `./data/admin-auth.json` | Admin auth data file |
| `HTTP_ADDR` | `:80` | Proxy HTTP listen address |
| `HTTPS_ADDR` | `:443` | Proxy HTTPS listen address |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | Trusted proxy CIDRs for `X-Forwarded-*` |
| `DATA_FILE` | `./data/sites.json` | Sites data file |
| `SETTINGS_FILE` | `./data/settings.json` | Settings data file |
| `CERT_DATA_FILE` | `./data/certificates.json` | Certificate data file |
| `CERT_DIR` | `./data/certs` | Certificate storage directory |
| `BACKUP_DIR` | `./data/backups` | Backup directory |
| `ACCESS_LOG_FILE` | `./data/access-logs.json` | Access log file |
| `ACCESS_LOG_MAX_ROWS` | `10000` | Max access log rows |
| `ACCESS_LOG_TTL` | `168h` | Access log retention; `0s` disables time-based pruning |
| `ACCESS_LOG_FLUSH_INTERVAL` | `2s` | Log flush interval |
| `ALERT_WEBHOOK_URL` | — | Webhook URL for alerting (optional) |
| `ALERT_CONSECUTIVE_5XX` | `10` | Consecutive 5xx threshold |
| `ALERT_LATENCY_MS` | `0` | Latency alert threshold (ms); `0` disables |
| `ALERT_COOLDOWN` | `5m` | Alert cooldown duration |
| `LETSENCRYPT_EMAIL` | — | Let's Encrypt email (optional) |
| `ENABLE_AUTO_TLS` | `false` | Enable automatic HTTPS via Let's Encrypt |
| `ENABLE_UI` | `true` | Enable built-in web UI; `false` keeps API only |
| `NODE_ID` | `default` | Pseudo-cluster node identifier |
| `NODE_NAME` | `Default Node` | Pseudo-cluster node display name |
| `NODE_DATA_FILE` | `./data/nodes.json` | Node registry file |
| `CLUSTER_SYNC_URL` | — | Controller URL for follower sync (must use `https://`) |
| `CLUSTER_SYNC_URLS` | — | Comma-separated controller URLs for failover |
| `CLUSTER_SYNC_USERNAME` | — | Controller login username |
| `CLUSTER_SYNC_PASSWORD` | — | Controller login password |
| `CLUSTER_SYNC_INTERVAL` | `3s` | Controller pull interval |
| `STORAGE_BACKEND` | `file` | Storage backend: `file` or `etcd` |
| `STORAGE_ETCD_ENDPOINTS` | — | etcd endpoints (comma-separated) |
| `STORAGE_ETCD_PREFIX` | `/flowproxy` | etcd key prefix |
| `STORAGE_ETCD_DIAL_TIMEOUT` | `3s` | etcd dial timeout |
| `CONFIG_FILE` | — | Path to YAML config file; auto-loads `./flowproxy.yaml` if present |

> 💡 When `ENABLE_AUTO_TLS=true` and `HTTPS_ADDR` is a non-default port (e.g. `:8443`), HTTP requests are redirected to that HTTPS port.

## Cluster / HA Modes

### Pseudo-Cluster (File Backend)

1. Run multiple FlowProxy instances against the same control data files.
2. Give each instance a distinct `NODE_ID` / `NODE_NAME`.
3. Assign `nodeId` on each site. Every instance loads only sites matching its own ID.

Keep runtime files (logs, backups) separated per node.

### Controller-Follower Sync

When shared storage is unavailable, designate one instance as the controller and configure followers to pull control data periodically:

```
CLUSTER_SYNC_URL=https://controller:9443
CLUSTER_SYNC_USERNAME=admin
CLUSTER_SYNC_PASSWORD=your-password
CLUSTER_SYNC_INTERVAL=3s
```

Follower sites/settings/nodes/certificates write APIs become read-only. Multiple controller URLs can be configured for automatic failover.

### etcd HA Backend

Set `STORAGE_BACKEND=etcd` to persist control data in etcd while runtime artifacts stay local.

## Declarative File Config

All runtime settings, sites, and certificates can be defined in a single YAML file — no UI needed.

```bash
./start.sh --config ./flowproxy.yaml
```

See `config/flowproxy.example.yaml` for a complete reference.

Key behaviors:
- `runtime` fields override environment variables
- `settings/sites/certificates` are written to data JSON files at startup
- Omitted sections leave existing data unchanged; explicit empty lists clear them
- Supports scheduled backup, country CIDR auto-updates, IP rule priority/conflict policies, and cluster sync settings

## API Reference

### Sites
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sites` | List all sites |
| POST | `/api/sites` | Create a site |
| PUT | `/api/sites/:id` | Update a site |
| DELETE | `/api/sites/:id` | Delete a site |
| POST | `/api/sites/:id/toggle` | Enable/disable a site |
| POST | `/api/sites/:id/cache/purge` | Purge site cache |

### Stats & Logs
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stats` | Runtime statistics |
| GET | `/metrics` | Prometheus metrics |
| GET | `/api/logs` | Access logs (filterable) |

### Certificates
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/certificates` | List certificates |
| POST | `/api/certificates` | Create a certificate |
| POST | `/api/certificates/:id/issue` | Issue ACME certificate |
| GET | `/api/certificates/:id/download` | Download certificate assets |
| DELETE | `/api/certificates/:id` | Delete a certificate |

### Settings & Cluster
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings` | Get settings |
| PUT | `/api/settings` | Update settings |
| GET | `/api/cluster-sync` | Get cluster sync status |

### Nodes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/nodes` | List nodes |
| POST | `/api/nodes` | Register a node |
| PUT | `/api/nodes/:id` | Update a node |
| DELETE | `/api/nodes/:id` | Delete a node |
| POST | `/api/nodes/:id/heartbeat` | Node heartbeat |

### Backups
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/backups` | List backups |
| POST | `/api/backups` | Create a backup |
| GET | `/api/backups/:name/download` | Download a backup |
| POST | `/api/backups/upload` | Upload a backup (multipart, field: `file`) |

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Log in |
| POST | `/auth/logout` | Log out |
| GET | `/auth/me` | Current user info |
| POST | `/auth/change-password` | Change password |

## Notes

- Let's Encrypt requires DNS resolution to this server and port `80/443` reachability.
- When TLS is enabled, HTTP serves ACME challenges; other traffic is redirected to HTTPS.
- If admin listens on a public address, configure `ADMIN_USERNAME`/`ADMIN_PASSWORD` or restrict with `webAccess.allowCidrs`.
- FlowProxy **rejects startup** when admin listens publicly with default `admin/admin` credentials.
- Admin passwords must be at least 10 characters.
- On first startup, an admin recovery code is logged. Store it securely.
- Password/account reset is CLI-only via `reset-admin`.

## License

FlowProxy is released under the [MIT License](LICENSE).
