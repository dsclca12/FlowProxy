# FlowProxy

[English](README.md) | [简体中文](README.zh-CN.md)

FlowProxy 是一个轻量级反向代理管理器，内置 HTTP 引擎 + L4 端口转发，配备双语 Web UI。

它是 Nginx Proxy Manager 的现代替代方案——更轻、更快、更易管理，适用于低配 VPS、NAS 和家庭服务器。

## 功能特性

### 🔄 反向代理（L7）
- 主机、泛域名、路径路由
- 多上游负载均衡：`round_robin`、`weighted_round_robin`、`least_conn`、`ip_hash`、`random`
- 路由规则：prefix / exact / regex，支持路径重写
- 路由条件匹配：method、header、cookie、query 参数
- 基于路由优先级转发
- WebSocket 升级透传
- 站点级自定义入口端口（`listenPort`）
- 请求/响应头改写（set/remove），自动代理头配置
- 站点级 gzip / brotli 下游压缩
- 响应缓存：TTL、最大条目数、最大响应体、缓存键忽略参数、手动清理 API

### 🚦 L4 端口转发
- **TCP** 端口转发（SSH、MySQL、Redis、PostgreSQL 等）
- **UDP** 端口转发（DNS、NTP、Syslog 等），基于会话跟踪
- **TLS** 透传转发
- 与 HTTP 反向代理并行运行，互不冲突

### 🔒 安全与访问控制
- 站点级 Basic Auth
- IP 白名单/黑名单，支持优先级排序
- 基于国家的 IP 自动封禁（自动从 `ipdeny` 同步 CIDR）
- 站点级限流与每 IP 并发连接限制
- IP 自动封禁与自动过期
- HTTP 方法白名单与 User-Agent 屏蔽
- 内置安全响应头

### 🛡️ 上游韧性
- 主动健康检查
- 可配置重试策略与退避算法（固定 / 指数 + 抖动）
- 熔断器
- 上游 HTTPS：自定义 SNI、自定义 CA bundle、可选 `InsecureSkipVerify`
- 站点级上游超时控制

### 🚀 金丝雀发布
- 基于 header / cookie 匹配流量分发
- 按权重分流到金丝雀上游

### 📊 可观测性
- 运行时统计与持久化访问日志 API（保留策略 + 过滤）
- WebSocket 实时日志推送
- Prometheus 指标端点（`/metrics`）
- Webhook 告警：5xx 突增检测、高延迟告警

### 🔐 管理界面
- 内置双语 Web UI（英文 / 简体中文 / 正体中文）
- 可选管理端 HTTPS：自定义证书或自动自签
- HTTP 到 HTTPS 自动跳转
- CLI 重置管理员凭据

### 💾 备份与恢复
- 手动与定时 ZIP 备份，保留策略清理
- 一键下载与上传备份

### 🌐 集群 / HA
- **伪集群模式**：多实例共享控制数据，站点按 `NODE_ID` 加载
- **控制面-执行节点同步**：执行节点定时拉取控制数据，支持多地址故障切换
- **etcd 后端**：控制数据持久化到 etcd，轻量高可用

### 🔧 声明式配置
- 单 YAML 文件配置 runtime + settings + sites + certificates
- 适合 Git 管理部署和无 UI 环境

### 🧩 其他
- Let's Encrypt 自动 HTTPS（`autocert`）
- DNS-01 ACME 挑战：Cloudflare API 支持，manual 模式打印 TXT 记录
- 网卡绑定：所有监听地址支持 `interface:port` 格式（如 `eth0:80`）

## 快速开始

### Docker

```bash
cp .env.example .env
# 先在 .env 中编辑 ADMIN_USERNAME / ADMIN_PASSWORD
docker compose up -d --build
```

打开管理界面 `http://<server-ip>:9000`，使用 `.env` 中的凭据登录。

> `docker-compose.yml` 默认使用 `host` 网络模式。也可以不使用 `.env`，直接传递环境变量：
>
> ```bash
> ADMIN_PORT=19000 PROXY_HTTP_PORT=18080 PROXY_HTTPS_PORT=18443 \
>   ADMIN_USERNAME=admin ADMIN_PASSWORD='your-strong-password' \
>   docker compose up -d --build
> ```

### 本地运行

```bash
./start.sh
```

脚本会先尝试默认端口（`:9000`、`:80`、`:443`），若不可用则自动回退到开发端口（`:8080`、`:8443`）。

自定义端口：

```bash
./start.sh --admin-port 19000 --http-port 18080 --https-port 18443
```

直接运行：

```bash
go run ./cmd/flowproxy
```

### 声明式配置

```bash
CONFIG_FILE=./flowproxy.yaml go run ./cmd/flowproxy
```

或：

```bash
./start.sh --config ./flowproxy.yaml
```

完整参考见 `config/flowproxy.example.yaml`。

### 重置管理员凭据

```bash
go run ./cmd/flowproxy reset-admin --username <new-user> --password <new-password>
```

## 配置

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_ADDR` | `0.0.0.0:9000` | 管理端监听地址 |
| `ADMIN_HTTPS_ADDR` | — | 管理端 HTTPS 监听地址（可选） |
| `ADMIN_TLS_CERTIFICATE_ID` | — | 管理端 HTTPS 使用的证书 ID |
| `ADMIN_TLS_CERT_FILE` + `ADMIN_TLS_KEY_FILE` | — | 管理端 HTTPS 自定义证书/密钥 |
| `ADMIN_TLS_AUTO_SELF_SIGNED` | `true` | 自动生成自签证书 |
| `ADMIN_TLS_REDIRECT_HTTP` | `false` | HTTP 重定向到 HTTPS |
| `ADMIN_USERNAME` + `ADMIN_PASSWORD` | — | 管理员凭据（公网监听必填） |
| `ADMIN_AUTH_FILE` | `./data/admin-auth.json` | 认证数据文件 |
| `HTTP_ADDR` | `:80` | 代理 HTTP 监听地址 |
| `HTTPS_ADDR` | `:443` | 代理 HTTPS 监听地址 |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | 受信代理 CIDR |
| `DATA_FILE` | `./data/sites.json` | 站点数据文件 |
| `SETTINGS_FILE` | `./data/settings.json` | 设置数据文件 |
| `CERT_DATA_FILE` | `./data/certificates.json` | 证书数据文件 |
| `CERT_DIR` | `./data/certs` | 证书存储目录 |
| `BACKUP_DIR` | `./data/backups` | 备份目录 |
| `ACCESS_LOG_FILE` | `./data/access-logs.json` | 访问日志文件 |
| `ACCESS_LOG_MAX_ROWS` | `10000` | 访问日志最大行数 |
| `ACCESS_LOG_TTL` | `168h` | 日志保留时间，`0s` 关闭 |
| `ACCESS_LOG_FLUSH_INTERVAL` | `2s` | 日志刷盘间隔 |
| `ALERT_WEBHOOK_URL` | — | 告警 Webhook URL（可选） |
| `ALERT_CONSECUTIVE_5XX` | `10` | 连续 5xx 告警阈值 |
| `ALERT_LATENCY_MS` | `0` | 延迟告警阈值（ms），`0` 关闭 |
| `ALERT_COOLDOWN` | `5m` | 告警冷却时间 |
| `LETSENCRYPT_EMAIL` | — | Let's Encrypt 邮箱 |
| `ENABLE_AUTO_TLS` | `false` | 启用自动 HTTPS |
| `ENABLE_UI` | `true` | 启用 Web UI；`false` 仅保留 API |
| `NODE_ID` | `default` | 伪集群节点标识 |
| `NODE_NAME` | `Default Node` | 伪集群节点名称 |
| `NODE_DATA_FILE` | `./data/nodes.json` | 节点注册表文件 |
| `CLUSTER_SYNC_URL` | — | 控制面地址（必须 `https://`） |
| `CLUSTER_SYNC_URLS` | — | 逗号分隔多个控制面地址 |
| `CLUSTER_SYNC_USERNAME` | — | 控制面登录用户名 |
| `CLUSTER_SYNC_PASSWORD` | — | 控制面登录密码 |
| `CLUSTER_SYNC_INTERVAL` | `3s` | 拉取间隔 |
| `STORAGE_BACKEND` | `file` | 存储后端：`file` 或 `etcd` |
| `STORAGE_ETCD_ENDPOINTS` | — | etcd 地址（逗号分隔） |
| `STORAGE_ETCD_PREFIX` | `/flowproxy` | etcd 键前缀 |
| `STORAGE_ETCD_DIAL_TIMEOUT` | `3s` | etcd 连接超时 |
| `CONFIG_FILE` | — | YAML 配置文件路径 |

## 集群 / HA 模式

### 伪集群（文件后端）

1. 多个实例共享控制数据文件
2. 每个实例设置不同的 `NODE_ID` / `NODE_NAME`
3. 站点设置 `nodeId`，各实例仅加载匹配自己的站点

运行期文件（日志、备份）建议按节点分开存放。

### 控制面-执行节点同步

不方便使用共享文件时，可指定一台实例为控制面，其他节点定时拉取：

```
CLUSTER_SYNC_URL=https://controller:9443
CLUSTER_SYNC_USERNAME=admin
CLUSTER_SYNC_PASSWORD=your-password
CLUSTER_SYNC_INTERVAL=3s
```

执行节点上的写入接口变为只读。可配置多个控制面地址实现自动故障切换。

### etcd HA 后端

设置 `STORAGE_BACKEND=etcd` 将控制数据持久化到 etcd，运行期产物保持本地落盘。

## 声明式文件配置

所有 runtime、settings、sites、certificates 均可通过单个 YAML 文件管理。

```bash
./start.sh --config ./flowproxy.yaml
```

完整参考见 `config/flowproxy.example.yaml`。

核心行为：
- `runtime` 字段覆盖环境变量
- `settings/sites/certificates` 启动时写入对应 JSON 文件
- 省略的 section 保持现有数据，显式空列表会清空该 section
- 支持定时备份、国家 CIDR 自动更新、IP 规则优先级/冲突策略、集群同步配置

## API 参考

### 站点
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/sites` | 获取站点列表 |
| POST | `/api/sites` | 创建站点 |
| PUT | `/api/sites/:id` | 更新站点 |
| DELETE | `/api/sites/:id` | 删除站点 |
| POST | `/api/sites/:id/toggle` | 启用/禁用站点 |
| POST | `/api/sites/:id/cache/purge` | 清理站点缓存 |

### 统计与日志
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/stats` | 运行时统计 |
| GET | `/metrics` | Prometheus 指标 |
| GET | `/api/logs` | 访问日志（可过滤） |

### 证书
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/certificates` | 证书列表 |
| POST | `/api/certificates` | 创建证书 |
| POST | `/api/certificates/:id/issue` | 签发 ACME 证书 |
| GET | `/api/certificates/:id/download` | 下载证书资产 |
| DELETE | `/api/certificates/:id` | 删除证书 |

### 设置与集群
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings` | 获取设置 |
| PUT | `/api/settings` | 更新设置 |
| GET | `/api/cluster-sync` | 集群同步状态 |

### 节点
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/nodes` | 节点列表 |
| POST | `/api/nodes` | 注册节点 |
| PUT | `/api/nodes/:id` | 更新节点 |
| DELETE | `/api/nodes/:id` | 删除节点 |
| POST | `/api/nodes/:id/heartbeat` | 节点心跳 |

### 备份
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/backups` | 备份列表 |
| POST | `/api/backups` | 创建备份 |
| GET | `/api/backups/:name/download` | 下载备份 |
| POST | `/api/backups/upload` | 上传备份（multipart，字段名：`file`） |

### 认证
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/auth/login` | 登录 |
| POST | `/auth/logout` | 登出 |
| GET | `/auth/me` | 当前用户信息 |
| POST | `/auth/change-password` | 修改密码 |

## 注意事项

- 使用 Let's Encrypt 时，域名需解析到当前服务器，`80/443` 端口需可访问。
- 启用 TLS 后，HTTP 用于 ACME challenge，其余流量重定向到 HTTPS。
- 管理端监听公网时，务必配置 `ADMIN_USERNAME`/`ADMIN_PASSWORD`。
- 若公网监听且仍使用默认 `admin/admin`，FlowProxy **会拒绝启动**。
- 管理员密码长度至少 10 个字符。
- 首次启动时会记录恢复码，请妥善保存。
- 密码重置仅支持 CLI 的 `reset-admin`。

## 许可证

FlowProxy 使用 [MIT 许可证](LICENSE)。
