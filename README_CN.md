# Zorv — Rust 自研协议内网穿透

> 自研二进制帧协议 + TLS 1.3 伪装 + 单连接多路复用 + 内置 Web 管理台的 TCP/UDP 内网穿透系统。
> 服务端 `zorvd` 运行在公网服务器，客户端 `zorv` 运行在内网机器，把内网服务安全地暴露到公网。

```
                        ┌─────────────────────┐
   外网用户 ────────────▶│   服务端 zorvd      │    公网服务器
   访问 listen 端口      │  listener + tunnel  │
                        └─────────┬───────────┘
                                  │ TLS 1.3 隧道（自研帧协议，单连接多路复用）
                                  │ 认证：HMAC-SHA256 + 时间戳窗口 / IP 白名单
                        ┌─────────┴───────────┐
                        │   客户端 zorv       │    内网机器 / NAS
                        │  dialer + forwarder │
                        └─────────┬───────────┘
                                  │ 本地 TCP/UDP
                        ┌─────────┴───────────┐
                        │   内网目标服务       │    127.0.0.1:8080 等
                        └─────────────────────┘
```

## 功能特性

- **自研私有协议**：二进制帧（`MAGIC 0x5A3C` + 类型 + Stream ID + 长度 + CRC32），非 HTTP/WebSocket，无公开指纹
- **TLS 1.3 传输**：纯 Rust（rustls）实现，握手外观与普通 HTTPS 一致
- **单连接多路复用**：一条隧道承载最多 65535 条并发业务流，Stream ID 分配控制帧为 `0xFFFFFFFF`
- **TCP / UDP 代理**：同时支持端口转发与 UDP 数据报（如 DNS 转发）
- **流量混淆**：随机 padding 抹平包长分布、心跳间隔随机抖动（`[obfuscation]`）
- **多客户端**：`client_id` 路由，代理规则与具体客户端绑定
- **Web 管理台**：在线客户端/总览/设置/流量监控四个页面，移动端自适应
  - 图形验证码 + 防爆破（单 IP 连续 5 次密码错误锁定 30 分钟）
  - 应用 Token 管理（支持随机生成 / 复制）、代理规则可视化增删改（弹窗表单 + 输入校验）
  - 在线客户端列表 + 一键踢出（踢出后客户端退出）
  - 流量监控：按 `client_id` 的 TCP/UDP 上行/下行统计，**落盘持久化** + 30s 采样时序曲线（Canvas 手绘，近 100 分钟）
  - 配置热重载：编辑服务端 `zorvd.toml` 后免重启生效（token 与代理规则差异应用）
  - 审计日志：登录、token 修改、规则增删改、重载、踢出均记录
  - 管理台可选用 HTTPS（`[admin.tls]`），密码支持 PBKDF2-HMAC-SHA256 哈希存储
- **可观测性**：Prometheus `/metrics`（在线客户端/配置规则/活跃流/TCP·UDP 流量计数，免鉴权供抓取）、客户端掉线 Webhook 通知
- **健壮性**：断线指数退避自动重连、心跳超时清理、重连竞态防护（旧会话清理不会误删新会话）

## 快速开始

### 1. 构建

需要 Rust 稳定版 toolchain（edition 2024，建议最新 stable）。

```bash
cargo build --release
# 产物：
#   target/release/zorvd  服务端
#   target/release/zorv   客户端（等价 `zorv server` / `zorv client`）
```

### 2. 生成证书（首次部署）

隧道强制 TLS 1.3。测试环境可用自签证书，生产环境建议使用受信 CA 签发的证书。

```bash
# 方式一：内置生成器（自签）
cargo run --release --example gen_cert -- server.crt server.key

# 方式二：OpenSSL
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=your-server.example.com"
```

### 3. 配置服务端

```bash
cp config/zorvd.example.toml zorvd.toml
```

最小可用配置（TLS 证书 + token + 一条 TCP 代理 + 开启管理台）：

```toml
tunnel_addr = "0.0.0.0:8443"

[tls]
cert_file = "/etc/zorv/server.crt"
key_file  = "/etc/zorv/server.key"

[auth]
token = "改成一个高强度随机串"

[[proxies]]
name      = "web"
type      = "tcp"
listen    = "0.0.0.0:18080"
client_id = "home-nas"
target    = "127.0.0.1:8080"

[admin]
enabled  = true
listen   = "127.0.0.1:9000"
username = "admin"
password = "change-me"          # 可先填明文，登录后建议换成哈希

[log]
level  = "info"
output = "./app.log"            # "stdout" 仅输出到控制台，或填任意文件路径
```

> 管理员密码哈希：`zorvd hash-password <明文>`，把输出（`$pbkdf2-sha256$...`）填入 `admin.password`。
> 除 `[[proxies]]` 外，代理规则也可以在 Web 管理台「设置」页动态增删改，无需写配置文件。

### 4. 配置客户端

```bash
cp config/zorv.example.toml zorv.toml
```

```toml
client_id   = "home-nas"                       # 必须与服务端代理规则的 client_id 一致
server_addr = "your-server.example.com:8443"

[auth]
token = "与服务端一致的 token"

[tls]
verify_cert = true                             # 自签证书可先设 false 测试
# ca_file = "/etc/zorv/ca.crt"                 # 自签 CA 场景：把服务端证书当 CA 导入

[reconnect]
initial_delay  = "2s"
max_delay      = "60s"
backoff_factor = 2.0
max_retries    = 0                             # 0 = 无限重连
```

> 客户端**无需**声明转发目标：目标（内部连接中转）在服务端管理台配置，服务端通过 `STREAM_OPEN` 帧下发，客户端据此连接本地目标。

### 5. 启动与验证

```bash
# 服务端
./target/release/zorvd --config zorvd.toml
# 或等价：./target/release/zorv server -c zorvd.toml

# 客户端
./target/release/zorv client -c zorv.toml

# 验证：访问服务端公网端口
curl http://your-server.example.com:18080/
ssh -p 12222 user@your-server.example.com
```

浏览器打开 `http://127.0.0.1:9000/` 进入管理台（服务器上如无法直接访问，用 `ssh -L 9000:127.0.0.1:9000 user@server` 转发）。

## 部署（服务化）

### Linux / systemd

仓库已提供加固过的服务单元 [deploy/zorvd.service](deploy/zorvd.service)，完整步骤见 [deploy/README.md](deploy/README.md)。摘要：

```bash
sudo useradd --system --home /var/lib/zorv --create-home --shell /usr/sbin/nologin zorv
sudo install -m 755 target/release/zorvd /usr/local/bin/zorvd
sudo mkdir -p /etc/zorv
sudo cp config/zorvd.example.toml /etc/zorv/zorvd.toml   # 编辑：token、证书、data_dir = "/var/lib/zorv"
sudo cp server.crt server.key /etc/zorv/
sudo cp deploy/zorvd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zorvd
journalctl -u zorvd -f
```

客户端同理注册为 systemd 服务（`ExecStart=/usr/local/bin/zorv client -c /etc/zorv/zorv.toml`）。

### Docker

仓库提供多阶段构建 [deploy/Dockerfile](deploy/Dockerfile)（构建阶段 `rust:1-bookworm`，运行阶段 `debian:bookworm-slim`，内置自签证书与默认配置）：

```bash
docker build -f deploy/Dockerfile -t zorvd:latest .
docker run -d --name zorvd --restart unless-stopped \
  -p 8443:8443 -p 9000:9000 \
  -v /srv/zorv/config:/etc/zorv \
  -v /srv/zorv/data:/var/lib/zorv \
  zorvd:latest
```

代理端口按需追加 `-p <port>:<port>` 映射。生产环境务必挂载自己的配置与证书（镜像内为自签测试证书）。

### Windows 服务

用 [NSSM](https://nssm.cc) 包装，仓库提供一键脚本 [deploy/zorvd-windows-service.ps1](deploy/zorvd-windows-service.ps1)：

```powershell
cargo build --release --bin zorvd
# 安装 NSSM 并加入 PATH 后，管理员 PowerShell：
powershell -ExecutionPolicy Bypass -File deploy\zorvd-windows-service.ps1
```

## 配置参考

### 服务端 `zorvd.toml`

| 段 | 字段 | 说明 |
| --- | --- | --- |
| 顶层 | `tunnel_addr` | 隧道监听地址，客户端拨号连接 |
| 顶层 | `data_dir` | 持久化目录（流量统计落盘等），默认 `data` |
| `[tls]` | `cert_file` / `key_file` | PEM 证书与私钥，隧道强制 TLS 1.3 |
| `[auth]` | `token` | 与客户端共享的预共享 token |
| `[auth]` | `allowed_ips` | 可选客户端 IP 白名单（精确 IP / IPv4 CIDR） |
| `[[proxies]]` | `name` / `type` / `listen` / `client_id` / `target` | 代理规则：外网 `listen` 端口经隧道转发到该 `client_id` 客户端的 `target`；`type` 支持 `tcp` / `udp` |
| `[performance]` | `max_streams_per_tunnel` / `stream_buffer_size` / `recv_buffer_size` | 并发流与缓冲区上限 |
| `[obfuscation]` | `padding` / `padding_max` | 帧随机填充开关与上限 |
| `[admin]` | `enabled` / `listen` / `username` / `password` | Web 管理台；`password` 支持明文或 PBKDF2 哈希（`zorvd hash-password` 生成） |
| `[admin.tls]` | `cert_file` / `key_file` | 可选，管理台 HTTPS |
| `[notify]` | `webhook` | 可选，客户端掉线时 POST JSON 通知 |
| `[log]` | `level` / `output` | 日志级别与输出（`"stdout"` 或文件路径） |

### 客户端 `zorv.toml`

| 段 | 字段 | 说明 |
| --- | --- | --- |
| 顶层 | `client_id` | 客户端唯一标识，与服务端规则绑定 |
| 顶层 | `server_addr` | 服务端隧道地址 `host:port` |
| `[auth]` | `token` | 与服务端一致的共享 token |
| `[tls]` | `verify_cert` / `ca_file` | 证书校验开关与自定义 CA |
| `[reconnect]` | `initial_delay` / `max_delay` / `backoff_factor` / `max_retries` | 指数退避重连策略 |
| `[obfuscation]` | `padding` / `padding_max` / `heartbeat_jitter` | 流量混淆 |
| `[log]` | `level` / `output` | 日志 |

## 监控与告警

- **Prometheus**：`GET /metrics` 免鉴权输出文本格式指标，含：
  - `zorv_online_clients`、`zorv_configured_proxies`、`zorv_active_streams`（gauge）
  - `zorv_traffic_{tcp,udp}_{up,down}_bytes_total{client_id="..."}`（counter）
- **流量历史 API**：`GET /api/traffic/history` 返回 30s 采样的时序历史（近 100 分钟，内存环形缓冲），管理台曲线图即用此数据
- **掉线 Webhook**：`[notify] webhook` 配置后，客户端会话结束时 POST JSON `{"event":"offline","client_id":"..."}`

## 安全说明

- 握手认证：HMAC-SHA256 + 毫秒时间戳 ±30s 窗口，防重放；可选 `allowed_ips` IP 白名单
- 管理台：图形验证码、单 IP 防爆破锁定、`SameSite=Lax` Cookie、`data-*` 属性 + 事件委托防 XSS、审计日志、密码 PBKDF2-HMAC-SHA256 存储、可选 HTTPS
- 部署建议：服务端最小化开放端口；隧道端口建议防火墙仅放行客户端 IP；token 定期轮换；管理台默认只监听本机，远程访问请走反向代理或 SSH 转发
- 合规声明：请仅用于自有服务器、家庭实验室、授权测试环境；在企业/未经授权的网络部署反向隧道可能违反安全政策与法规

## 开发与测试

```bash
cargo test --lib                    # 单元测试（协议/认证/管理台 API/流量/重连竞态等）
cargo test                          # 含端到端集成测试（TCP/UDP 转发、客户端断线重连）
cargo run --release --example fuzz_protocol -- --iters 100000   # 确定性协议 fuzz（崩溃会打印复现 seed）
cargo run --release --example smoke # 冒烟演示
```

主要目录：

```
src/
├── main.rs             # zorv 入口（server/client 子命令）
├── bin/server.rs       # zorvd 入口（hash-password 子命令）
├── server/             # 服务端：隧道、代理监听、会话管理、管理台 API、审计、metrics、热重载
├── client/             # 客户端：拨号重连、流量转发、UDP 会话
├── protocol/           # 帧编解码、握手、fuzz 工具
└── common/             # 配置、TLS、日志、错误
html/                   # 管理台页面（include_str! 内嵌，改动需重新编译）
config/                 # 服务端/客户端示例配置
deploy/                 # systemd 单元、Dockerfile、Windows 服务脚本、部署说明
examples/               # gen_cert / smoke / fuzz_protocol
tests/                  # 端到端集成测试、协议测试
```

## License

MIT
