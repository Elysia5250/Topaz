# `topaz-coord` VPS 部署与运维指南

`topaz-coord` 是单二进制、零外部依赖（内置 SQLite、自签名 Ed25519 TLS 1.3、STUN、TCP/WSS 流中继与 UDP/QUIC 数据报中继）的协调服务器，无需域名或反向代理即可在任意 Linux VPS 上线。

## 1. 零构建一键安装（推荐，适用于 256MB+ 廉价 VPS）

GitHub Actions（`.github/workflows/release.yml`）已为每次 `v*` 发版自动构建全静态链接（`musl`）的 `topaz-coord-linux-x86_64` 与 `topaz-coord-linux-aarch64` 二进制并附带 `SHA256SUMS.txt`。在 VPS 上直接执行一行命令即可安装或升级，无需安装 Rust：

```bash
PUBLIC_IP="$(curl -4 -fsS https://ifconfig.me)"
curl -fsSL https://raw.githubusercontent.com/Elysia5250/Topaz/master/scripts/deploy-coord.sh \
  | sudo bash -s -- --public-url "https://${PUBLIC_IP}:7722"
```

> 可选参数：
> - `--version v0.2.0`：指定发布版本（默认 `latest`）
> - `--relay-quic-port 7724`：自定义 UDP/QUIC 数据报中继端口（默认 `7724`）
> - `--ws-443`：若 443 端口空闲，额外在 443 端口监听 WSS 中继（适用于仅放行 443 的严格防火墙环境）

再次运行同一条命令即可**无损升级二进制**，不会覆盖 `/etc/topaz-coord/coord.env` 与 `/var/lib/topaz-coord/coord.db`，并在安装完成后自动打印新二进制版本。

> **从 v0.1.x 升级到 v0.2.0 注意**：`v0.2.0` 升级了 `x-topaz-*` 认证请求头与 `mux=v2` 传输协议，请先更新服务端，再同步升级所有客户端；如原有 `/etc/topaz-coord/coord.env` 未包含 `COORD_RELAY_QUIC_LISTEN`，服务端默认仍自动在 `0.0.0.0:7724` 启用 UDP/QUIC 数据报中继（无需手动改 env，放行 `7724/udp` 即可）。

## 2. 备选：本地编译后上传安装

如需部署尚未发版的开发分支，可在开发机编译并上传：

```bash
cargo build --release -p topaz-coord
scp target/release/topaz-coord scripts/deploy-coord.sh root@<VPS_IP>:/tmp/
# 登录 VPS 执行：
chmod +x /tmp/deploy-coord.sh
sudo /tmp/deploy-coord.sh --binary /tmp/topaz-coord --public-url https://<VPS_IP>:7722
```

## 3. 防火墙放行端口

| 端口 | 协议 | 用途 |
| :--- | :--- | :--- |
| `7722` | TCP | HTTPS 控制面 + WSS 信令 + WSS 中继 |
| `7723` | TCP | TCP 流中继（Yamux 多路复用） |
| `7724` | UDP | UDP/QUIC 不可靠数据报中继（E2E 加密，避免中继 VPN 的 TCP-over-TCP 拥塞；未放行时自动回退 TCP/WSS） |
| `3478` | UDP | 内置 RFC 5389 STUN（NAT 打洞必需） |
| `443`（可选） | TCP | 额外 WSS 中继端口（仅启用 `--ws-443` 时需要） |

## 4. 常用运维命令

在 VPS 上执行：

```bash
# 0. 查看服务端二进制版本与运行中接口版本/端点信息
topaz-coord version
curl -kfsS https://127.0.0.1:7722/v1/version && echo ""
curl -kfsS https://127.0.0.1:7722/v1/info && echo ""

# 1. 创建一次性邀请码（并自动打印客户端单行初始化命令）
sudo -u topaz bash -c 'set -a; source /etc/topaz-coord/coord.env; topaz-coord invite create'

# 2. 查看 TLS Pin 指纹
sudo -u topaz topaz-coord --db /var/lib/topaz-coord/coord.db fingerprint

# 3. 查看各账号中继流量统计
sudo -u topaz topaz-coord --db /var/lib/topaz-coord/coord.db usage

# 4. 查看实时日志
sudo journalctl -u topaz-coord -f

# 5. 备份数据库（含服务端 TLS 密钥与账号设备表）
sudo cp /var/lib/topaz-coord/coord.db /root/coord.db.bak
```

---

## 5. 发布新版本（维护者）

推送新 tag 即自动触发 `.github/workflows/release.yml` 构建全静态 Linux `x86_64` / `aarch64` 与 macOS `aarch64` 二进制并发布到 GitHub Releases：

```bash
git tag v0.2.0
git push origin v0.2.0
```
