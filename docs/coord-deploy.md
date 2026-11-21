# `topaz-coord` VPS 部署与运维指南

`topaz-coord` 是单二进制、零外部依赖（内置 SQLite、自签名 Ed25519 TLS 1.3、STUN 与 TCP/WSS Relay）的协调服务器，无需域名或反向代理即可在任意 Linux VPS 上线。

## 1. 构建二进制

在你的开发机（或直接在 VPS 上）编译 release 二进制：

```bash
cargo build --release -p topaz-coord
# 产物位置: target/release/topaz-coord
```

如果本地是 x86_64 Linux 且 VPS 也是同架构 Linux，直接上传 `target/release/topaz-coord` 与 `scripts/deploy-coord.sh` 即可：

```bash
scp target/release/topaz-coord scripts/deploy-coord.sh root@<VPS_IP>:/tmp/
```

## 2. 一键安装 / 升级

登录 VPS 执行：

```bash
chmod +x /tmp/deploy-coord.sh
sudo /tmp/deploy-coord.sh \
  --binary /tmp/topaz-coord \
  --public-url https://<VPS_IP>:7722
```

> 可选：如果客户端处于严格防火墙环境（只放行 443 端口），且 VPS 的 443 端口未被占用，可加 `--ws-443` 参数同时在 443 端口提供 WSS 中继。

再次运行同一条命令即可**无损升级二进制**，不会覆盖 `/etc/topaz-coord/coord.env` 与 `/var/lib/topaz-coord/coord.db`。

## 3. 防火墙放行端口

| 端口 | 协议 | 用途 |
| :--- | :--- | :--- |
| `7722` | TCP | HTTPS 控制面 + WSS 信令 + WSS 中继 |
| `7723` | TCP | TCP 中继（直连与打洞失败时的首选高速回退） |
| `3478` | UDP | 内置 RFC 5389 STUN（NAT 打洞必需） |
| `443`（可选） | TCP | 额外 WSS 中继端口（仅启用 `--ws-443` 时需要） |

## 4. 常用运维命令

在 VPS 上执行：

```bash
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
