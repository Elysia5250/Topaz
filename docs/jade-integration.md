# Topaz ↔ Jade 运行时联动与集成契约（v2）

> 本文档定义 **独立 VPN 网络底座 `topaz`** 与 **独立 Agent 产品 `jade`** 之间的运行时通信契约。
>
> **核心原则**：
> 1. **零编译期耦合**：`topaz` 与 `jade` 各自作为独立项目演进，Workspace 之间**没有任何 Cargo 依赖**。
> 2. **单一网络守护进程**：由 `topaz run` 独占管理设备密钥、QUIC/Relay 组网、TUN 虚拟网卡（`100.64.0.0/10`）、本地域名解析（`*.topaz`）与本地控制套接字 `~/.topaz/control.sock`。
> 3. **双通道互补**：`jade` 同时支持 **通过 `control.sock` 进行服务流桥接（`service_id = 16`，无 TUN 也可用且自带 mTLS 身份）** 与 **通过虚拟 IP / 短域名进行 L3 直连（需开启 TUN）**。

---

## 1. 为什么不再使用旧版 `jade/bridge`

旧版 `jade/bridge` 通过 Cargo path 依赖引入 `topaz-*` crate，并在独立进程内启动第二个 `topaz_fabric::Engine`。在 `topaz` 转为独立 VPN 产品后，这种做法存在根本冲突：

- `topaz run` 已经通过 `~/.topaz/control.sock` 实行数据目录单实例锁，并独占管理 QUIC 端口与 TUN 网卡；
- 如果再启动 `jade-bridge`，会与 `topaz run` 争抢设备身份、重复向 `coord` 注册端点，且无法共享同一个 mesh 会话与虚拟网卡。

因此，新的集成方式改为 **`jade` 直接在运行时连接 `topaz run` 暴露的 `~/.topaz/control.sock`**（Unix Domain Socket）。旧 `jade/bridge/` 可在迁移完成后下线或归档。

---

## 2. 路径与权限约定（Linux / macOS）

| 项目 | 约定值 | 说明 |
| :--- | :--- | :--- |
| 控制套接字默认路径 | `$TOPAZ_DATA_DIR/control.sock`，否则 `$HOME/.topaz/control.sock` | 稳定契约；`topaz socket-path` 直接打印该路径，客户端也可用 `--topaz-socket <PATH>` / `TOPAZ_CONTROL_SOCK` 覆盖 |
| 跨权限访问 | `topaz run` 若以 `sudo` 启动 TUN，会将 `control.sock` 属主/权限保持为原用户可读写（`0660`） | `jade serve` 与 `jade` CLI 始终以普通用户运行，无需 root |
| 注册服务号 | `AGENT_SERVICE_ID = 16` | `topaz` 保留 `1..=15` 给核心能力，`16..=1023` 为注册应用服务段 |
| 传输层协议 | Unix Domain Socket 上的 **HTTP/1.1 + JSON** 与 **WebSocket（RFC 6455）** | 复用标准 HTTP/WS 协议，无自定义二进制信封 |

---

## 3. 节点发现与实时事件（`jade` 与 `topaz tui` 共用）

### 3.1 `GET /v1/status`
返回当前本机与活跃对端状态快照（含虚拟 IP 与已挂接本地服务摘要）：

```json
{
  "account": "acct_...",
  "device_id": "3fa9c1d2e4b56789",
  "device_name": "workstation",
  "dns_name": "workstation",
  "virtual_ip": "100.64.0.1",
  "tun": {
    "enabled": true,
    "interface": "tun0",
    "cidr": "100.64.0.0/10"
  },
  "connection": "direct",
  "peers": [
    {
      "device_id": "91ff0e2c88aabb11",
      "name": "laptop",
      "dns_name": "laptop",
      "virtual_ip": "100.64.0.2",
      "path": "direct",
      "rtt_ms": 14,
      "services": [
        {
          "service_id": 16,
          "name": "jade"
        }
      ]
    }
  ],
  "services": [
    {
      "service_id": 16,
      "name": "jade",
      "online": true,
      "listeners": 2
    }
  ]
}
```

> 字段兼容性：
> - `dns_name`、`virtual_ip` 在尚未分配或离线/旧数据时可能为 `null`；`tun` 在 `--no-tun` 模式下 `enabled` 为 `false`。
> - `peers[].services` 为对端通过 `topaz` 核心发现通道（`service::DISCOVERY = 4`）实时通告的**远端在线插件列表**（对端离线或未挂接任何插件时为 `[]`；旧版本节点兼容缺省为 `[]`）。主控 Agent 可据此直接区分“只开 VPN 的纯组网节点”与“已挂接 `jade`（`service_id = 16`）的可调度节点”。

### 3.2 `GET /v1/devices`
返回账号下全部已验证证书设备（含离线/已吊销设备）：

```json
{
  "account": "acct_...",
  "devices": [
    {
      "device_id": "3fa9c1d2e4b56789",
      "name": "workstation",
      "dns_name": "workstation",
      "virtual_ip": "100.64.0.1",
      "status": "active",
      "issuer": "recovery code",
      "me": true
    },
    {
      "device_id": "91ff0e2c88aabb11",
      "name": "laptop",
      "dns_name": "laptop",
      "virtual_ip": "100.64.0.2",
      "status": "active",
      "issuer": "3fa9c1d2e4b56789",
      "me": false
    }
  ]
}
```

### 3.3 `GET /v1/events`（WebSocket 实时推送）
- 客户端通过 `control.sock` 升级到 WebSocket；
- 连接成功后**立即收到一条初始快照**，之后每当节点列表、直连/中继状态、RTT、虚拟 IP 或本地服务注册状态（包括 `services[].listeners` / `online` 增减）变化时立即收到推送帧（`Message::Text` JSON）：

```json
{
  "type": "status",
  "status": { /* 与 GET /v1/status 相同的 JSON 对象 */ }
}
```

---

## 4. 方式一：`control.sock` Service 流桥接（`service_id = 16`，推荐默认）

即使未启动 TUN（如 `--no-tun`、容器内或无 root 权限），`jade` 也可以通过 `control.sock` 的 WebSocket 桥接复用 `topaz` 的 QUIC/Relay 多路复用流，并由 `topaz` 直接用 **mTLS 证书**担保对端 `device_id`。

`jade` 只需封装一个极小的 `WsByteStream`（将 WebSocket `Message::Binary` 适配为 `AsyncRead + AsyncWrite + Unpin + Send`；drop / `poll_shutdown` 时发送 WS `Close`，`topaz` 侧随即半闭底层 `Channel`）。

### 4.1 出站开流（Client / `AgentDialer` 侧）

- **请求**：`GET /v1/services/16/open/{target}`（WebSocket Upgrade）
- **`{target}` 解析优先级（由 `topaz` 在当前 `active` 设备中匹配，不含本机）**：
  1. 精确匹配 `device_id`
  2. 精确匹配 `dns_name`（忽略大小写，允许带或不带 `.topaz` 后缀）
  3. 精确匹配 `virtual_ip`（如 `100.64.0.2`）
  4. 唯一匹配 `DeviceCert.name`（忽略大小写）
- **升级失败（非 `101` HTTP 错误响应约定）**：
  - 所有非 `101` 错误响应**保证**携带 `Content-Type: application/json` 与显式 `Content-Length` 响应头（不使用无 body 响应，也不使用 chunked 编码），响应体为 `{"error": "...", "code": "..."}`：`code` 稳定、供客户端分支处理，`error` 只用于展示。
  - `400 invalid_service`：非法 `service_id`（`0` 或核心保留段 `1..=15`）
  - `400 empty_target`：目标为空
  - `404 device_not_found`：找不到该目标设备（或已被吊销）
  - `409 ambiguous_target`：设备名不唯一，需改用 `device_id` 或 `dns_name`
  - `503 peer_offline`：无活跃会话、拨号失败或开流超时
  - `503 service_not_registered`：对端在线、且**已发送过 DISCOVERY**，但其通告列表没有该 `service_id`（例如纯 VPN 节点）
- **前置拒绝的边界**：`service_not_registered` 只在“已有活跃会话 + 收到过对端 DISCOVERY”时给出。旧版本对端从不发送发现帧，不能被误拒；无活跃会话时不前置拒绝，仍交给 `EngineHandle::open` 按需拨号，失败映射为 `peer_offline`。
- **升级成功（`101 Switching Protocols`）**：
  - 响应头附带：`X-Topaz-Peer-Id`、`X-Topaz-Peer-Name`、以及可选的 `X-Topaz-Peer-Ip`；
  - 升级后即为**纯净的全双工透明字节流**，双向透传 `jade-proto` v2 帧（`Op` / `Reply` / `ClientMsg`），无需任何前缀帧。

### 4.2 入站接单（`jade serve` 侧 — Accept Pool 模型）

- **请求**：`GET /v1/services/16/accept?name=jade`（WebSocket Upgrade）
- **注册 ≠ 空闲容量**：`services[].online` 表示“已注册”，`services[].listeners` 只表示当前空闲连接数。两者分离后，`/v1/events` 与 `peers[].services` 不会因为并发高峰而抖动。
- **宽限期（20 秒）**：最后一个空闲连接被交接消耗后，注册与对端通告继续保留 `DRAIN_GRACE = 20s`，给 `jade` 补池的时间；宽限期内仍无连接才真正下线。
- **有界等待（2 秒）**：宽限期内到达的入站流会暂存在每服务最多 32 条的队列里等新连接，最多等 `PENDING_WAIT = 2s`，超时才关闭。并发突刺不再被静默丢弃。
- **断开立即下线**：`/accept` WebSocket 断开（进程退出、崩溃、TOPAZ 重启）会立刻撤销注册与通告，不享受宽限期，避免把流量调度到已死的节点。
- **推荐池大小**：`jade serve` 维持 **2~4 条**空闲等待连接（类似 `accept` 队列），断线后按指数退避自动重连；每当一条连接被分配给入站流，立刻补充一条新的连接。
- **交接协议（非常关键）**：
  1. 当远端设备向本机发起 `service_id = 16` 的流时，`topaz` 从空闲池取出一条 `/v1/services/16/accept` WebSocket 连接；
  2. `topaz` 发送**唯一一帧 `Message::Text`** 作为调用方身份交接元数据：
     ```json
     {
       "event": "accepted",
       "service_id": 16,
       "peer_device_id": "3fa9c1d2e4b56789",
       "peer_name": "workstation",
       "peer_dns_name": "workstation",
       "peer_virtual_ip": "100.64.0.1",
       "connection": "direct"
     }
     ```
  3. 从**下一帧开始**，该 WebSocket 连接进入**纯净全双工二进制透传模式**，直接桥接对端的 `topaz_net::Channel`；
  4. `jade serve` 收到 `Message::Text` 解析出 `peer_device_id`（由 `topaz` mTLS 严格认证，不可伪造）后，包装剩余二进制流为 `WsByteStream`，`tokio::spawn(agent_server.serve_stream(&peer_device_id, stream))` 并立刻补齐 accept 池。
- **异常处理**：如果远端开流时本地没有空闲连接，`topaz` 会在宽限期内最多等待 2 秒；等不到才关闭该入站 `Channel`（不阻塞网元循环，远端最终收到 EOF）。

```text
jade --on laptop                 topaz (local)              topaz (laptop)             jade serve (laptop)
      │                                 │                             │                             │
      │                                 │                             │◀── WS /v1/services/16/accept (空闲等待)
      │── WS /v1/services/16/open/laptop│                             │                             │
      │                                 │── EngineHandle::open(16) ──▶│                             │
      │◀─ 101 Switching Protocols ──────│                             │── Text {"event":"accepted", │
      │                                 │                             │         "peer_device_id"} ─▶│
      │                                 │                             │                             │── tokio::spawn(serve_stream)
      │◀══════ Binary <-> Channel ═════▶│◀═════ QUIC / Relay ════════▶│◀═════ Binary <-> Channel ══▶│
```

---

## 5. L3 虚拟内网（TUN + `*.topaz`）——不属于 Agent 契约

`100.64.0.0/10` 与 `*.topaz` 的定位是让**用户自己的工具**（ssh、curl、数据库、浏览器、opal 同步）像局域网服务一样互通。

**Agent 通信只走 `control.sock` 的 WebSocket 桥（`service_id = 16`）**，不使用 L3：

1. **身份绑定等级不同**：WS 桥的 `peer_device_id` 是随每条流、由 mTLS 会话同步认证的身份；L3 只能依赖 TUN 源 IP 防伪 + 应用侧缓存反查，是旁路映射，授权关键路径上多一次可竞态的一致性假设。
2. **可用性**：WS 桥在 `--no-tun`、容器内、无 sudo/root 环境都能用，只有一条代码路径、一种失败模式。
3. **启动时序**：`jade serve` 启动时 VIP 可能尚未分配或刚变更，绑定 `<self_virtual_ip>:<port>` 并不总是可行。

因此 `jade` **不实现** `--listen-vpn`，也不对 Agent RPC 做 `peer_addr().ip() -> device_id` 反查。`/v1/devices`、`/v1/status` 中的 `virtual_ip` 只用于用户工具寻址与展示。

---

## 6. `jade` 远端工具链插件架构：并发模型与同机共生设计（#4 架构约定）

面向“**主控端跑单个 AI Agent，同时操纵多台机器**”的定位，远端机器不需要运行完整 LLM/推理循环，也**不应把工具执行塞进 `topaz` 进程**（`topaz run` 开启 TUN 时可能以 `sudo`/`CAP_NET_ADMIN` 运行，而工作区命令/文件操作必须限制在普通用户权限内）。

### 6.1 一机单实例双入口共生模型（解决“被控机也装了 `jade`”）

不拆出互不相干的第二个后台 daemon，而是在每台跑 `jade` 的机器上维持**唯一一个常驻后台 `jade serve`**，同时对外暴露两个入口并共享同一份状态：

```text
                      ┌─── 本地入口：~/.jade/jade.sock （供本机 jade ui / mcp / cli 使用）
唯一后台：jade serve ─┤
                      └─── 远程入口：topaz /v1/services/16/accept （供主控 Agent 跨机调度）
                             │
                             ▼
                  共享同一个 AgentServer + Allowlist + Job 持久化存储
```

这样可实现三种角色自由切换且互不冲突：
1. **互为主从的开发机**：两台电脑都装标准 `jade`；在 A 机本地用 `jade ui` 起任务、或用 B 机远程调度 A 机，看到的是同一份 `job` 目录和历史日志，不会各自锁库或互相不可见。
2. **安全隔离（装了 ≠ 被控）**：即使某台机器运行着完整 `jade`，只要本机 `allowlist` 未信任主控机的 `device_id`（或显式启用 `--local-only`），就不会放行远程操作。
3. **无头纯被控节点（可选轻量化）**：对于只想作为被控机器的服务器，无需新造协议：
   - **运行时开关**：提供 `jade serve --worker-only`（只连接 `control.sock` 注册 `service 16` 接单，不提供/不提示交互式前端或 MCP）；
   - **编译期可选裁剪（按需）**：若追求极小二进制体积，可通过 Cargo feature 把 `tui` / `mcp` 设为可选，无头服务器仅编译 `jade-core + jade-service + worker` 入口。

### 6.2 多路并发保障（瞬时突刺有界等待，不静默丢弃）

并发由传输层、桥接池、执行层三层协同完成：
1. **传输层（`topaz-net::Multiplexer`）**：单条 QUIC/Relay 会话内置多路复用，支持任意数量独立 `Channel`（每条流独立 2 MiB 背压队列 + 小帧优先调度），同一控制端并发对同一目标开多条操作流不会队头阻塞。
2. **桥接层（`topaz-cli` Accept 池）**：`jade serve` 维持 **2~4 条**挂起 `GET /v1/services/16/accept` WebSocket 连接；每当一条远端 `/v1/services/16/open/{target}` 到达，`topaz` 的 `ServiceRegistry` 立即弹出一根空闲 WS 发送 `"accepted"` 交接帧，`jade serve` 当即 `tokio::spawn` 处理并异步补回空闲池。瞬时超过池深度的流在 20 秒注册宽限内最多等待 2 秒，不会静默丢弃。
3. **执行层（`jade`）**：长耗时操作转后台 `Job` 落盘异步执行；单控 Agent 可同一时刻向 N 台机器并行下发 `exec`/`read`/`edit` 并同时订阅多路 `Job` 日志流。

### 6.3 远端服务发现消费（单控 Agent 调度）

- 每个对端只要连上就会收到一帧 DISCOVERY（**列表为空也会发 `seq=0, []`**），因此“在线但没装插件”和“旧版本从不发发现帧”在协议上可区分；
- 订阅 `GET /v1/events` 后，主控端过滤 `status.peers[]` 中 `path != null` 且 `services` 包含 `service_id == 16` 的节点，即可识别哪些机器当前已挂载 `jade`；`path == null` 表示离线（此时 `services` 为空，不代表没装）；
- 因此主控 Agent 与 `jade ui` 目标切换器无需向纯 VPN 节点盲试 `/v1/services/16/open/{target}`。

---

## 7. 给 `jade` 仓库的实现清单

> **当前进度同步**：
> - `topaz` 侧核心能力与联调进度：
>   - **Step 1–2（已完成）**：QUIC/Relay 数据报与并发 Eager Mesh 底座
>   - **Step 3（已完成）**：`topaz-coord` IPAM（`100.64.0.0/10` + 唯一 `dns_name`）与状态字段输出
>   - **Step 4（已完成）**：`topaz-vpn`（Linux/macOS TUN 与 `*.topaz` 本地 DNS，支持 `--no-tun`）
>   - **Step 5（已完成）**：`control.sock` 上的 `/v1/events` 实时推送与 `/v1/services/{id}/open|accept` 双向桥接（所有非 `101` 错误均保证携带 `Content-Length` + JSON `{"error": "..."}`）
>   - **Step 6（已完成）**：跨节点 `peers[].services` 实时发现、`topaz run --detach`、以及 OpenCode 风格 `topaz tui`
> - `jade` 侧可直接接入 `/v1/events` 实时推送在线机器（含远端 `peers[].services`）与本机 `service 16` 的 `listeners` 数量，并与 `topaz run` 进行端到端联调：

1. **在 `jade-service` 新增 `topaz` 运行时适配器（纯 UDS + WS，不引入 `topaz-*` 依赖）**：
   - 新增 `WsByteStream`（`AsyncRead + AsyncWrite` 封装 WebSocket Binary 帧）。
   - 新增 `TopazClient`（连接 `TOPAZ_CONTROL_SOCK` / `~/.topaz/control.sock`）：
     - `devices()` / `status()` / `subscribe_events()`（解析本机 `services` 及远端 `peers[].services`，`#[serde(default)]` 兼容缺省空数组）
     - `TopazDialer`（实现 `AgentDialer`）：默认走 `GET /v1/services/16/open/{peer}`；可选支持 L3 模式（通过 `devices()` 解析 `virtual_ip` 直连 `<ip>:<port>`）。
   - 修改 `jade_service::dialer_for`：除 `local` 外使用 `TopazDialer`（或在迁移期保留 `JADE_BRIDGE_SOCK` 兼容 `RouteDialer`）。
2. **在 `jade-cli` 的 `jade serve` 接入入站桥接与角色开关**：
   - 后台常驻任务连接 `control.sock` 的 `GET /v1/services/16/accept?name=jade`，维持 2~4 条等待连接，断线指数退避重连（`topaz` 未启动时静默等待重试，不影响本地 `jade.sock` 正常使用）。
   - 收到 `"event": "accepted"` 文本帧后，读取 `peer_device_id` 并 `tokio::spawn(server.serve_stream(&peer_device_id, ws_byte_stream))`。
   - 若同时启用 L3 TCP 监听（可选 `--listen-vpn <port>`），对接入连接按 `remote_ip -> device_id` 反查后再调用 `AgentServer::serve_stream(&device_id, tcp_stream)`。
   - 按需提供 `--worker-only`（仅注册 `service 16` 被控接单）与 `--local-only`（不向外暴露 `service 16`，仅本地使用）选项。
3. **测试与清理**：
   - 在 `jade-service` 中使用本地 `tokio::net::UnixListener` + `axum`/`tokio-tungstenite` 编写 Mock `control.sock` 集成测试，覆盖：`/v1/services/16/open/{peer}` 正常与 `404/409/503` 错误传播、`/v1/services/16/accept` 身份交接与 `allowlist` 拦截、`peers[].services` 发现解析、流关闭取消 `JobLog` 推送等场景。
   - 迁移验证完成后，移除或归档不再使用的 `jade/bridge/`。
