# 拆分留档与引擎接入架构说明（Topaz / Opal / Jade）

> 本文档在三个独立项目（`topaz`、`opal`、`jade`）中均保留一份同源存档，用于记录原单体项目的解体背景、三个项目的职责边界，以及 **`opal`（文件同步）和 `jade`（Agent）未来接入 `topaz`（网络引擎）的设计契约**。

---

## 1. 背景：从单体解体为三个独立项目

原 `syncscale` 单体项目已正式停止并彻底解体，按职责拆分为三个零耦合、可独立演进的 Rust Workspace：

| 项目 | 定位 | 二进制 | 核心职责 | 独立数据目录 |
| :--- | :--- | :--- | :--- | :--- |
| **`topaz`** | **纯网络与会话引擎底座** | `topaz`、`topaz-coord` | 设备密钥身份、账号信任链、Coord 信令/Relay/STUN、QUIC/mTLS、NAT 打洞、mDNS、多路复用会话与插件分发 | `~/.topaz` |
| **`opal`** | **文件同步项目（上层应用）** | `opal` | `blake3` 分块索引、Delta 同步、冲突保留、历史版本（`.opal/versions`）、忽略规则（`.opalignore`）、Ed25519 签名文件夹策略 | `~/.opal` |
| **`jade`** | **Agent 执行与 MCP 项目（上层应用，待重做/演进）** | `jade` | 独立进程组命令执行、范围读取、原子写、目录列表、审计与作业日志、stdio MCP 服务、策略门禁 | `~/.jade` |

### 当前状态：刻意不耦合
三个项目之间目前**没有任何代码级依赖**（Cargo 依赖完全隔离）。`opal` 和 `jade` 当前均内置本地 CLI 与内存/双工流测试，不直接依赖网络实现。

---

## 2. 核心架构关系：`opal` 与 `jade` 都需要接入 `topaz`

在完整产品形态下，**`topaz` 是唯一负责跨设备组网与可信信道的基础设施；`opal` 与 `jade` 都是运行在 `topaz` 会话织物之上的上层业务服务**：

```text
+-----------------------------------+     +-----------------------------------+
|          opal (文件同步)          |     |          jade (Agent/MCP)        |
|  - opal-service::SyncService     |     |  - jade-service::AgentServer     |
|  - trait SyncHost                 |     |  - trait AgentHost / AgentDialer  |
+-----------------+-----------------+     +-----------------+-----------------+
                  |                                         |
                  |  service_id = 1                         |  service_id = 16
                  |  AsyncRead + AsyncWrite (Channel)       |  AsyncRead + AsyncWrite (Channel)
                  v                                         v
+-----------------------------------------------------------------------------+
|                         topaz (纯网络会话引擎)                              |
|  - topaz_fabric::Service trait (on_stream / on_session / on_peers_refreshed)
|  - topaz_fabric::EngineHandle (open / kick / device_set / status)         |
|  - topaz_net (QUIC + mTLS / TCP+WSS Relay / STUN 打洞 / Multiplexer)       |
+-----------------------------------------------------------------------------+
```

### 架构铁律
1. **`topaz` 永远保持纯网络底座**：绝不允许把文件夹策略、分块同步状态、Agent 权限策略或业务路由塞回 `topaz-core`、`topaz-coord` 或 `topaz-net`。
2. **向上暴露流，不暴露传输细节**：`topaz` 只把已通过 mTLS 认证的多路复用流 `topaz_net::Channel`（实现了 `AsyncRead + AsyncWrite + Unpin + Send`）按 `service_id` 分发给服务。
3. **接入通过独立适配器 / 装配层完成**：将来连接时，可在独立集成 crate 或装配二进制中实现适配胶水，将 `topaz` 与 `opal` / `jade` 装配到同一运行循环（或通过 IPC 暴露流接口）。

---

## 3. 服务 ID 分配与底层契约

当 `opal` 和 `jade` 接入 `topaz` 时，遵循以下从原插件规范沉淀下来的核心契约：

### 3.1 服务 ID（`u16`）规划
| 号段 | 归属 / 用途 | 当前分配 |
| :--- | :--- | :--- |
| `0` | 非法 | 引擎启动时直接拒绝 |
| `1..=15` | 核心保留段 | `opal` 同步协议（`SYNC_SERVICE_ID = 1`）、`topaz` 内置探活（`PING = 2`） |
| `16..=1023` | 注册应用服务段 | `jade` Agent 协议（`AGENT_SERVICE_ID = 16`） |
| `1024..=65535` | 实验/私有服务段 | 新协议实验（对端未挂载时回 `Frame::Unknown` 并排空流） |

> 协议原则：**无带内 ID 协商、无信封版本协商**。每个上层服务在其流内第一帧携带自己的协议版本号（如 `opal` 的 `Hello`、`jade` 的 `AgentCall { version, op }`），版本不匹配直接拒绝该流并 `drop(channel)`。

### 3.2 并发与不对称规则（接入时务必遵守）
1. **只有较小 `device_id` 一侧触发 `on_session`**：
   - 轮次主动发起（拨号/复用会话）只在 `local_device_id < peer_device_id` 一侧通过 `Service::on_session(peer, mux)` 触发，防止双端同时主动对发起造成死锁。
   - **例外**：`EngineHandle::open(peer, service_id)` 允许宿主在任意一侧按需向对端开流（例如 `jade` 从控制端向目标机器发起工具调用）。
2. **长驻服务必须 `tokio::spawn` 后立即返回**：
   - `Service::on_stream(peer, channel)` 在 `topaz` 引擎主循环上内联运行。
   - **轮次型服务（`opal`）**：在一轮 `handle_stream` 内跑完返回，天然保证同步轮次串行化。
   - **长驻/并发型服务（`jade`）**：一条命令可能运行数分钟，必须在 `on_stream` 中 `tokio::spawn` 独立任务接管 `channel` 并立即返回，否则会阻塞引擎主循环的心跳与其它服务。
3. **背压与取消语义（`mux=v2`）**：
   - **独立流控、无队头阻塞**：直连使用 QUIC 原生双向流，TCP/WSS 中继使用 `yamux` 每流独立窗口流控（单条慢流不会拖垮整条会话或阻塞其它服务流）；中继 L3 数据报优先经由端到端 ChaCha20-Poly1305 加密的 UDP/QUIC Datagram Relay（`7724/udp`）透传，避免 TCP-over-TCP 拥塞崩溃。
   - **真半关闭与 EOF 取消**：`shutdown()` 仅关闭写方向（保留读方向接收尾包），`drop(channel)` 发送 FIN/RESET，接收端读到 EOF 即视为取消信号（`jade` 据此强杀子进程组、回滚未提交的 `.part` 写入）。

---

## 4. 各项目已预留的接入边界清单

### 4.1 `topaz` 侧（提供底层网络与会话能力）
- 服务注册接口：`topaz_fabric::Service`（`id`、`on_stream`、`on_session`、`on_peers_refreshed`）
- 引擎外部句柄：`topaz_fabric::EngineHandle`
  - `open(&self, peer: &str, service: u16) -> Result<Channel>`（主动向对端开流）
  - `kick(&self, announce: bool)`（本地事件唤醒一轮会话）
  - `device_set(&self)` / `status(&self)`（获取当前账号信任设备表与连接状态）
- 构建入口：`topaz_fabric::Engine::build(deps, make_services, status)`

### 4.2 `opal` 侧（待接入 `topaz` 的文件同步接口）
- 宿主边界 trait：`opal_service::SyncHost`
  - `kick(&self, announce: bool)` → 对接 `EngineHandle::kick`
  - `status_changed(&self)` → 对接状态写入通知
  - `trust_context(&self) -> (String, Vec<TrustedDeviceKey>)` → 对接 `topaz` 账号公钥与 `DeviceSet`
- 流入口：
  - `SyncService::handle_stream(&self, stream: &mut S, peer_id: &str)`
  - `opal_service::run_rounds(stream, store, peer_id, user_pubkey, active)`
  - 其中 `S: AsyncRead + AsyncWrite + Unpin`，直接传入 `topaz_net::Channel` 即可完成适配。
- 接入形态建议：实现一个 `OpalFabricService` 包装 `Arc<opal_service::SyncService>`，在 `id()` 返回 `opal_proto::SYNC_SERVICE_ID (1)`，在 `on_session()` 主动开流跑 `handle_stream`，在 `on_stream()` 被动应答 `handle_stream`。

### 4.3 `jade` 侧（待重做或后续接入 `topaz` 的接口）
- 传输与策略边界 trait（位于 `jade_service::transport`）：
  - `jade_service::AgentDialer::open_stream(peer, service_id) -> BoxFuture<Result<BoxStream>>` → 对接 `EngineHandle::open(peer, AGENT_SERVICE_ID)`
  - `jade_service::AgentHost::config(&self) -> AgentConfig` → 提供本地/动态策略配置（并可通过信任列表将对端设备名解析为 `device_id`）
- 服务端与客户端入口：
  - 服务端：`AgentServer::serve_stream(&self, caller_id: &str, stream: S)`（接收 `Channel` 并 `tokio::spawn` 运行）
  - 客户端：`AgentClient<D>` 或流级函数 `open_call` / `probe` / `pump` / `ReadStream` / `WriteStream`
- 注意：`jade` 后续计划结合新需求重构交互/工具模型；只要保持“通过双向字节流 `AsyncRead + AsyncWrite` 通信、通过 `topaz` 的 `service_id = 16` 承载”这一契约，底层传输即可无缝对接 `topaz`。
