# 配置说明（与当前代码一致）

本文描述 `config.h` / `config.cpp` / `main.cpp` 的当前行为，重点覆盖 `socks5`、`mux`、`tproxy`、`reality`。

## 1. 顶层结构

配置顶层字段：

- `mode`
- `workers`
- `log`
- `inbound`
- `outbound`
- `socks`
- `tproxy`
- `timeout`
- `limits`
- `heartbeat`
- `monitor`
- `reality`

## 2. 进程启动顺序

`main.cpp` 中的运行装配顺序：

1. 解析并校验配置（`parse_config_with_error`）。
2. 启动 `monitor_server`（当 `monitor.enabled=true`）。
3. 当 `mode=server` 时启动 `remote_server`。
4. 当 `mode=client` 且 `socks.enabled=true` 时启动 `socks_client`。
5. Linux 且编译启用 TPROXY 时，若 `mode=client` 且 `tproxy.enabled=true` 启动 `tproxy_client`。

说明：`socks_client` / `tproxy_client` 仅在 `mode=client` 启动；`mode=server` 下即使配置了 `socks/tproxy` 也不会启动。

## 3. 基础字段

### `mode`

- 可选：`client` / `server`。
- 其他值直接报错：`/mode must be client or server`。
- `mode=client` 时要求至少启用 `socks` 或 `tproxy` 之一（非 Linux 构建不支持 `tproxy`）。

### `workers`

- `0`：使用 `std::thread::hardware_concurrency()`；若探测失败回退 `4`。
- `>0`：按指定线程数创建 `io_context_pool`。

### `log`

- `log.level`：日志等级（默认 `info`）。
- `log.file`：日志文件（默认 `app.log`）。

## 4. 入站/出站配置

### `inbound`（服务端监听）

- 字段：`inbound.host`、`inbound.port`。
- 校验：`mode=server` 时，`inbound.host` 必须是非空且合法 IP。
- 使用位置：`remote_server::accept_loop()`。

### `outbound`（客户端远端地址）

- 字段：`outbound.host`、`outbound.port`。
- 校验：`mode=client` 时，`host` 非空、`port != 0`。
- 使用位置：`client_tunnel_pool` 连接远端服务端。

## 5. SOCKS5

字段：

- `socks.enabled`（默认 `true`）
- `socks.host`（默认 `127.0.0.1`）
- `socks.port`（默认 `1080`）
- `socks.auth`（默认 `false`）
- `socks.username` / `socks.password`

校验：

- `mode=client` 且 `socks.enabled=true` 时，`socks.host` 必须是合法 IP。
- `username/password` 不得包含 `NUL`。
- 当 `socks.auth=true`：用户名和密码必须非空，且长度都 <= 255 字节。

运行行为：

- `socks_session` 支持 `CONNECT` 与 `UDP ASSOCIATE`。
- `CONNECT` 进入 `tcp_socks_session`（按路由走 `direct_upstream` 或 `proxy_upstream`）。
- `UDP ASSOCIATE` 进入 `udp_socks_session`，通过 mux stream 与服务端 `remote_udp_session` 交互。

## 6. TPROXY

字段：

- `tproxy.enabled`（默认 `false`）
- `tproxy.listen_host`（默认 `::`）
- `tproxy.tcp_port`（默认 `1081`）
- `tproxy.udp_port`（默认 `0`）
- `tproxy.mark`（默认 `0x11`）

校验：

- `mode=server` 禁止启用 `tproxy`。
- 非 Linux 构建（`SOCKS_HAS_TPROXY=0`）时，`tproxy.enabled=true` 直接报错。
- `tproxy.enabled=true` 时：
  - `listen_host` 必须是合法 IP。
  - `tcp_port` 和 `udp_port` 不能同时为 0。

运行行为：

- `TPROXY TCP` 使用 `SO_ORIGINAL_DST` 提取原始目标地址，再按路由规则选择 `direct` 或 `proxy`。
- `TPROXY UDP` 使用 `recvmsg + IP_RECVORIGDSTADDR/IPV6_RECVORIGDSTADDR` 提取原始目标地址，并按 `client endpoint + target endpoint` 维护会话。
- `mark` 用于本地出站 socket 的 `SO_MARK`，包括直连上游 socket、隧道连接 socket，以及回包用的透明 UDP socket。

## 7. 路由

### 路由规则

路由器从 `config/` 下读取：

- `block_ip.txt`
- `direct_ip.txt`
- `proxy_domain.txt`
- `block_domain.txt`
- `direct_domain.txt`

`router` 决策输出：`direct` / `proxy` / `block`。

注意：
- IP 规则仅支持 CIDR（如 `1.2.3.4/32`、`2001:db8::/32`），不带 `/` 的行会被忽略。
- 域名规则为后缀匹配（`example.com` 会匹配 `foo.example.com`）。
- 任一规则文件缺失或加载失败会导致 `router.load()` 返回失败，`socks/tproxy` 启动会直接返回错误。
- 默认路由：IP 未命中规则时走 `proxy`，域名未命中规则时走 `direct`。

## 8. 超时与心跳

### `timeout`

- `timeout.read`
- `timeout.write`
- `timeout.connect`
- `timeout.idle`

语义：

- `read/write/connect` 为 `0` 时禁用该类超时（`timeout_io.h`）。
- `idle` 用于空闲回收 watchdog，必须大于 `0`，禁止配置为 `0`。

注意：

- 使用 MUX 时，`timeout.write` 禁止为 `0`，避免单个 stream 反压导致整条连接无进度。
- `timeout.idle` 禁止为 `0`，避免 UDP 会话等长时间不回收导致资源耗尽。

### `heartbeat`

字段：

- `heartbeat.enabled`
- `heartbeat.idle_timeout`
- `heartbeat.min_interval` / `heartbeat.max_interval`
- `heartbeat.min_padding` / `heartbeat.max_padding`

校验：

- `min_interval > 0`
- `max_interval > 0`
- `min_interval <= max_interval`
- `min_padding <= max_padding`
- `max_padding <= kMaxPayload`（单个 mux 帧最大 payload）

运行行为：

- 在 `mux_connection::heartbeat_loop()` 中发送心跳帧（`stream_id=heartbeat`）。

## 9. 限流与容量

### `limits`

字段：

- `limits.max_connections`（默认 `5`）
- `limits.max_buffer`（默认 `10 MiB`）
- `limits.max_streams`（默认 `1024`）
- `limits.max_handshake_records`（默认 `256`）

校验：

- `max_connections` 在反序列化后会归一化：`0 -> 1`。
- `max_buffer > 0`。
- `max_handshake_records` 必须在 `1..4096`。

运行行为：

- `max_connections`：用于客户端 `client_tunnel_pool` 维护的并发隧道数。
- `max_streams`：用于 `mux_connection` 的 stream 数量上限。
- `max_buffer`：用于 `mux_dispatcher` 明文缓存上限。
- `max_handshake_records`：用于客户端 REALITY 握手读取上限。

## 10. REALITY

字段：

- `reality.sni`
- `reality.fingerprint`
- `reality.replay_cache_max_entries`
- `reality.private_key`
- `reality.public_key`
- `reality.short_id`

校验要点：

- `private_key` / `public_key`：提供时必须是 32 字节十六进制。
- `short_id`：提供时最多 8 字节十六进制。
- `sni`：提供时必须是合法 ASCII hostname；不能为空白、控制字符或非 ASCII；总长度 <= 255，单个 label 长度 <= 63，且 label 不能以前后缀 `-` 或空 label 形式出现。
- `mode=client`：`public_key` 必填，`fingerprint` 必须是允许值（`random/chrome/firefox/ios/android` 或版本别名）。
- `mode=server`：`private_key` 必填。

字段语义：

- `reality.sni`
  - `mode=client`：写入客户端 `ClientHello` 的 `SNI`。
  - `mode=server`：作为服务端侧使用的目标主机名。
- `reality.fingerprint`
  - 仅 `mode=client` 生效，用于选择客户端握手指纹模板。
- `reality.replay_cache_max_entries`
  - 仅 `mode=server` 生效，用于限制重放缓存容量。
- `reality.private_key`
  - 仅 `mode=server` 生效，用于服务端认证相关密钥计算。
- `reality.public_key`
  - 仅 `mode=client` 生效，用于客户端认证相关密钥计算。
- `reality.short_id`
  - 客户端写入认证载荷，服务端用于校验；`mode=server` 时必须非空。

## 11. 监控

字段：

- `monitor.enabled`
- `monitor.port`

运行行为：

- `monitor_server` 默认监听 `127.0.0.1:<port>`。
- 仅支持 `GET /metrics`（Prometheus 文本格式）。
- 当前实现不包含鉴权或限流逻辑。
