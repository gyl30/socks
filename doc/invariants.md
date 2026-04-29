# 协议与架构不变量

这份说明只记录当前实现必须保持为真的边界，不展开设计背景。

## 1. 架构边界

- `router`
  - 只负责把 `request_context` 映射到 outbound。
  - 语义是 `first-match`，匹配到第一条规则后立即返回。
  - 不负责建立连接，不负责转发数据，不维护会话生命周期。

- `tcp_connect_flow` / `udp_session_flow`
  - 负责把入站请求整理成统一的目标信息，然后调用路由和出站。
  - TCP/UDP 的目标归一化必须保持一致；`::ffff:x.y.z.w` 视为 IPv4。
  - 这里是“目标识别 + 路由 + 出站创建”的唯一入口，不应在各个 session 内重复实现一套。

- `*_session`
  - 一个 session 对应一个用户可见的代理请求。
  - 负责协议状态机、超时、关闭原因、trace 事件。
  - 不跨 session 共享传输状态。

- `stream_relay` / `datagram_relay`
  - 只负责双向搬运和 idle watchdog。
  - 不做路由决策，不解释业务规则。

## 2. 路由语义

- 当前只支持 `first-match`，不支持多条件组合求值。
- `domain` 规则按精确匹配处理，不是 suffix / wildcard。
- `inbound` 规则可以直接选定 outbound。
- `block` 是显式路由结果，不是错误分支。

## 3. Reality 外层连接模型

- 不做连接复用。
- 不做 mux。
- 一个代理 TCP 会话对应一条 `proxy_reality_connection`。
- 一个代理 UDP 会话对应一条 `proxy_reality_connection`。
- 服务端 `reality_inbound` 完成握手后，只承载一个代理会话。

如果将来要改成复用或 mux，必须先改协议，再改 session 与 relay；不能只在实现层偷偷共享连接。

## 4. 自定义代理协议

### TCP

- 建连顺序固定：
  1. `tcp_connect_request`
  2. `tcp_connect_reply`
  3. `tcp_data` / `tcp_shutdown`

- `tcp_data`
  - payload 必须非空。
  - 只能出现在连接建立成功之后。
  - 本端发送 `tcp_shutdown` 后，不能继续发送 `tcp_data`。
  - 收到对端 `tcp_shutdown` 后，不能继续接收 `tcp_data`。

- `tcp_shutdown`
  - 表示流级半关闭，不等于整条外层 REALITY/TCP 连接关闭。
  - 每个方向最多一次。
  - 重复 `tcp_shutdown`、`tcp_shutdown` 后继续发 `tcp_data`、或其他非法序列，都按协议错误处理。

### UDP

- 建连顺序固定：
  1. `udp_associate_request`
  2. `udp_associate_reply`
  3. `udp_datagram`

- `udp_datagram`
  - 必须保留报文边界。
  - 最大 payload 按系统 UDP 能承载的大小收口。
  - 内部代理帧不能接受超出系统可落地 UDP payload 的报文。

## 5. 关闭与错误语义

- 配置错误、监听失败、启动期关键资源错误：记录日志后直接退出进程。
- TCP EOF：传播为对端 `shutdown_send`，不是直接把整个会话硬关闭。
- idle timeout：关闭当前 session，并写入对应 trace / 日志。
- 协议帧非法、消息序列非法、读写错误：关闭当前代理会话；不做自动恢复或降级。

## 6. 改代码时必须守住的检查点

- 改 TCP 协议状态机：至少更新 `proxy_protocol_regression` 和 `reality_integration_smoke`。
- 改跨路径行为：至少更新 `outbound_consistency`。
- 改资源回收、超时、会话生命周期：至少更新 `reality_resource_stability`。
- 改 UDP framing 或 guardrails：至少更新 `protocol_guardrails`。
