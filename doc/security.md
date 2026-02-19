# 安全设计

本项目以“最小暴露面、可控资源、可追踪审计”为原则，设计要点如下：

## 暴露面控制

1. 本地 SOCKS5 监听地址可配置，默认建议仅监听回环地址。
2. 监控接口仅允许本机访问，鉴权由 token 控制（按现有实现）。
3. 服务端对连接数与 stream 数量做上限控制，避免资源被耗尽。

## 认证与握手

1. 使用 REALITY 伪装握手对外观进行伪装。
2. 会话内使用派生密钥进行加密传输。
3. 对异常握手与重放行为进行检测并拒绝。
4. SOCKS5 用户名/密码认证仅在用户名和密码均非空时生效，任一为空时按无认证处理。

## 资源与并发限制

1. `max_connections` 限制服务端并发隧道数。
2. `max_streams` 限制单连接内 stream 数量。
3. `max_buffer` 限制 mux dispatcher 缓冲区，防止内存放大。
4. 写队列与缓冲溢出会触发连接关闭与 reset。
5. fallback 防护的来源状态表采用上限控制，避免高基数来源导致状态内存无限增长。
6. `监控鉴权增强` 与 `客户端配置热加载` 不在项目规划范围内。

## 异步执行模型

1. 每个异步对象绑定并只使用自己的 `io_context`，不使用 `strand`。
2. 跨线程访问对象内部状态时，通过 `post/dispatch` 回到该对象的 `io_context` 执行。
3. 任何同步等待回投递结果的路径都必须是有界等待，并覆盖 `running_in_this_thread` 与 `io_context.stopped()` 分支，避免自阻塞或停机阻塞。
4. `stop` 语义要求在 `io_context` 已停止或当前线程即执行线程时可直接内联清理，避免清理逻辑因队列不再调度而丢失。
5. `mux_connection::streams_` 采用“原子快照 + CAS”更新模型，发布后的快照必须视为只读，不允许对旧快照执行 `move/clear/erase` 等写操作。
6. `mux_connection` 在 `stop/remove` 路径使用 `dispatch_cleanup_or_run_inline`，当队列阻塞或超时仍需内联完成清理，保证资源回收不丢失。

## 超时与空闲回收

1. TCP/UDP 会话均有空闲检测，超时会主动关闭。
2. 心跳与读写超时结合，保证连接不可长期占用。

## 运行时控制

1. `drain` 模式仅关闭入站接收，不主动中断已建立隧道，用于滚动维护窗口。
2. `stop` 模式关闭入站并回收已建立隧道，用于完整停机。
3. `stop` 或 `drain` 后可再次 `start` 重新打开监听端口，支持原地重启。
4. 客户端不支持配置热加载；配置变更需要重启客户端进程生效。

## 日志与审计

1. 所有错误路径必须记录日志。
2. 敏感握手数据不输出明文，仅记录大小或状态。
3. 日志内容统一小写，避免额外格式化符号。
4. 关键失败日志统一字段：`trace_id/conn_id/stream_id`（由 `LOG_CTX_*` 前缀输出）+ `stage` + `target` + `error/timeout`。
5. 当前关键链路至少覆盖：`client_tunnel_pool(resolve/connect/handshake)`、`remote_session(resolve/connect)`、`remote_udp_session(decode_header/resolve/send)`、`direct_upstream(resolve/connect)`、`proxy_upstream(send_syn/wait_ack/decode_ack)`、`fallback(resolve/connect/write)`、`cert_fetcher(resolve/connect)`。

## 失败路径处理

1. SOCKS/MUX 失败必须返回错误码或 reset。
2. 失败后立即回收 stream、关闭 socket、停止定时器。
3. 严禁在运行时使用 `abort()` 终止进程。

## 安全契约（稳定）

1. 监控鉴权必须先于监控限流执行，未授权请求不应污染限流状态。
2. fallback 防护按来源地址维度维护状态，限流与熔断只影响对应来源，不应跨来源串扰。
3. 连接上限在握手前执行硬拒绝，避免被未完成握手连接占满计算资源。
4. 握手失败、fallback 限流、路由拦截等关键拒绝路径必须暴露到监控指标中，便于告警与审计。

## 监控告警基线

1. fallback 失败按阶段拆分观测：`socks_fallback_*_{failures,timeouts,errors}_total`。
2. 客户端建连按阶段拆分观测：`socks_client_tunnel_pool_{resolve,connect,handshake}_{timeouts,errors}_total`。
3. 服务端会话按阶段拆分观测：`socks_remote_session_{resolve,connect}_{timeouts,errors}_total`、`socks_remote_udp_session_resolve_{timeouts,errors}_total`、`socks_direct_upstream_{resolve,connect}_{timeouts,errors}_total`。
4. 看板建议先展示 5 分钟短窗增量，再展示 1 小时趋势，示例：

```promql
increase(socks_fallback_connect_timeouts_total[5m])
increase(socks_client_tunnel_pool_handshake_errors_total[5m])
increase(socks_remote_session_connect_errors_total[5m])
```

5. 告警建议使用 10 分钟窗口并加 `for` 抑制瞬时抖动，初始阈值可从以下基线起步（按单实例）：

```promql
# fallback connect 超时突增
increase(socks_fallback_connect_timeouts_total[10m]) > 20

# 隧道握手错误突增
increase(socks_client_tunnel_pool_handshake_errors_total[10m]) > 15

# 远端 TCP 连接失败突增
increase(socks_remote_session_connect_errors_total[10m]) > 30
```

6. 基线阈值需结合部署规模按实例数线性放大，并在上线后一周依据真实流量回放修订。

## 每步验证要求

1. 编译：`cmake --build build -j15`
2. 单元与集成：`ctest --test-dir build -j20 --output-on-failure`
