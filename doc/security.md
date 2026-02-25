# 安全设计

本项目以“最小暴露面、可控资源、可追踪审计”为原则，设计要点如下：

## 暴露面控制

1. 本地 SOCKS5 监听地址可配置，默认建议仅监听回环地址。
2. 监控接口仅允许本机访问，当前实现不提供鉴权与限流能力，依赖本机绑定与网络隔离。
3. 服务端对连接数与 stream 数量做上限控制，避免资源被耗尽。

## 认证与握手

1. 使用 REALITY 伪装握手对外观进行伪装。
2. 会话内使用派生密钥进行加密传输。
3. 对异常握手与重放行为进行检测并拒绝。
4. 当 `socks.auth = true` 时，SOCKS5 用户名和密码必须均非空，任一为空会在配置解析阶段直接报错。

## 资源与并发限制

1. `max_connections` 限制服务端并发隧道数。
2. `max_streams` 限制单连接内 stream 数量。
3. `max_buffer` 限制 mux dispatcher 缓冲区，防止内存放大。
4. 写队列与缓冲溢出会触发连接关闭与 reset。
5. fallback 防护的来源状态表采用上限控制，避免高基数来源导致状态内存无限增长。
6. `监控鉴权/限流能力` 与 `客户端配置热加载` 不在当前项目规划范围内。

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

1. fallback 防护按来源地址维度维护状态，限流与熔断只影响对应来源，不应跨来源串扰。
2. 连接上限在握手前执行硬拒绝，避免被未完成握手连接占满计算资源。
3. 握手失败、fallback 限流、路由拦截等关键拒绝路径必须暴露到监控指标中，便于告警与审计。

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

## 代码审查问题追踪（2026-02-25）

以下问题按严重度排序，均已修复并通过测试回归。

### P0: fallback 精确 SNI 匹配未做规范化，导致错误回落目标

- 触发时机或场景：
  - 服务端 `fallbacks.sni` 配置为包含大写或尾点形式，例如 `WWW.Example.COM.`。
  - 客户端握手 SNI 使用语义等价但大小写或尾点不同的形式，例如 `www.example.com`。
- 表现出的现象：
  - 本应命中的精确 fallback 规则未命中。
  - 流量被错误地路由到 wildcard fallback、`reality.dest`，或在无可用回落目标时直接失败。
  - 外部表现为 fallback 目标错误、连接失败率升高、行为与配置不一致。
- 根因：
  - 精确匹配路径使用原始字符串逐字节比较，未进行 SNI 语义规范化。
- 修复方案：
  - 在 fallback 精确匹配路径引入统一 SNI 规范化（ASCII 小写化，去除尾随 `.`）。
  - 匹配时对配置侧和请求侧都使用规范化值比较。
- 影响范围：
  - `remote_server` 的 `find_exact_sni_fallback` 与 `find_fallback_target_by_sni` 相关路径。
- 验证：
  - 单测补充并通过：`tests/remote_server_test.cpp` 中 `FallbackSelectionAndCertificateTargetBranches` 新增大小写和尾点覆盖断言。

### P1: fallback_guard 在 `ip_sni` 维度未去尾点，存在限流/熔断桶分裂

- 触发时机或场景：
  - `reality.fallback_guard.key_mode = ip_sni`。
  - 同一来源地址使用 `www.example.com` 与 `www.example.com.` 交替发起 fallback 触发流量。
- 表现出的现象：
  - 同一逻辑域名被分配到不同 bucket，令牌桶和熔断状态分裂。
  - 结果为限流与熔断效果被弱化，监控上同源同域行为出现异常离散。
- 根因：
  - bucket key 仅做了小写化，未对尾点进行规范化。
- 修复方案：
  - fallback_guard key 与 fallback 精确匹配复用同一 SNI 规范化策略（小写 + 去尾点）。
- 影响范围：
  - `remote_server::fallback_guard_key`、`consume_fallback_token`、`record_fallback_result` 相关状态聚合行为。
- 验证：
  - 单测补充并通过：`tests/remote_server_test.cpp` 中 `FallbackGuardKeyModeIpSniSeparatesBuckets` 新增尾点归一化断言。

### P1: 证书缓存 SNI 键未规范化，导致缓存分裂与额外证书抓取

- 触发时机或场景：
  - 不同客户端使用大小写不同或尾点不同但语义等价的 SNI。
  - 服务端按 SNI 从 `cert_manager` 查询证书缓存。
- 表现出的现象：
  - 语义等价 SNI 产生多份缓存条目，命中率下降。
  - 证书抓取请求次数增加，带来额外延迟和外连开销。
  - 在极端情况下更早触发 LRU 淘汰，挤出热点证书条目。
- 根因：
  - `cert_manager` 对 `set/get` 采用原始 SNI 字符串作为 map key。
- 修复方案：
  - `cert_manager` 在读写缓存键时统一进行 SNI 规范化（小写 + 去尾点）。
  - `remote_server::resolve_certificate_target` 的 `cert_sni` 也同步使用规范化值，避免上游路径产生非规范键。
- 影响范围：
  - `cert_manager` 的缓存索引行为与 `remote_server` 的证书目标解析路径。
- 验证：
  - 单测补充并通过：`tests/cert_manager_test.cpp` 新增 `SniLookupNormalizesCaseAndTrailingDot`。
  - `tests/remote_server_test.cpp` 在证书目标分支新增 `cert_sni` 规范化断言。

## 每步验证要求

1. 编译：`cmake --build build -j15`
2. 单元与集成：`ctest --test-dir build -j20 --output-on-failure`
