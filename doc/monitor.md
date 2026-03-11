# 监控指标

`monitor_server` 默认监听 `127.0.0.1:<port>`，仅支持 `GET /metrics`（Prometheus 文本格式），当前无鉴权与限流。

## 指标列表

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `socks_uptime_seconds` | gauge | 进程启动后的运行秒数。 |
| `socks_active_connections` | gauge | 当前活跃的 SOCKS 连接数。 |
| `socks_total_connections` | counter | 累计 SOCKS 连接数。 |
| `socks_active_mux_tunnels` | gauge | 当前活跃的 MUX 隧道数。 |
| `socks_bytes_read_total` | counter | 累计读取字节数。 |
| `socks_bytes_written_total` | counter | 累计写出字节数。 |
| `socks_auth_failures_total` | counter | REALITY 认证失败总数。 |
| `socks_auth_short_id_failures_total` | counter | short_id 校验失败总数。 |
| `socks_auth_clock_skew_failures_total` | counter | 时间戳偏差导致的认证失败总数。 |
| `socks_auth_replay_failures_total` | counter | 重放检测失败总数。 |
| `socks_cert_verify_failures_total` | counter | 证书校验失败总数。 |
| `socks_client_finished_failures_total` | counter | 客户端 Finished 校验失败总数。 |
| `socks_fallback_rate_limited_total` | counter | fallback 被限流的次数。 |
| `socks_fallback_no_target_total` | counter | fallback 无目标的次数。 |
| `socks_fallback_resolve_failures_total` | counter | fallback 解析失败总数。 |
| `socks_fallback_resolve_timeouts_total` | counter | fallback 解析超时总数。 |
| `socks_fallback_resolve_errors_total` | counter | fallback 解析错误总数。 |
| `socks_fallback_connect_failures_total` | counter | fallback 连接失败总数。 |
| `socks_fallback_connect_timeouts_total` | counter | fallback 连接超时总数。 |
| `socks_fallback_connect_errors_total` | counter | fallback 连接错误总数。 |
| `socks_fallback_write_failures_total` | counter | fallback 写失败总数。 |
| `socks_fallback_write_timeouts_total` | counter | fallback 写超时总数。 |
| `socks_fallback_write_errors_total` | counter | fallback 写错误总数。 |
| `socks_site_material_fetch_attempts_total` | counter | 站点素材抓取尝试次数。 |
| `socks_site_material_fetch_successes_total` | counter | 站点素材抓取成功次数。 |
| `socks_site_material_fetch_failures_total` | counter | 站点素材抓取失败次数。 |
| `socks_direct_upstream_resolve_timeouts_total` | counter | 直连上游解析超时次数。 |
| `socks_direct_upstream_resolve_errors_total` | counter | 直连上游解析错误次数。 |
| `socks_direct_upstream_connect_timeouts_total` | counter | 直连上游连接超时次数。 |
| `socks_direct_upstream_connect_errors_total` | counter | 直连上游连接错误次数。 |
| `socks_remote_session_resolve_timeouts_total` | counter | 远端会话解析超时次数。 |
| `socks_remote_session_resolve_errors_total` | counter | 远端会话解析错误次数。 |
| `socks_remote_session_connect_timeouts_total` | counter | 远端会话连接超时次数。 |
| `socks_remote_session_connect_errors_total` | counter | 远端会话连接错误次数。 |
| `socks_remote_udp_session_resolve_timeouts_total` | counter | 远端 UDP 会话解析超时次数。 |
| `socks_remote_udp_session_resolve_errors_total` | counter | 远端 UDP 会话解析错误次数。 |
| `socks_client_tunnel_pool_resolve_timeouts_total` | counter | 客户端隧道池解析超时次数。 |
| `socks_client_tunnel_pool_resolve_errors_total` | counter | 客户端隧道池解析错误次数。 |
| `socks_client_tunnel_pool_connect_timeouts_total` | counter | 客户端隧道池连接超时次数。 |
| `socks_client_tunnel_pool_connect_errors_total` | counter | 客户端隧道池连接错误次数。 |
| `socks_client_tunnel_pool_handshake_timeouts_total` | counter | 客户端隧道池握手超时次数。 |
| `socks_client_tunnel_pool_handshake_errors_total` | counter | 客户端隧道池握手错误次数。 |
| `socks_routing_blocked_total` | counter | 路由被阻断的次数。 |
| `socks_connection_limit_rejected_total` | counter | 连接上限拒绝次数（当前未接入统计）。 |
| `socks_stream_limit_rejected_total` | counter | stream 上限拒绝次数（当前未接入统计）。 |
| `socks_monitor_auth_failures_total` | counter | monitor 鉴权失败次数（当前未接入统计）。 |
| `socks_monitor_rate_limited_total` | counter | monitor 限流次数（当前未接入统计）。 |
| `socks_handshake_failures_by_sni_total{reason="...",sni="..."}` | counter | 按 SNI 归类的握手失败次数。 |
