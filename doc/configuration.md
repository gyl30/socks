# 配置说明

配置文件通过 `config` 结构体反射生成，字段按模块分组如下。

## 基础字段

- `mode`：运行模式（默认 `server`）。
- `workers`：`io_context` worker 线程数；`0` 表示自动使用硬件并发数（探测失败时回退到 `4`）。
- `log.level` / `log.file`：日志等级与输出文件。

## 网络入口

- `inbound.host` / `inbound.port`：服务端监听地址与端口。
- `outbound.host` / `outbound.port`：客户端连接地址与端口。
- `socks.enabled`：是否启用 SOCKS5 入站（默认 `true`）。
- `socks.host` / `socks.port`：本地 SOCKS5 监听地址与端口。
- `socks.auth` / `socks.username` / `socks.password`：SOCKS5 认证配置。
  - 当 `socks.auth = true` 时，`socks.username` 与 `socks.password` 必须均为非空字符串。
  - 任一为空会在配置解析阶段直接报错。
- `tproxy.enabled`：是否启用 TPROXY 入站（默认 `false`）。
- `tproxy.listen_host`：TPROXY 监听地址（默认 `::`）。
- `tproxy.tcp_port` / `tproxy.udp_port`：TPROXY TCP/UDP 端口。`udp_port = 0` 表示跟随 `tcp_port`。
- `tproxy.mark`：TPROXY `SO_MARK`，用于路由/回避回环（默认 `0x11`）。
- 所有端口字段均要求 `0-65535` 的无符号整数；超出范围或负数会在解析阶段直接报错。

## 传输与超时

- `timeout.read` / `timeout.write` / `timeout.idle`：读写与空闲超时秒数。
- `heartbeat.enabled`：是否启用心跳。
- `heartbeat.idle_timeout`：空闲多久触发心跳。
- `heartbeat.min_interval` / `heartbeat.max_interval`：心跳随机间隔。
- `heartbeat.min_padding` / `heartbeat.max_padding`：心跳填充长度范围。
- `heartbeat.min_interval <= heartbeat.max_interval` 且 `heartbeat.min_padding <= heartbeat.max_padding`，否则配置解析失败。
- `heartbeat.min_interval` 和 `heartbeat.max_interval` 必须大于 `0`，否则配置解析失败，避免出现零间隔忙轮询。
- `heartbeat.max_padding` 必须小于等于 `65408`（`kMaxPayload`），否则配置解析失败，避免心跳分配超大缓冲区。

## 限制与保护

- `limits.max_connections`：服务端隧道最大并发数，`0` 会在加载与运行时归一化为 `1`。
- `limits.max_connections_per_source`：单来源并发连接上限，`0` 表示不启用来源维度限制。
- `limits.source_prefix_v4`：IPv4 来源聚合前缀（`0-32`），默认 `32`（按单 IP 限制）。
- `limits.source_prefix_v6`：IPv6 来源聚合前缀（`0-128`），默认 `128`（按单 IP 限制）。
- `limits.max_streams`：单连接 stream 最大数量。
- `limits.max_buffer`：mux dispatcher 最大缓冲区。
- `limits.max_buffer` 必须大于 `0`，否则配置解析失败。

## 协议契约（兼容性红线）

以下行为属于对外协议契约，后续版本不得无通知变更：

1. `limits.max_connections = 0` 视为配置错误输入并归一化为 `1`，客户端和服务端一致执行。
2. 服务端在 `accept` 成功后、REALITY 握手前预占连接槽；达到全局上限或来源上限时直接拒绝该连接，不进入握手路径。
3. 流量进入 mux 后，若 `max_streams` 已达上限，服务端必须先返回 `ACK(rep=general failure)`，再发送 `RST`。
4. SOCKS5 请求中，目标主机为空必须拒绝；`CONNECT` 请求目标端口为 `0` 必须拒绝；`UDP ASSOCIATE` 允许端口 `0`。
5. 监控接口仅接受 `GET /metrics` 或 `metrics`，并要求 `token` 参数精确匹配；未授权请求不得占用限流窗口。
6. 客户端配置变更不支持热加载，修改配置后必须重启客户端进程生效。

## REALITY

- `reality.sni`：伪装 SNI。
- `reality.fingerprint`：客户端指纹（默认 `random`）。
  - 可选值：`random`、`chrome`、`firefox`、`ios`、`android`（分别映射到 `chrome_120` / `firefox_120` / `ios_14` / `android_11_okhttp`）。
- `reality.dest`：回落目标（格式 `host:port`）。
- `reality.type`：回落网络类型（默认 `tcp`）。
- `reality.strict_cert_verify`：是否严格校验证书签名（默认 `false`）。
  - 仅当服务端证书公钥与 `CertificateVerify` 签名密钥一致时可开启；使用真实站点 fallback 证书时通常不满足该条件。
- `reality.replay_cache_max_entries`：重放缓存最大条目数（默认 `100000`，用于控制窗口内内存占用）。
- `reality.private_key` / `reality.public_key`：REALITY 密钥对（结构体默认空值；`socks config` 输出时会生成随机密钥对）。
- `reality.short_id`：短 ID。
- `reality.fallback_guard.enabled`：是否启用 fallback 防护（默认 `true`）。
- `reality.fallback_guard.rate_per_sec`：每 IP 每秒允许 fallback 次数（默认 `2`）。
- `reality.fallback_guard.burst`：每 IP 令牌桶突发上限（默认 `10`）。
- `reality.fallback_guard.circuit_fail_threshold`：触发熔断前连续失败次数（默认 `5`）。
- `reality.fallback_guard.circuit_open_sec`：熔断持续秒数（默认 `30`）。
- `reality.fallback_guard.state_ttl_sec`：fallback 防护状态保留秒数（默认 `600`）。

## 监控

- `monitor.enabled`：是否启用监控接口。
- `monitor.port`：监控端口（仅本机）。
- `monitor.token`：监控接口 token。
- `monitor.min_interval_ms`：最小请求间隔。

### fallback 失败原因指标

监控接口会输出以下 fallback 失败原因计数：

- `socks_fallback_no_target_total`
- `socks_fallback_resolve_failures_total`
- `socks_fallback_connect_failures_total`
- `socks_fallback_write_failures_total`

### 看板查询建议

推荐按 5 分钟窗口观察各失败原因增量：

```promql
increase(socks_fallback_no_target_total[5m])
increase(socks_fallback_resolve_failures_total[5m])
increase(socks_fallback_connect_failures_total[5m])
increase(socks_fallback_write_failures_total[5m])
```

可再补一个总失败增量面板：

```promql
increase(socks_fallback_no_target_total[5m])
+ increase(socks_fallback_resolve_failures_total[5m])
+ increase(socks_fallback_connect_failures_total[5m])
+ increase(socks_fallback_write_failures_total[5m])
```

### 告警规则样例

以下阈值为默认样例，建议按生产基线调整：

```yaml
groups:
  - name: socks-fallback-alerts
    rules:
      - alert: SocksFallbackNoTargetSpike
        expr: increase(socks_fallback_no_target_total[10m]) > 20
        for: 5m
      - alert: SocksFallbackResolveFailuresHigh
        expr: increase(socks_fallback_resolve_failures_total[10m]) > 10
        for: 5m
      - alert: SocksFallbackConnectFailuresHigh
        expr: increase(socks_fallback_connect_failures_total[10m]) > 20
        for: 5m
      - alert: SocksFallbackWriteFailuresHigh
        expr: increase(socks_fallback_write_failures_total[10m]) > 10
        for: 5m
```

## fallback

`fallbacks`：SNI 伪装回退列表（`sni` / `host` / `port`）。

## 测试脚本参数

`script/valgrind_test.py` 支持以下关键参数：

- `--traffic-count`：附加短连接探测次数，默认 `5`。
- `--server-ready-timeout`：等待服务端入站端口就绪超时秒数，默认 `20`。
- `--client-ready-timeout`：等待客户端 socks 端口就绪超时秒数，默认 `90`。

CI 中建议显式传入超时参数，避免不同执行机性能差异导致偶发超时：

```bash
python3 script/valgrind_test.py \
  --build-dir build_valgrind \
  --socks-bin ./socks \
  --server-ready-timeout 30 \
  --client-ready-timeout 120
```

## 分层测试执行（smoke/full）

使用 `script/run_test_tier.sh` 统一执行分层回归：

```bash
# 快速回归（本地开发默认）
bash script/run_test_tier.sh --tier smoke --build-dir build

# 全量回归（发布前/合并前）
bash script/run_test_tier.sh --tier full --build-dir build
```

可选参数：

- `--jobs`：指定并行度（默认读取 `TEST_JOBS` 或 `nproc`）。
- `SMOKE_TEST_REGEX`：覆盖 smoke 测试集合。
- `INTEGRATION_TEST_REGEX`：覆盖 integration 测试匹配规则（`--tier unit|integration` 使用）。

CI 策略：

- `pull_request` 默认执行 `smoke`，保证快速反馈。
- `push` 执行 `smoke + full`，保证主线全量回归。

## 推荐默认安全配置

1. `socks.host = 127.0.0.1`，并开启 `socks.auth`。
2. 配置合理 `max_connections` 与 `max_streams`。
4. 启用 `monitor.token`，避免无鉴权访问。
