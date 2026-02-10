# 配置说明

配置文件通过 `config` 结构体反射生成，字段按模块分组如下。

## 基础字段

- `mode`：运行模式（默认 `server`）。
- `log.level` / `log.file`：日志等级与输出文件。

## 网络入口

- `inbound.host` / `inbound.port`：服务端监听地址与端口。
- `outbound.host` / `outbound.port`：客户端连接地址与端口。
- `socks.enabled`：是否启用 SOCKS5 入站（默认 `true`）。
- `socks.host` / `socks.port`：本地 SOCKS5 监听地址与端口。
- `socks.auth` / `socks.username` / `socks.password`：SOCKS5 认证配置。
- `tproxy.enabled`：是否启用 TPROXY 入站（默认 `false`）。
- `tproxy.listen_host`：TPROXY 监听地址（默认 `::`）。
- `tproxy.tcp_port` / `tproxy.udp_port`：TPROXY TCP/UDP 端口。`udp_port = 0` 表示跟随 `tcp_port`。
- `tproxy.mark`：TPROXY `SO_MARK`，用于路由/回避回环（默认 `0x11`）。

## 传输与超时

- `timeout.read` / `timeout.write` / `timeout.idle`：读写与空闲超时秒数。
- `heartbeat.enabled`：是否启用心跳。
- `heartbeat.idle_timeout`：空闲多久触发心跳。
- `heartbeat.min_interval` / `heartbeat.max_interval`：心跳随机间隔。
- `heartbeat.min_padding` / `heartbeat.max_padding`：心跳填充长度范围。

## 限制与保护

- `limits.max_connections`：服务端隧道最大并发数。
- `limits.max_streams`：单连接 stream 最大数量。
- `limits.max_buffer`：mux dispatcher 最大缓冲区。

## REALITY

- `reality.sni`：伪装 SNI。
- `reality.fingerprint`：客户端指纹（默认 `random`）。
  - 可选值：`random`、`chrome`、`firefox`、`ios`、`android`（分别映射到 `chrome_120` / `firefox_120` / `ios_14` / `android_11_okhttp`）。
- `reality.dest`：回落目标（格式 `host:port`）。
- `reality.type`：回落网络类型（默认 `tcp`）。
- `reality.private_key` / `reality.public_key`：REALITY 密钥对。
- `reality.short_id`：短 ID。

## 监控

- `monitor.enabled`：是否启用监控接口。
- `monitor.port`：监控端口（仅本机）。
- `monitor.token`：监控接口 token。
- `monitor.min_interval_ms`：最小请求间隔。

## fallback

`fallbacks`：SNI 伪装回退列表（`sni` / `host` / `port`）。

## 推荐默认安全配置

1. `socks.host = 127.0.0.1`，并开启 `socks.auth`。
2. 配置合理 `max_connections` 与 `max_streams`。
4. 启用 `monitor.token`，避免无鉴权访问。
