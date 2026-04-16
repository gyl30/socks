# 代理系统当前流程图

## 1. 核心约束

- `route=proxy` 时不再复用隧道。
- 一个 TCP 代理请求对应一条 `proxy_reality_connection`。
- 一个 UDP 代理会话对应一条 `udp_proxy_outbound -> proxy_reality_connection`。
- 服务端通过 `reality_inbound` 完成 REALITY 认证后，只处理一个代理会话。
- UDP 仍保留 `udp_datagram` framing，用来保存报文边界；它只负责报文边界，不承担连接复用。
- 域名解析统一使用系统 dns，不引入自定义 dns 组件。

## 2. 总体架构与数据流

当前 TCP/UDP 主路径已经收敛到四个公共模块：
- `tcp_connect_flow`：统一处理目标识别、路由决策、出站实例创建。
- `udp_session_flow`：统一处理 UDP 路由决策、模式选择、代理出站建立。
- `stream_relay`：统一处理 `socket <-> tcp_outbound_stream` 的双向转发与 idle watchdog。
- `datagram_relay`：统一处理 UDP 回包循环、代理回包循环与 idle watchdog。

```mermaid
flowchart TD
  App[客户端应用] -->|TCP/UDP| Inbound{SOCKS5 / TPROXY / TUN}

  Inbound -->|SOCKS5| SocksProto["socks_session -> socks_protocol_session"]
  SocksProto -->|CONNECT| SocksTcp["socks_tcp_session"]
  SocksProto -->|UDP ASSOCIATE| SocksUdp["socks_udp_session"]
  Inbound -->|TPROXY TCP| TproxyTcp["tproxy_inbound -> tproxy_tcp_session"]
  Inbound -->|TPROXY UDP| TproxyUdp["tproxy_inbound -> tproxy_udp_session"]
  Inbound -->|TUN TCP| TunTcp["tun_inbound -> tun_tcp_session"]
  Inbound -->|TUN UDP| TunUdp["tun_inbound -> tun_udp_session"]

  SocksTcp --> TcpFlow[tcp_connect_flow]
  TproxyTcp --> TcpFlow
  TunTcp --> TcpFlow
  SocksUdp --> UdpFlow[udp_session_flow]
  TproxyUdp --> UdpFlow
  TunUdp --> UdpFlow
  TcpFlow --> Router[router]
  UdpFlow --> Router

  Router -->|direct,tcp| DirectTcp[direct_tcp_outbound]
  Router -->|direct,udp| DirectUdp[direct UDP socket]
  Router -->|proxy,tcp| ProxyTcp[proxy_tcp_outbound]
  Router -->|proxy,udp| ProxyUdp[udp_proxy_outbound]
  Router -->|block| Block[拒绝 / 丢弃]

  DirectTcp --> Target[目标服务]
  DirectUdp --> Target

  ProxyTcp --> ClientConnTcp[proxy_reality_connection]
  ProxyUdp --> ClientConnUdp[proxy_reality_connection]
  ClientConnTcp --> ClientReality["reality_engine (client)"]
  ClientConnUdp --> ClientReality
  ClientReality <--> Network[公网 TCP 连接]
  Network <--> ServerReality["reality_engine (server)"]
  ServerReality --> ServerConn["proxy_reality_connection (server)"]
  ServerConn --> RealityInbound[reality_inbound]
  RealityInbound --> RealityProto["reality_protocol_session"]
  RealityProto --> RealityTcp[reality_tcp_session]
  RealityProto --> RealityUdp[reality_udp_session]
  RealityTcp --> TcpFlow
  RealityUdp --> UdpFlow

  Block -.-> Note1["不再存在旧的连接池 / 复用层 / stream 管理器"]
```

## 3. TCP 正常流程

```mermaid
sequenceDiagram
  autonumber
  participant App as Client App
  participant Inb as Inbound
  participant Flow as tcp_connect_flow
  participant Router as router
  participant Up as direct_tcp_outbound / proxy_tcp_outbound
  participant Conn as proxy_reality_connection
  participant Server as reality_inbound
  participant Proto as reality_protocol_session
  participant RTcp as reality_tcp_session
  participant Target as Target

  App->>Inb: TCP connect / CONNECT
  Inb->>Flow: request_context
  Flow->>Router: decide_ip / decide_domain

  alt route=direct
    Flow->>Up: direct_tcp_outbound.connect
    Up->>Target: TCP connect
    Target-->>Up: connected
    Up-->>Flow: success
    Flow-->>Inb: connect ok
    Inb-->>App: success / reply
    loop 双向转发
      App->>Inb: data
      Inb->>Up: write(data)
      Target->>Up: data
      Up->>Inb: read(data)
      Inb->>App: data
    end
  else route=proxy
    Flow->>Up: proxy_tcp_outbound.connect
    Up->>Conn: connect()
    Conn->>Server: REALITY handshake
    Up->>Conn: tcp_connect_request
    Conn->>Server: encrypted request
    Server->>Proto: start(request)
    Proto->>RTcp: start(request)
    RTcp->>Flow: request_context
    Flow->>Target: resolve + connect

    alt connect fail
      RTcp->>Server: tcp_connect_reply(fail)
      Server->>Conn: encrypted reply
      Conn->>Up: tcp_connect_reply(fail)
      Up-->>Flow: connect failed
      Flow-->>Inb: connect failed
      Inb-->>App: error reply
    else connect ok
      RTcp->>Server: tcp_connect_reply(success, bind)
      Server->>Conn: encrypted reply
      Conn->>Up: tcp_connect_reply(success)
      Up-->>Flow: connect ok
      Flow-->>Inb: connect ok
      Inb-->>App: success / reply

      loop 双向转发
        App->>Inb: data
        Inb->>Up: write(data)
        Up->>Conn: write(plaintext)
        Conn->>Server: encrypted application data
        Server->>RTcp: relay to target
        Target->>RTcp: data
        RTcp->>Server: relay to client
        Server->>Conn: encrypted application data
        Conn->>Up: read(plaintext)
        Up->>Inb: data
        Inb->>App: data
      end
    end
  end
```

## 4. UDP 正常流程

```mermaid
sequenceDiagram
  autonumber
  participant App as Client App
  participant Inb as Inbound
  participant Flow as udp_session_flow
  participant Router as router
  participant Direct as direct UDP socket
  participant ProxyUdp as udp_proxy_outbound
  participant Conn as proxy_reality_connection
  participant Server as reality_inbound
  participant Proto as reality_protocol_session
  participant RUdp as reality_udp_session
  participant Target as Target

  App->>Inb: UDP 数据包
  Inb->>Flow: request_context
  Flow->>Router: decide_ip / decide_domain

  alt route=direct
    Flow->>Direct: sendto(target)
    Target-->>Direct: UDP reply
    Direct-->>Flow: reply
    Flow-->>Inb: reply
    Inb-->>App: reply
  else route=proxy
    Flow->>ProxyUdp: connect()
    ProxyUdp->>Conn: connect()
    Conn->>Server: REALITY handshake
    ProxyUdp->>Conn: udp_associate_request
    Conn->>Server: encrypted request
    Server->>Proto: start(request)
    Proto->>RUdp: start(request)
    RUdp->>Server: udp_associate_reply
    Server->>Conn: encrypted reply
    Conn->>ProxyUdp: udp_associate_reply

    Inb->>Flow: send_datagram(host, port, payload)
    Flow->>ProxyUdp: send_datagram(host, port, payload)
    ProxyUdp->>Conn: udp_datagram
    Conn->>Server: encrypted datagram
    Server->>RUdp: sendto(target)
    Target-->>RUdp: UDP reply
    RUdp-->>Server: udp_datagram
    Server-->>Conn: encrypted datagram
    Conn-->>ProxyUdp: udp_datagram
    ProxyUdp-->>Flow: reply
    Flow-->>Inb: reply
    Inb-->>App: reply
  end
```

## 5. 生命周期与异常路径

```mermaid
flowchart TD
  Start[收到代理请求] --> Route{路由结果}

  Route -->|block| Reject[拒绝 / 丢弃]
  Route -->|direct| Direct[直接建立 TCP/UDP 出口]
  Route -->|proxy| NewConn[新建 proxy_reality_connection]

  NewConn -->|握手失败| HandshakeFail[返回错误并关闭]
  NewConn -->|TCP| TcpReq[tcp_connect_request]
  NewConn -->|UDP| UdpReq[udp_associate_request]

  TcpReq -->|connect fail| TcpFail[tcp_connect_reply(fail)]
  TcpReq -->|connect ok| TcpRelay[TCP 双向转发]

  UdpReq -->|associate fail| UdpFail[udp_associate_reply(fail)]
  UdpReq -->|associate ok| UdpRelay[udp_datagram 往返转发]

  TcpRelay -->|EOF| HalfClose[shutdown_send 另一侧]
  TcpRelay -->|read/write error| CloseConn[关闭整条 REALITY 连接]
  TcpRelay -->|idle timeout| CloseConn

  UdpRelay -->|idle timeout| CloseConn
  UdpRelay -->|非法报文 / payload 过大| DropOrClose[丢弃或关闭]

  note1["没有复用会话标识、旧式控制帧、预建隧道恢复逻辑"]
  CloseConn -.-> note1
```

## 6. TUN 路径

```mermaid
flowchart TD
  App[客户端应用] --> Kernel[内核路由]
  Kernel --> TunDev[TUN 设备]
  TunDev --> TunInbound["tun_inbound.read_loop"]
  TunInbound --> Lwip["tun_lwip / lwIP"]

  Lwip -->|TCP| TunTcp[tun_tcp_session]
  Lwip -->|UDP| TunUdp[tun_udp_session]

  TunTcp --> TcpFlow[tcp_connect_flow]
  TunUdp --> UdpFlow[udp_session_flow]

  TcpFlow --> Router[router]
  UdpFlow --> Router

  Router -->|direct| Direct[direct_tcp_outbound / direct UDP socket]
  Router -->|proxy,tcp| ProxyTcp[proxy_tcp_outbound]
  Router -->|proxy,udp| ProxyUdp[udp_proxy_outbound]
  Router -->|block| Block[丢弃 / RST / ICMP]

  Direct --> Target[目标服务]
  ProxyTcp --> ConnTcp[proxy_reality_connection]
  ProxyUdp --> ConnUdp[proxy_reality_connection]
  ConnTcp --> Target
  ConnUdp --> Target
```

## 7. 与旧架构的区别

- 客户端不再预建长期 REALITY 隧道。
- 服务端不再在一条连接上承载多个并发子会话。
- TCP 关闭语义回到“连接即会话”，半关闭直接依赖 `shutdown_send`。
- UDP 仍然有内部报文封装，但只保留 `udp_associate_reply` 和 `udp_datagram` 这类单会话协议消息。

## 8. 当前运行时清理基线

- 已删除旧的预建隧道、连接复用和控制帧实现。
- 已删除旧的 `connection_tracker` 和只增减不读取的连接守卫。
- `route=proxy` 时，TCP 请求和 UDP 会话都直接新建 `proxy_reality_connection`，不再存在预建隧道槽位。
- `socks_session` 已拆出 `socks_protocol_session`，`reality_inbound` 已拆出 `reality_protocol_session`。
- `socks_tcp_session`、`reality_tcp_session`、`tproxy_tcp_session`、`tun_tcp_session` 已接入统一 `tcp_connect_flow`。
- `socks_udp_session`、`reality_udp_session`、`tproxy_udp_session`、`tun_udp_session` 已接入统一 `udp_session_flow`。
- `socks_tcp_session`、`reality_tcp_session`、`tproxy_tcp_session` 已接入统一 `stream_relay`。
- 四条 UDP 会话路径都已经复用 `datagram_relay` 的公共收包、回包与 idle watchdog 编排能力。
- 连接关闭和正常收尾错误判断统一收敛到 `net_utils`：
  `is_basic_close_error`、`is_socket_close_error`、`is_socket_shutdown_error`、`is_channel_close_error`。
- 日志统一使用 `log_event::kRelay`，语义与当前架构一致。

## 9. 严格告警验证

- 构建系统新增了 `ENABLE_STRICT_WARNINGS` 开关，默认关闭，不影响日常构建。
- 当前严格告警集包含：
  `-Wshadow`、`-Wpedantic`、`-Wcast-qual`、`-Wold-style-cast`、`-Wsign-conversion`
- 推荐用单独构建目录验证：

```bash
cmake -S . -B build-gcc-strict \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DENABLE_ASAN=OFF \
  -DENABLE_TSAN=OFF \
  -DENABLE_LSAN=OFF \
  -DENABLE_STRICT_WARNINGS=ON \
  -DOPENSSL_ROOT_DIR=/home/gyl/openssl \
  -DBOOST_ROOT=/home/gyl/boost_1_89_0
cmake --build build-gcc-strict -j8
```

```bash
cmake -S . -B build-clang-strict \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_ASAN=OFF \
  -DENABLE_TSAN=OFF \
  -DENABLE_LSAN=OFF \
  -DENABLE_STRICT_WARNINGS=ON \
  -DOPENSSL_ROOT_DIR=/home/gyl/openssl \
  -DBOOST_ROOT=/home/gyl/boost_1_89_0
cmake --build build-clang-strict -j8
```

- 当前代码在 GCC 和 Clang 下都已通过这组 stricter warnings 的全量编译。
