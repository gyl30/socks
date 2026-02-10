# 部署拓扑

## 单机部署（开发/测试）

```
User App
   |
Local Client (SOCKS5)
   |
Remote Server (REALITY + MUX)
   |
Target
```

适用于本机验证、功能测试、开发调试。

## 客户端-服务端分离

```
User App ----> Client Host (SOCKS5 + REALITY Client)
                      |
                Internet
                      |
                Server Host (REALITY Server + MUX)
                      |
                   Target
```

建议对服务端进行隔离部署，并限制监听地址与端口访问范围。

## 关键部署建议

1. 服务端应限制入站端口，仅开放 REALITY 监听端口。
2. 监控接口建议仅本机访问，不开放到公网。
3. 客户端建议绑定本地回环地址并开启鉴权。
4. 若需要对外开放 SOCKS5，请确保鉴权启用并设置强密码。

## TPROXY 部署说明

TPROXY 仅支持 Linux，需具备 `CAP_NET_ADMIN` 权限（或以 root 运行）。本项目客户端已在出站连接上设置 `SO_MARK`，用于策略路由与避免回环。

### 基础策略路由

将 `fwmark` 指向本地路由表，保证被 TPROXY 标记的包进入本机透明监听。

```bash
ip rule add fwmark 0x11/0xff lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

ip -6 rule add fwmark 0x11/0xff lookup 100
ip -6 route add local ::/0 dev lo table 100
```

### iptables 规则示例

以下示例将目标流量透明导入 `tproxy.tcp_port`/`tproxy.udp_port`，并使用 `tproxy.mark`（默认 `0x11`）。请按需替换 `TPROXY_PORT` 与 `TPROXY_MARK`，并对服务端地址做排除。

```bash
TPROXY_PORT=1081
TPROXY_MARK=0x11

iptables -t mangle -N TPROXY_MUX
iptables -t mangle -A PREROUTING -j TPROXY_MUX

iptables -t mangle -A TPROXY_MUX -d <SERVER_IP> -j RETURN
iptables -t mangle -A TPROXY_MUX -p tcp -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
iptables -t mangle -A TPROXY_MUX -p udp -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
```

IPv6 规则：

```bash
ip6tables -t mangle -N TPROXY_MUX
ip6tables -t mangle -A PREROUTING -j TPROXY_MUX

ip6tables -t mangle -A TPROXY_MUX -d <SERVER_IPV6> -j RETURN
ip6tables -t mangle -A TPROXY_MUX -p tcp -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
ip6tables -t mangle -A TPROXY_MUX -p udp -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
```

### 仅转发 DNS 的 UDP 示例

如仅希望将 DNS UDP 导入 TPROXY，可加端口过滤。

```bash
iptables -t mangle -A TPROXY_MUX -p udp --dport 53 -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
```

### nftables 规则示例

```bash
nft add table inet tproxy
nft add chain inet tproxy prerouting { type filter hook prerouting priority mangle \\; }
nft add rule inet tproxy prerouting ip daddr <SERVER_IP> return
nft add rule inet tproxy prerouting meta l4proto tcp tproxy to :1081 meta mark set 0x11
nft add rule inet tproxy prerouting meta l4proto udp tproxy to :1081 meta mark set 0x11
```

### 权限与回环避免

1. 若使用非 root 运行，可考虑 `setcap cap_net_admin,cap_net_bind_service+ep <binary>`。
2. 请确保被代理流量不会再次被 TPROXY 捕获。通常通过 `tproxy.mark` + 策略路由实现回环规避，并在防火墙中排除服务端地址或直连网段。
