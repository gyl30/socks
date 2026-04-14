# socks

一个使用 C++23 实现的代理程序，支持 Reality、SOCKS5、TPROXY 和 TUN 入站。

## 服务端配置

```json
{
  "mode": "server",
  "workers": 0,
  "log": {
    "level": "info",
    "file": "app.log"
  },
  "inbound": {
    "host": "0.0.0.0",
    "port": 443
  },
  "socks": {
    "enabled": false
  },
  "reality": {
    "sni": "www.example.com",
    "max_handshake_records": 256,
    "private_key": "替换为服务端私钥",
    "public_key": "替换为服务端公钥",
    "short_id": "0102030405060708"
  },
  "timeout": {
    "read": 100,
    "write": 100,
    "connect": 10,
    "idle": 300
  }
}
```

## 客户端配置

```json
{
  "mode": "client",
  "workers": 0,
  "log": {
    "level": "info",
    "file": "app.log"
  },
  "outbound": {
    "host": "你的服务端地址",
    "port": 443
  },
  "socks": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 1080,
    "auth": false,
    "username": "",
    "password": ""
  },
  "tproxy": {
    "enabled": false,
    "listen_host": "::",
    "tcp_port": 1081,
    "udp_port": 0,
    "mark": 17
  },
  "tun": {
    "enabled": false,
    "name": "socks-tun",
    "mtu": 1500,
    "ipv4": "198.18.0.1",
    "ipv4_prefix": 32,
    "ipv6": "fd00::1",
    "ipv6_prefix": 128
  },
  "reality": {
    "sni": "www.example.com",
    "fingerprint": "random",
    "max_handshake_records": 256,
    "public_key": "替换为服务端公钥",
    "short_id": "0102030405060708"
  },
  "timeout": {
    "read": 100,
    "write": 100,
    "connect": 10,
    "idle": 300
  }
}
```

## 关键配置项

- `private_key` 和 `public_key`：执行 `./build/socks x25519` 生成一对密钥。服务端使用生成出的 `private key` 和 `public key`，客户端只填写同一组里的 `public key`。
- `short_id`：客户端和服务端必须一致，使用 16 个十六进制字符，例如 `0102030405060708`。
- `reality.sni`：客户端和服务端必须一致，填写你要伪装的域名，例如 `www.example.com`。
- `inbound.host` 和 `inbound.port`：服务端监听地址和端口。
- `outbound.host` 和 `outbound.port`：客户端连接到服务端的地址和端口，应与服务端监听地址对应。
- `socks.host` 和 `socks.port`：客户端本地 SOCKS5 监听地址和端口。
- `socks`、`tproxy`、`tun` 三种客户端入站可以按需单独启用，也可以同时启用；同时启用时建议让不同入口处理不同流量域，并配套独立的策略路由或透明代理规则，未使用的入站保持 `enabled: false`。
