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
