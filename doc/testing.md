# 测试流程

本项目测试分为构建、单元测试与集成测试三部分。

## 构建

```bash
cmake -S . -Bbuild && cmake --build build -j12
```

## 单元测试

```bash
ctest --test-dir build -j12 --output-on-failure
```

## TPROXY 手工验证

TPROXY 需要 Linux 与 `CAP_NET_ADMIN`。建议先将 `timeout.idle` 调整为较小值（如 30 秒）以便观察会话回收。

1. 配置客户端（`mode=client`）
   - `tproxy.enabled=true`
   - `tproxy.tcp_port=1081`
   - `tproxy.udp_port=0`
   - `tproxy.mark=0x11`
   - `tproxy.listen_host="::"`
2. 配置策略路由与防火墙
   - 参见 `doc/deployment.md` 中的 TPROXY 规则示例
3. TCP 测试
   - `curl http://example.com`
4. UDP 测试（DNS）
   - `dig @8.8.8.8 example.com`
5. 回收验证
   - 等待 `timeout.idle + 5s` 后再次发起 DNS 请求，应看到新会话创建

## 注意事项

1. 测试前确保端口未被占用（如 1080/8844/9999/8888/14443/14444/14445）。
2. 集成测试会启动本地假 TLS 与 Echo 服务。
3. 若单测失败，优先查看对应测试日志与错误输出。
