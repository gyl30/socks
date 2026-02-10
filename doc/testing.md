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

## 集成测试

```bash
python3 script/comprehensive_test.py
python3 script/setup_and_run_other_tests.py
```

如需在综合测试中运行 TPROXY 全链路校验：

```bash
sudo env RUN_TPROXY=1 python3 script/comprehensive_test.py
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

## TPROXY CI 草案

若 CI 允许 `CAP_NET_ADMIN` 或特权容器，可直接运行脚本：

```bash
sudo script/ci_tproxy_test.sh
```

全链路模式（客户端 tproxy -> 远端 server -> 目标服务）：

```bash
sudo script/ci_tproxy_test.sh --full
```

或使用环境变量（注意 sudo 需要保留环境变量）：

```bash
sudo env FULL_CHAIN=1 script/ci_tproxy_test.sh
```

脚本会在 server netns 启动 `remote_server`，并自动生成临时密钥对用于 reality 握手；全链路模式会额外启动一个本地 TLS 服务用于证书抓取（无需外网 DNS），依赖 `openssl` 命令。

脚本内置：
1. 创建 client/proxy/server 三个 netns 与两组 veth，不修改宿主机 iptables。
2. 在 server netns 启动 TCP/UDP echo 服务，client netns 发起请求。
3. 配置 `ip rule` 与 `iptables TPROXY` 规则。
4. 发起 TCP/UDP 请求并校验响应内容。
5. 等待 `timeout.idle` 超时后重复 UDP 请求。

默认使用 `TPROXY_MARK=0x11` 作为透明接管标记，`OUTBOUND_MARK=18` 作为代理出站标记，避免策略路由回环。`OUTBOUND_MARK` 可用十六进制（如 `0x12`），脚本会转换为十进制写入配置。

提示：CI 环境如无法授予权限，可仅保留单元测试覆盖。

## 注意事项

1. 测试前确保端口未被占用（如 1080/8844/9999/8888/14443/14444/14445）。
2. 集成测试会启动本地假 TLS 与 Echo 服务。
3. 若单测失败，优先查看对应测试日志与错误输出。
