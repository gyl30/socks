# 数据面性能基线（第4阶段）

## 采集时间

- 2026-02-19 10:32:28（本地开发环境）

## 采集脚本与命令

- 脚本：`script/perf_baseline.py`
- 输出：`build/perf_baseline_latest.json`
- 执行命令：

```bash
python3 script/perf_baseline.py \
  --build-dir build \
  --socks-bin ./socks \
  --iterations 2000 \
  --payload-size 1024 \
  --out-json build/perf_baseline_latest.json
```

## 压测场景

1. 启动本地 TCP/UDP 回显服务。
2. 启动 `socks` server/client（REALITY + MUX）。
3. TCP：通过 SOCKS5 CONNECT 执行 2000 次 1KB 请求-应答，统计 RTT 与吞吐。
4. UDP：通过 SOCKS5 UDP ASSOCIATE 执行 2000 次 1KB 报文，统计 RTT、吞吐、丢包。
5. 采样 socks server/client 进程 CPU time 与峰值 RSS。

## 基线结果

| 维度 | 指标 | 数值 |
| --- | --- | --- |
| TCP | 吞吐（Mbps） | 1.110 |
| TCP | RTT 平均（ms） | 7.377 |
| TCP | RTT P50/P95/P99（ms） | 6.574 / 9.215 / 16.085 |
| TCP | 丢包率 | 0.00000 |
| UDP | 吞吐（Mbps） | 2.109 |
| UDP | RTT 平均（ms） | 3.881 |
| UDP | RTT P50/P95/P99（ms） | 0.163 / 11.251 / 12.624 |
| UDP | 丢包率 | 0.00000 |
| 进程资源 | 总 CPU time（s） | 51.240 |
| 进程资源 | 总 CPU 利用率（%） | 214.44 |
| 进程资源 | 总峰值 RSS（MB） | 6820.590 |
| 进程资源 | server/client 峰值 RSS（MB） | 3433.109 / 3387.480 |

## 结果解读与注意事项

1. 当前 `build` 目录使用 ASAN 构建，内存指标会明显高于发布构建，RSS 仅作为“同构建配置下”的相对对比基线。
2. 后续性能优化应使用同一脚本、同一参数重复采集，并与本文件表格对比增量（吞吐、RTT、丢包、CPU、RSS）。
3. 若切换到 Release 构建，需重新生成一份独立基线，避免跨构建类型横向比较。
