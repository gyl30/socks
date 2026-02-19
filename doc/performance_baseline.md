# 数据面性能基线（第4阶段）

## 采集脚本与命令

- 脚本：`script/perf_baseline.py`

ASAN（默认开发构建）：

```bash
python3 script/perf_baseline.py \
  --build-dir build \
  --socks-bin ./socks \
  --iterations 2000 \
  --payload-size 1024 \
  --out-json build/perf_baseline_latest.json
```

Release（关闭 ASAN）：

```bash
cmake -S . -B build_release_perf -DENABLE_ASAN=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build_release_perf -j15 --target socks
python3 script/perf_baseline.py \
  --build-dir build_release_perf \
  --socks-bin ./socks \
  --iterations 2000 \
  --payload-size 1024 \
  --out-json build_release_perf/perf_baseline_latest.json
```

## 压测场景

1. 启动本地 TCP/UDP 回显服务。
2. 启动 `socks` server/client（REALITY + MUX）。
3. TCP：通过 SOCKS5 CONNECT 执行 2000 次 1KB 请求-应答，统计 RTT 与吞吐。
4. UDP：通过 SOCKS5 UDP ASSOCIATE 执行 2000 次 1KB 报文，统计 RTT、吞吐、丢包。
5. 采样 socks server/client 进程 CPU time 与峰值 RSS。

## 基线 A（ASAN）

- 时间：2026-02-19 10:32:28
- 输出：`build/perf_baseline_latest.json`

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

## 基线 B（Release, ENABLE_ASAN=OFF）

- 时间：2026-02-19 10:39:18
- 输出：`build_release_perf/perf_baseline_latest.json`

| 维度 | 指标 | 数值 |
| --- | --- | --- |
| TCP | 吞吐（Mbps） | 3.561 |
| TCP | RTT 平均（ms） | 2.300 |
| TCP | RTT P50/P95/P99（ms） | 2.387 / 5.834 / 8.664 |
| TCP | 丢包率 | 0.00000 |
| UDP | 吞吐（Mbps） | 129.934 |
| UDP | RTT 平均（ms） | 0.062 |
| UDP | RTT P50/P95/P99（ms） | 0.053 / 0.098 / 0.283 |
| UDP | 丢包率 | 0.00000 |
| 进程资源 | 总 CPU time（s） | 12.640 |
| 进程资源 | 总 CPU 利用率（%） | 217.79 |
| 进程资源 | 总峰值 RSS（MB） | 3394.281 |
| 进程资源 | server/client 峰值 RSS（MB） | 1917.539 / 1476.742 |

## 对照增量（B 对比 A）

| 指标 | A（ASAN） | B（Release） | 变化 |
| --- | --- | --- | --- |
| TCP 吞吐（Mbps） | 1.110 | 3.561 | +220.81% |
| TCP RTT P95（ms） | 9.215 | 5.834 | -36.69% |
| UDP 吞吐（Mbps） | 2.109 | 129.934 | +6060.93% |
| UDP RTT P95（ms） | 11.251 | 0.098 | -99.13% |
| UDP RTT P99（ms） | 12.624 | 0.283 | -97.76% |
| 总峰值 RSS（MB） | 6820.590 | 3394.281 | -50.23% |
| 总 CPU 利用率（%） | 214.44 | 217.79 | +1.56% |

## 注意事项

1. A 与 B 仅用于同机、同脚本、同参数下的相对比较，不作为跨机器绝对性能结论。
2. 后续每次数据面优化完成后，建议同时更新 A/B 两组数据，保持趋势可追踪。
