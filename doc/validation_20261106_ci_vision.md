# 2026-11-06 CI 与 REALITY/Vision 验证

## 1. 当前基线

- 仓库：`gyl30/socks`；分支 `main`；本地 HEAD 与 `git ls-remote origin refs/heads/main` 均为 `6bd4743e71c677f45337eb0aff48b8007b45edc5`。
- 初始暂存区为空；已有未提交修改为 `.github/workflows/ci.yml`（macos-15）和 `scripts/test_proxy_udp_stale_budget.py`（发送时序修正）。保留两项；后者本轮未修改。
- Linux x86_64，Intel i7-13700KF；重复负载固定 CPU 0–3。Clang 23.0.0、OpenSSL 3.6.0、本地 Boost 1.92.0，Release，无 ASan/TSan。CI 的 Boost 1.89.0 未升级，本地结果不能替代该依赖组合的 macOS 验证。
- 被测 socks SHA256：`52807dd911136e97d944df876545ce07f89ad982c9b8f454f89c83285c57bf85`；修改前后相同。
- 本项目使用自定义 REALITY TCP 协议及内部 Vision；本轮没有进行 VLESS/Xray 互通，也不据此声称兼容 Xray。

## 2. macOS CI

**CONFIRMED；修改待验证，BLOCKED。** 最新运行仍为 [42036720396](https://github.com/gyl30/socks/actions/runs/42036720396)，对应基线提交。8 个 Linux 矩阵及 Windows 成功；macOS job `127276674538` 在 Install Dependencies 失败，未进入项目编译。

日志显示 macOS 14 为 Homebrew Tier 3、z3 5.3.3 源码构建失败，随后 LLVM 安装报 `/opt/homebrew/opt/z3 not present or broken`。过滤日志保留于 `.cache/maintenance-20261106/macos-job-evidence.log`。

保留初始 `runs-on: macos-15` 修改；仅将 macOS Boost、OpenSSL、ccache 的精确键及恢复前缀增加 `macos-15`，避免恢复旧系统缓存。保留 `CCACHE_COMPILERCHECK=content`，编译器内容变化将使旧编译结果失效。未修改生产 C++、Homebrew 源码、依赖版本或 Linux/Windows 工作流。

[GitHub runner 文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)将公开仓库 `macos-15` 列为 ARM64；[Homebrew LLVM](https://formulae.brew.sh/formula/llvm)提供 ARM64 Sequoia bottle。OpenSSL 仍为 3.6.0 的 `darwin64-arm64-cc` 路径；Boost 仍为 1.89.0 头文件依赖。上述为静态核对，不能证明真实 CI 构建成功。

本机无 macOS，且本轮未获提交/推送授权，未发布工作流修改或触发新提交 CI。需后续授权推送后，确认依赖安装、OpenSSL 构建及项目构建均成功。

## 3. Vision 负载测试

固定每个场景 4 MiB/请求、并发 8、每 worker 2 次请求，另有 5 次顺序延迟探针。修改前连续 **20/20**，修改后连续 **20/20**；同一主程序、CPU 亲和及请求参数。原有相对吞吐下限（baseline 的 60%）、请求超时、字节数检查和 256 MiB RSS 上限保留；未提高任何阈值。

吞吐 MiB/s，最小 / 中位 / 最大：

| 场景 | 修改前 20 轮 | 修改后 20 轮 |
| --- | --- | --- |
| TLS 1.3 Vision Direct | 333.07 / 368.79 / 388.13 | 350.49 / 372.60 / 390.30 |
| TLS 1.2 Vision fallback | 296.64 / 310.46 / 327.40 | 308.47 / 319.70 / 336.47 |
| REALITY TLS 1.3 baseline | 287.47 / 303.48 / 327.57 | 292.41 / 308.75 / 325.11 |

没有生产性能改动，不将差异解释为性能提升。修改后每轮并发请求中位数的跨轮分布（最小 / 中位 / 最大，ms）：

| 场景 | appconnect | appconnect − connect | 首字节等待 | 请求耗时 | 单请求最大值 |
| --- | --- | --- | --- | --- | --- |
| Direct | 10.867 / 11.927 / 13.393 | 5.865 / 7.106 / 9.268 | 1.799 / 3.118 / 4.543 | 63.925 / 73.856 / 80.384 | 94.988 |
| fallback | 11.903 / 13.892 / 15.170 | 7.060 / 8.837 / 10.784 | 0.930 / 1.824 / 2.997 | 69.651 / 86.528 / 93.509 | 109.588 |
| baseline | 10.514 / 13.157 / 14.885 | 5.857 / 7.966 / 9.955 | 1.906 / 2.838 / 4.673 | 78.226 / 89.279 / 103.248 | 111.973 |

`appconnect` 是 curl 连接及 TLS 完成时间；减去 `connect` 后仍包含 SOCKS 协商和代理初始化，不是纯 TLS 加密握手耗时。首字节等待为 `starttransfer − appconnect`，包含 origin 处理。没有将这些值描述为精确的 socket 写停顿。

逐轮数据见 [vision_load_20261106.csv](vision_load_20261106.csv)：120 行，前后各 20 轮 × 3 场景。注意旧版本没有并发延迟中位数字段，before 的 setup/首字节中位数来自顺序探针、最大 setup 来自并发；after 均来自并发。不能直接比较这些不同采样口径的延迟。原始顺序探针及并发汇总保存在 `.cache/maintenance-20261106/{before,after}/rounds.json` 及其引用的仓库内临时目录。

### 确定性 RED / GREEN

**FIXED：旧测试将 origin 延迟错误归因为写停顿。** 受控 HTTPS origin 分别在 TLS 开始前、响应前延迟 50 ms；每项仍完成 5 次真实 4 MiB 传输。`strace -f -e trace=setsockopt` 确认真实 socket 成功启用 TCP_NODELAY。

- 无延迟控制组通过。
- TLS 前延迟：旧断言以 appconnect 中位数 55.621 ms 报 `write stall detected`。
- 响应前延迟：旧断言以首字节等待中位数 50.646 ms 报同样错误。
- 新版本完整记录延迟并标记原 30/20 ms 预算超限，不作无依据的 TCP 归因；三组真实传输均通过。
- 单元回归修复前 3 项中 1 项报错，修复后 3/3；真实传输失败及字节数不符仍失败。

证据：`.cache/maintenance-20261106/latency-proof.log`、`latency-proof-socket.log`、`latency-proof-green.log`、`metrics-red.log`、`metrics-green.log`；受控实验脚本为同目录 `prove_latency-before.py`、`prove_latency.py`。诊断使用 strace，不新增 CI 依赖。

新增 Linux 链接器 syscall 包装回归，通过公开 connect 接口建立真实 loopback 连接并读取 ClientHello：正常 getsockopt 验证 TCP_NODELAY=1；注入 ENOPROTOOPT 时验证仍按原策略警告并继续握手，socket 值为 0。该测试替代错误的延迟因果推断，并不声称测出了所有写停顿。其他平台不运行这项 Linux 专属注入。

Direct 检查加强为客户端及服务端均出现 raw-read、raw-write；fallback 两端均不得出现 raw。20 轮修改后均通过，三场景峰值 RSS 分别 14.69、14.78、14.76 MiB。普通重复未复现生产链路不稳定；有限本地样本不能保证所有 CI 调度条件下永不失败。

## 4. 生产代码修改

**未修改生产 C++。** `proxy_reality_connection.cpp` 当前 TCP_NODELAY 失败为警告后继续，符合可选性能设置策略。没有证据支持修改 `vision_tcp.cpp` 或连接状态机。

本轮修改 CI 缓存键、负载测量和更严格 Direct 断言、Linux socket 正常/失败路径测试、测量单元测试及 CMake 注册；不增加生产状态、重试或协议能力。

## 5. 回归命令与结果

以下命令均在 socks 仓库执行，日志位于 `.cache/maintenance-20261106/`：

```bash
cmake -S . -B .cache/maintenance-20261106/build -GNinja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_ASAN=OFF -DENABLE_TSAN=OFF -DOPENSSL_ROOT_DIR=/home/gyl/openssl
cmake --build .cache/maintenance-20261106/build -j4
python3 .cache/maintenance-20261106/repeat_load.py before
python3 .cache/maintenance-20261106/repeat_load.py after
python3 scripts/test_reality_vision_load_metrics.py
unshare -Urnm sh -c 'ip link set lo up; exec env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy -u NO_PROXY -u no_proxy taskset -c 0-3 ctest --test-dir .cache/maintenance-20261106/build --output-on-failure'
unshare -Urnm sh -c 'ip link set lo up; KEEP_TEST_ARTIFACTS=1 exec bash scripts/test_socks5.sh "$PWD/.cache/maintenance-20261106/build/socks"'
git diff --check
```

before 命令运行时脚本尚未修复；当前重复执行将使用新脚本。被测主程序版本为本报告基线构建，SHA256 见上；测试代码包含本轮未提交修改。

配置和构建通过；SOCKS5 shell 集成通过。完整 CTest 初轮 35/36：trace_web_integration 的 curl 继承宿主代理，访问 loopback 时转向隔离 namespace 内不存在的 10081 端口。保留 `ctest.log` 原始失败，清除测试进程代理变量后复验，不更改宿主配置。最终复验结果见下方验收记录。

既有回归涵盖 REALITY 握手/协议失败，Vision TLS1.3 双向 Direct、TLS1.2 fallback、padding/raw 边界、EOF/half-close、取消/超时、SOCKS5 成功/拒绝、UDP 正常转发及控制连接关闭。UDP transparent CTest 为既有测试覆盖，不冒充真实宿主 TPROXY 拓扑验收。本轮无宿主路由、防火墙、sysctl 或其他项目修改。

## 6. 遗留问题

- P2 **CONFIRMED / BLOCKED**：已发布 macOS CI 的 Homebrew 依赖安装失败。本地 runner/cache 修改尚未经过真实 macOS CI。
- **FIXED**：端到端延迟被错误判为写停顿；不是已确认的生产 Nagle 缺陷。
- **NOT REPRODUCED**：普通负载间歇失败，本机前后各 20/20；CI 条件下的长期稳定性仍无充分证据。
- 初轮 trace_web 失败是隔离测试进程继承代理的环境问题，不修改项目实现。

## 7. Git 状态与验收

保留原有两项未提交修改；没有暂存、提交、推送或部署。最终状态以交付时 `git status --short` 为准。

最终验收记录：

- 清除测试进程继承代理后，完整 CTest **36/36**，耗时 150.53 s；日志 `ctest-clean-env.log`。新增测量测试 3/3，Python ruff 检查通过。
- SOCKS5 shell 集成退出码 0；日志 `socks5-integration.log`，在独立 user/network/mount namespace 执行。没有修改宿主代理变量或网络配置。
- YAML 可解析，macOS 所有缓存键及恢复前缀均限定 macos-15；这不替代 Actions 执行。
- `git diff --check` 通过，暂存区为空。最终 8 个未提交文件：`.github/workflows/ci.yml`、`CMakeLists.txt`、`scripts/test_proxy_reality_connection_regression.cpp`、`scripts/test_proxy_udp_stale_budget.py`、`scripts/test_reality_vision_load.py`、`scripts/test_reality_vision_load_metrics.py`、本报告和 CSV。原有 UDP 脚本 SHA256 核对一致。

| 项目 | 结论 | 范围 |
| --- | --- | --- |
| macOS CI | BLOCKED | 需要实际运行修改后的 workflow |
| Linux | GO | 本机 x86_64 Clang Release；36/36 及 SOCKS5 |
| Windows | 未重测 | 仅确认已有远端运行成功 |
| REALITY/Vision | GO | 本项目协议、TLS1.3 双向 Direct / TLS1.2 fallback；不代表 VLESS/Xray |
| 负载测试稳定性 | GO | 本机固定负载修改后连续 20/20；不外推所有 CI 环境 |
| 整体 | INCONCLUSIVE | 等待 macOS CI 实际验证 |
