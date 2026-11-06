# macOS OpenSSL 头文件边界修复验收

## 1. 基线与范围

- 仓库：`gyl30/socks`；分支 `main`；本地 HEAD 和 `git ls-remote origin refs/heads/main` 均为 `9d35932f8c9a9006787a3a126691503fc1aa43ad`。
- 初始工作区、暂存区均为空；未发现仓库内 `AGENTS.md`，遵守本轮提供的规则。
- 仅操作 socks；未修改其他项目、宿主网络、已通过的 REALITY/Vision 生产逻辑或依赖源码。
- 阅读 README 构建说明、CMakeLists.txt、CI、架构不变量和此前验收记录。本轮不重复处理已解决的 Homebrew 安装故障。

## 2. 失败 CI 核实

[运行 42170525732](https://github.com/gyl30/socks/actions/runs/42170525732)，macOS job `127737024578`：Install Dependencies、Prepare Boost Headers、Build OpenSSL、Configure 均成功，Build Binary 失败。

实际编译器：Homebrew LLVM 23.1.5，ARM64；固定 OpenSSL 3.6.0 编译并安装到 `/Users/runner/.cache/openssl/install-3.6.0`。日志显示 Brotli 1.2.1 已安装；本轮没有改变 Homebrew 安装命令或任何固定版本。

`tls/crypto_util.cpp` 共 6 个错误：

- 1175 行两处、1180 行三处：`member access into incomplete type 'const ASN1_BIT_STRING'`。
- 对应类型前向声明来自 `/opt/homebrew/include/openssl/types.h:58`。
- 1221 行：不能用 `const X509_NAME *` 初始化 `X509_NAME *`。

本轮未修改证书签名或 ASN.1 逻辑。编译命令及错误摘录存于 `.cache/macos-openssl-20261106/ci-compile-evidence.log`。

已检查全部 10 个 job：Linux x86/arm64 × gcc/clang × glibc/musl **8/8 成功**，Windows **1/1 成功**，macOS **0/1**。这些是原提交的真实结果，不是本轮修改后的 CI。

## 3. 路径证据与根因

CI 的真实失败编译命令包含以下顺序：

```text
-isystem /opt/homebrew/include
...其他项目依赖...
-isystem /Users/runner/.cache/openssl/install-3.6.0/include
```

`find_path(BROTLI_INCLUDE_DIR NAMES brotli/decode.h ...)` 可以选中 Homebrew 通用 include。`configure_core_target()` 将其加入 SYSTEM include，随后通过 `OpenSSL::SSL`、`OpenSSL::Crypto` 的传递依赖加入固定 OpenSSL include。声明一个正确的 OpenSSL 导入目标，不会阻止其他依赖的通用路径先找到另一套同名头文件。

**CONFIRMED：Brotli 的通用 include 范围越界，导致固定 OpenSSL 头文件被其他安装抢先覆盖。** CI 直接证明了错误头的来源；没有 CI 头文件跟踪，不声称已经枚举了该次编译读取的全部 OpenSSL 头或确认全局头的版本。CI 在链接之前失败，亦没有实际 socks 链接结果可供验证。

### Linux 受控复现

在仓库忽略目录 `.cache/macos-openssl-20261106/` 内建立类似 Homebrew 的搜索拓扑，所有依赖均为真实已安装文件的符号链接，未改动第三方头：

- `global/include/brotli` → `/usr/include/brotli`。
- `global/include/openssl` → `/usr/include/openssl`（3.0.2）。
- `global/opt/brotli/include/brotli` → `/usr/include/brotli`；该 include 下只提供 Brotli。
- 两个构建均由 CONFIG 模式导入 `/home/gyl/openssl`（3.6.0）。

从 `compile_commands.json` 提取 `tls/crypto_util.cpp` 的实际 include 参数，并使用 Clang `-E -H` 跟踪读取的头文件；同时用 CMake 延迟回调读取目标属性：

| 检查项 | 修复前 | 修复后 |
| --- | --- | --- |
| BROTLI_INCLUDE_DIR | `global/include` | `global/opt/brotli/include` |
| OpenSSL_DIR | `/home/gyl/openssl/lib64/cmake/OpenSSL` | 相同 |
| SSL/Crypto include 属性 | `/home/gyl/openssl/include` | 相同 |
| SSL/Crypto IMPORTED_LOCATION | `/home/gyl/openssl/lib64/libssl.so`、`libcrypto.so` | 相同 |
| 实际读取的 OpenSSL 头 | `/usr/include` 与 `/home/gyl/openssl/include` 两套 | 全部来自 `/home/gyl/openssl/include` |
| 版本探针 | 编译失败 | header=3.6.0，runtime=3.6.0 |

修复前编译真实 `tls/crypto_util.cpp` 失败：3.0.2 的 `macros.h` 与 3.6.0 的 `configuration.h` 混用，报 `OPENSSL_API_COMPAT expresses an impossible API compatibility level`。这是相同路径缺陷的 Linux 复现，**不是冒充重现 macOS 的同一组 6 个诊断**。

修复后头文件跟踪的 70 条 OpenSSL 头路径记录（52 个不同头文件）均归属固定安装；实际目标属性、链接命令和运行时加载另行检查。具体证据位于：

- `before/crypto-command.txt`、`after/crypto-command.txt`。
- `before/header-trace.txt`、`after/header-trace.txt`、`openssl-header-roots.json`。
- 两个目录的 `dependency-properties.txt`。
- `build-before.log`、`probe-before.log`、`probe-after.log`。

## 4. 最小修复

生产构建配置仅修改 `.github/workflows/ci.yml` 的 macOS Configure 三行：

```bash
BROTLI_INCLUDE_DIR="$(brew --prefix brotli)/include"
test -f "${BROTLI_INCLUDE_DIR}/brotli/decode.h"
# 加入现有 CMake 参数：
-DBROTLI_INCLUDE_DIR="${BROTLI_INCLUDE_DIR}"
```

路径检查先于 CMake；若头文件不存在立即失败，避免悄悄回到通用 include。Linux 本地已验证对应目录和真实 decode.h 存在，缺失目录检查退出码为 1。**本机无 Homebrew/macOS，不能声称已实际验证 runner 上该目录；该检查将在下次 macOS CI 配置前执行。**

macOS 预期变化：

```text
之前：-isystem /opt/homebrew/include
之后：-isystem /opt/homebrew/opt/brotli/include
固定 OpenSSL include 保持不变
```

这是期望路径，实际 prefix 由 runner 的 `brew --prefix brotli` 决定。无需调整通用 CMake include 顺序，也未改 CMakeLists.txt、警告选项、缓存策略、固定 Boost/OpenSSL 版本或第三方源码。YAML 解析及 Configure shell 语法检查通过；结构化比较确认 Linux/Windows Job 内容与 HEAD 完全一致。

## 5. 本地验证命令

所有构建使用新的忽略目录，不清理或覆盖原有构建。Linux x86_64、Clang 23.0.0、Boost 1.92.0、OpenSSL 3.6.0、Release，无 ASan/TSan；本地 Boost 与 CI 1.89.0 的差异保留，不据此声称覆盖 macOS 固定依赖组合。

```bash
# 修复前：CMAKE_PREFIX_PATH 指向上述受控通用前缀，find_path 自动选中通用 include
cmake -S . -B .cache/macos-openssl-20261106/before -GNinja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_ASAN=OFF -DENABLE_TSAN=OFF -DOPENSSL_ROOT_DIR=/home/gyl/openssl \
  -DCMAKE_PREFIX_PATH="$PWD/.cache/macos-openssl-20261106/global" \
  -DCMAKE_PROJECT_socks_INCLUDE="$PWD/.cache/macos-openssl-20261106/dependency-properties.cmake"
cmake --build .cache/macos-openssl-20261106/before --target CMakeFiles/core.dir/tls/crypto_util.cpp.o

# 修复后：其他参数相同，仅明确给出 Brotli 专属 include
cmake -S . -B .cache/macos-openssl-20261106/after -GNinja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_ASAN=OFF -DENABLE_TSAN=OFF -DOPENSSL_ROOT_DIR=/home/gyl/openssl \
  -DCMAKE_PREFIX_PATH="$PWD/.cache/macos-openssl-20261106/global" \
  -DCMAKE_PROJECT_socks_INCLUDE="$PWD/.cache/macos-openssl-20261106/dependency-properties.cmake" \
  -DBROTLI_INCLUDE_DIR="$PWD/.cache/macos-openssl-20261106/global/opt/brotli/include"
python3 .cache/macos-openssl-20261106/probe_paths.py before
python3 .cache/macos-openssl-20261106/probe_paths.py after
cmake --build .cache/macos-openssl-20261106/after -j4
unshare -Urnm sh -c 'ip link set lo up; exec env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy -u NO_PROXY -u no_proxy taskset -c 0-3 ctest --test-dir .cache/macos-openssl-20261106/after --output-on-failure'
git diff --check
```

探针使用真实编译命令中的搜索参数，而非另设 include 顺序。版本检查将 `OPENSSL_VERSION_STR` 与实际链接的 `OpenSSL_version(OPENSSL_VERSION_STRING)` 比较。探针源码、检查脚本及属性回调均保留在本地证据目录；不是生产构建的一部分。

## 6. macOS 后续验收

本机只有 Linux，未访问其他项目或受控构建主机。没有提交、推送或运行新提交 Actions。因此 macOS ARM64 实际构建仍 **BLOCKED**。

获得提交推送授权后，需检查新运行的全部 10 个 Job；macOS 需完成依赖安装、固定 OpenSSL 构建、头文件存在性检查、Configure、Build Binary。还需检查真实 compile_commands、OpenSSL imported include/library 属性及预处理头文件跟踪，确认全部 OpenSSL 头及链接库归属于同一 3.6.0 安装。不能仅以编译成功替代该检查。

## 7. 最终回归、状态与结论

- 完整新目录配置和构建成功，含 socks 及全部测试可执行文件；`build-after.log` 保存 147 项构建结果。
- 完整 CTest **36/36**，耗时 150.34 s；日志 `ctest.log`。包含 REALITY/Vision 协议、Direct/fallback、padding、半关闭、TCP_NODELAY、超时、UDP 及负载测试。本轮未重复上轮的 20 次负载验收；当前主程序 SHA256 与上轮相同，本次 CTest 中的负载测试另行通过。
- 主程序 SHA256：`52807dd911136e97d944df876545ce07f89ad982c9b8f454f89c83285c57bf85`。
- `socks-commands.txt` 的最终链接命令明确指定 `/home/gyl/openssl/lib64/libssl.so` 和 `libcrypto.so`；`runtime-libraries.txt` 的 ldd 同时确认两个库实际从该安装加载。版本探针确认 header=3.6.0 / runtime=3.6.0。没有仅凭编译成功推定一致性。
- `git diff --check` 通过。最终只有 `.github/workflows/ci.yml` 修改，以及本验收文档新增；暂存区为空，无提交、推送或部署。初始没有用户未提交修改可被覆盖；既有构建目录均未变更。

| 分类 | 结论 | 限制 |
| --- | --- | --- |
| 依赖头文件边界缺陷 | FIXED | 已完成最小配置修复并通过 Linux 受控 RED/GREEN |
| macOS 原始编译错误 | 未修复（验收未完成） | 原始六个错误尚未在真实 macOS 上复验，不能宣称已经消失 |
| macOS CI | BLOCKED | 本机无 macOS，未授权推送，尚无修改后的 CI |
| Linux | GO | 本地 x86_64 Clang Release，36/36；其他矩阵仅确认原 CI 成功 |
| Windows | 未重测 | Job 配置完全未变，原 CI 为成功 |
| 整体 | INCONCLUSIVE | 等待真实 macOS CI 与依赖路径复验 |
