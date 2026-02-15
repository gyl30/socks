# 错误处理规范

本项目当前采用“`std::expected` 为主，`asio::awaitable<std::error_code>` 作为异步边界接口”的混合模式。

## 错误处理模式

### 1. `std::expected<T, std::error_code>`（同步与业务层）

适用于：加密解密、协议编解码、配置校验、业务流程等需要表达“值或错误”的路径。

```cpp
auto result = crypto_util::aead_decrypt(...);
if (!result)
{
    return std::unexpected(result.error());
}
auto plaintext = std::move(*result);
```

不返回值时使用 `std::expected<void, std::error_code>`。

### 2. `asio::awaitable<std::error_code>`（异步 I/O 边界）

适用于：socket 读写、握手分段发送/接收等“是否成功”语义的协程边界接口。

```cpp
std::error_code ec = co_await conn->send_async(stream_id, cmd, payload);
if (ec)
{
    LOG_WARN("send failed {}", ec.message());
    co_return;
}
```

现有接口示例：`mux_connection::send_async`、`remote_server::send_server_hello_flight`、`remote_server::verify_client_finished`。

### 3. `asio::awaitable<std::expected<T, std::error_code>>`（异步且需要返回值）

适用于：既要异步执行又需要返回业务值的协程接口。

### 4. `std::optional<T>`（非错误的“缺失”语义）

适用于：查询可能不存在的数据或配置项。

```cpp
auto cfg = parse_config(path);
if (!cfg)
{
    return;
}
```

### 5. 异常

项目代码中禁止使用异常。
1. 禁止新增 `throw` / `try` / `catch`。
2. 错误通过 `std::expected`、`std::optional`、`std::error_code` 或显式状态返回。
3. 失败路径必须可测试、可日志观测，不依赖异常捕获。

## 规范要点

1. 新增业务接口优先使用 `std::expected`。
2. 新增异步 I/O 边界接口允许使用 `asio::awaitable<std::error_code>`，禁止回退到 `std::error_code&` 输出参数。
3. 统一通过返回值传播错误，禁止静默吞错。
4. 关键错误路径必须记录日志并在测试中覆盖。

## 迁移策略

1. 先统一文档口径（当前阶段已采用混合模式）。
2. 新代码保持“业务 `expected`、边界 `awaitable<std::error_code>`”。
3. 存量接口逐步迁移为更强类型返回（按“接口签名 -> 调用链 -> 测试”顺序）。

## 异常禁用工作清单

异常禁用专项清单以 `doc/tests_exception_inventory.md` 为主，本文件仅保留编码约束摘要。

1. 项目代码（`third/` 除外）禁止新增 `throw` / `try` / `catch`。
2. 禁止新增 `std::error_code&` 输出参数风格接口。
3. 已在 CTest 增加 `no_exception_keywords_test` 静态检查，核心扫描命令为：`rg -n "\\bthrow\\b|\\btry\\b|\\bcatch\\b" --glob '*.{cpp,h}' --glob '!third/**'`。
