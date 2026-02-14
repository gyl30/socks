# 错误处理规范

本项目全面采用 C++23 `std::expected` 进行错误处理，替代传统的 `std::error_code&` 输出参数模式。

## 错误处理模式

### 1. `std::expected<T, std::error_code>` 返回值 (同步操作)

适用于：绝大多数同步操作，如加密解密、配置解析、数据处理等。

```cpp
// 定义
std::expected<std::vector<std::uint8_t>, std::error_code> crypto_util::aead_decrypt(
    ...);

// 使用方式
auto result = crypto_util::aead_decrypt(...);
if (!result)
{
    LOG_ERROR("decrypt failed: {}", result.error().message());
    return;
}
auto plaintext = *result; // 或者 std::move(*result)
```

对于不返回具体值的函数，使用 `std::expected<void, std::error_code>`：

```cpp
std::expected<void, std::error_code> validate_input(...);

if (auto res = validate_input(...); !res)
{
    return std::unexpected(res.error());
}
```

### 2. `asio::awaitable<std::expected<T, std::error_code>>` (异步操作)

适用于：所有协程环境下的异步网络 I/O 操作。

```cpp
// 定义
asio::awaitable<std::expected<std::size_t, std::error_code>> async_read_wrapper(
    asio::ip::tcp::socket& socket, ...);

// 使用方式
auto res = co_await async_read_wrapper(socket, ...);
if (!res)
{
    LOG_ERROR("async read failed: {}", res.error().message());
    co_return; // 或处理错误
}
auto bytes_transferred = *res;
```

**注意**：对于 `asio::awaitable<std::expected<void, std::error_code>>`，在 `co_return` 成功时需显式构造：

```cpp
co_return std::expected<void, std::error_code>{};
```

### 3. `std::optional<T>` 返回值 (仅限查询/缓存)

适用于：查询可能不存在的数据（非错误情况），如缓存查找、配置项读取。

```cpp
std::optional<config> parse_config(const std::string& filename);

if (auto cfg = parse_config(...); cfg)
{
    // found
}
```

### 4. 异常

项目代码中禁止使用异常。
- 禁止新增 `throw` / `try` / `catch`。
- 错误统一通过 `std::expected`、`std::optional` 或显式状态值返回。
- 反序列化失败必须通过返回值上报，不得依赖异常捕获。

## 规范要点

1.  **一致性**：新代码必须使用 `std::expected`，禁止添加新的 `std::error_code&` 输出参数，也禁止使用异常。
2.  **错误传播**：使用 `return std::unexpected(ec)` 传播错误。
3.  **nodiscard**：所有返回 `std::expected` 的函数均应视为隐含 `[[nodiscard]]`（C++23 标准特性或编译器警告支持）。
4.  **资源管理**：利用 RAII（如 `scoped_exit`）确保出错时资源正确释放。

## 迁移指南

旧代码：
```cpp
std::error_code ec;
func(arg, ec);
if (ec) { ... }
```

新代码：
```cpp
auto res = func(arg);
if (!res) { auto ec = res.error(); ... }
```

## 异常禁用工作清单

为避免依赖缺失文档，异常禁用相关清单统一维护在本文件，不再依赖 `doc/tests_exception_inventory.md`。

1. 项目代码（`third/` 除外）禁止新增 `throw` / `try` / `catch`。
2. 新增错误返回接口统一使用 `std::expected`，禁止新增 `std::error_code&` 输出参数。
3. 反序列化、握手、I/O 失败路径必须在测试中断言可观测错误返回，不依赖异常。
4. 建议在本地或 CI 增加静态检查：`rg -n "\\bthrow\\b|\\btry\\b|\\bcatch\\b" --glob '*.{cpp,h}' --glob '!third/**'`。
5. 发现存量不一致时，按“接口签名 -> 调用链 -> 测试”顺序迁移，避免半迁移状态。
