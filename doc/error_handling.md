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

### 4. 异常 (Scope 限制)

仅在以下场景容许使用异常：
- `reflect.h` 内部的 JSON 序列化/反序列化（由最外层捕获）。
- 极少数不可恢复的初始化错误（如 `std::bad_alloc`）。
- 禁止在核心业务逻辑流中使用异常进行控制流跳转。

## 规范要点

1.  **一致性**：新代码必须使用 `std::expected`，禁止添加新的 `std::error_code&` 输出参数。
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
