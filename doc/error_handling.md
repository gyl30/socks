# 错误处理规范

本项目采用以下错误处理策略：

## 错误处理模式

### 1. `std::error_code&` 输出参数 (推荐用于底层操作)

适用于：加密、网络 I/O、解码等可能失败的操作。

```cpp
std::vector<std::uint8_t> crypto_util::aead_decrypt(
    ...,
    std::error_code& ec);  // 调用方检查 ec

// 使用方式
std::error_code ec;
auto result = crypto_util::aead_decrypt(..., ec);
if (ec)
{
    LOG_ERROR("decrypt failed: {}", ec.message());
    return;
}
```

### 2. `std::optional<T>` 返回值 (适用于查询操作)

适用于：配置解析、缓存查询等可能返回空的操作。

```cpp
std::optional<config> parse_config(const std::string& filename);

// 使用方式
auto cfg_opt = parse_config("config.json");
if (!cfg_opt.has_value())
{
    LOG_ERROR("config parse failed");
    return false;
}
const auto& cfg = *cfg_opt;
```

### 3. `bool` 返回值 (适用于简单检查)

适用于：初始化、加载规则文件等不需要详细错误信息的操作。

```cpp
bool router::load();
bool ip_matcher::match(const asio::ip::address& addr) const;

// 使用方式
if (!router.load())
{
    LOG_WARN("router load failed");
}
```

### 4. 异常 (仅限反射层)

仅在 `reflect.h` 的 JSON 解析中使用，调用方必须捕获：

```cpp
// 仅在 reflect.h 内部使用
throw std::invalid_argument("bool");

// 调用方
if (!reflect::deserialize_struct(cfg, json_content))
{
    return {};  // 异常已被捕获
}
```

## 规范要点

1. **不混用**：同一模块内使用一致的错误处理方式
2. **必须检查**：所有 `std::error_code` 必须检查后再继续
3. **日志记录**：错误路径必须有日志输出
4. **[[nodiscard]]**：返回错误信息的函数必须标记 `[[nodiscard]]`
5. **禁止 abort**：运行时错误不使用 `abort()` 终止进程，应返回错误并停止启动或关闭会话

## 日志级别选择

| 场景 | 级别 | 示例 |
|------|------|------|
| 正常失败 | `WARN` | 文件不存在、规则不匹配 |
| 异常错误 | `ERROR` | 解密失败、网络错误 |
| 开发调试 | `DEBUG` | 路由决策、状态变化 |

## 资源回收与协议响应

1. **会话失败必须回收资源**：关闭 socket、移除 stream、停止定时器
2. **协议失败要返回响应**：例如 SOCKS5 错误码、MUX reset
3. **空闲回收**：长时间无数据的会话需要超时关闭
