#ifndef LOG_H
#define LOG_H

#define SPDLOG_SHORT_LEVEL_NAMES {"TRC", "DBG", "INF", "WRN", "ERR", "CTL", "OFF"};

#include <string>

#include <spdlog/spdlog.h>

void init_log(const std::string& filename);
void set_level(const std::string& level);
void shutdown_log();

#define LOG_TRACE(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::trace, __VA_ARGS__)
#define LOG_DEBUG(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::debug, __VA_ARGS__)
#define LOG_INFO(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::info, __VA_ARGS__)
#define LOG_WARN(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::warn, __VA_ARGS__)
#define LOG_ERROR(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::err, __VA_ARGS__)

#define LOG_CTX_TRACE(ctx, fmt, ...) LOG_TRACE("{} " fmt, (ctx).prefix(), ##__VA_ARGS__)
#define LOG_CTX_DEBUG(ctx, fmt, ...) LOG_DEBUG("{} " fmt, (ctx).prefix(), ##__VA_ARGS__)
#define LOG_CTX_INFO(ctx, fmt, ...) LOG_INFO("{} " fmt, (ctx).prefix(), ##__VA_ARGS__)
#define LOG_CTX_WARN(ctx, fmt, ...) LOG_WARN("{} " fmt, (ctx).prefix(), ##__VA_ARGS__)
#define LOG_CTX_ERROR(ctx, fmt, ...) LOG_ERROR("{} " fmt, (ctx).prefix(), ##__VA_ARGS__)

#endif
