#include <memory>
#include <string>
#include <vector>
#include <charconv>
#include <cstdint>
#include <string_view>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "constants.h"
#include "log.h"

static void init_default_log(const std::string& filename);
static void set_log_level();
static uint32_t get_env_uint32_or_default(const char* env_name, uint32_t default_value);
static uint32_t get_log_file_size();
static uint32_t get_log_file_count();
static spdlog::level::level_enum parse_level_name(const std::string& level);

void init_log(const std::string& filename)
{
    init_default_log(filename);

    set_log_level();
}

void set_level(const std::string& level) { spdlog::set_level(parse_level_name(level)); }

void shutdown_log()
{
    spdlog::default_logger()->flush();
    spdlog::shutdown();
}

static void init_default_log(const std::string& filename)
{
    const uint32_t file_size = get_log_file_size();
    const uint32_t file_count = get_log_file_count();
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, file_size, file_count));
    auto logger = std::make_shared<spdlog::logger>("", begin(sinks), end(sinks));
    spdlog::set_default_logger(logger);
    spdlog::flush_every(std::chrono::seconds(constants::log::kFlushIntervalSec));
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("%Y%m%d %T.%f %t %L %v %s:%#");
}

static void set_log_level()
{
    spdlog::set_level(spdlog::level::info);
    if (std::getenv("TRACE") != nullptr)
    {
        spdlog::set_level(spdlog::level::trace);
    }
    else if (std::getenv("DEBUG") != nullptr)
    {
        spdlog::set_level(spdlog::level::debug);
    }
}

static spdlog::level::level_enum parse_level_name(const std::string& level)
{
    struct level_alias
    {
        const char* name;
        spdlog::level::level_enum value;
    };

    static constexpr level_alias kLevels[] = {
        {.name = "debug", .value = spdlog::level::debug},
        {.name = "warn", .value = spdlog::level::warn},
        {.name = "warning", .value = spdlog::level::warn},
        {.name = "err", .value = spdlog::level::err},
        {.name = "error", .value = spdlog::level::err},
        {.name = "trace", .value = spdlog::level::trace},
    };

    for (const auto& entry : kLevels)
    {
        if (level == entry.name)
        {
            return entry.value;
        }
    }
    return spdlog::level::info;
}

static uint32_t get_env_uint32_or_default(const char* env_name, uint32_t default_value)
{
    if (const char* env_value = std::getenv(env_name); env_value != nullptr && *env_value != '\0')
    {
        uint32_t value_u32 = 0;
        const std::string_view value(env_value);
        const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), value_u32);
        if (ec == std::errc() && ptr == value.data() + value.size())
        {
            return value_u32;
        }
    }
    return default_value;
}

static uint32_t get_log_file_size() { return get_env_uint32_or_default("kLogFileSize", constants::log::kFileSize); }

static uint32_t get_log_file_count() { return get_env_uint32_or_default("kLogFileCount", constants::log::kFileCount); }
