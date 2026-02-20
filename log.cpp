#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include "spdlog/common.h"
#include "spdlog/logger.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "log.h"

static void init_default_log(const std::string& filename);
static void set_log_level();
static std::uint32_t get_log_file_size();
static std::uint32_t get_log_file_count();
static spdlog::level::level_enum parse_level_name(const std::string& level);

void init_log(const std::string& filename)
{
    init_default_log(filename);

    set_log_level();
}

void set_level(const std::string& level)
{
    spdlog::set_level(parse_level_name(level));
}

void shutdown_log()
{
    spdlog::default_logger()->flush();
    spdlog::shutdown();
}

static void init_default_log(const std::string& filename)
{
    const std::uint32_t file_size = get_log_file_size();
    const std::uint32_t file_count = get_log_file_count();
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, file_size, file_count));
    auto logger = std::make_shared<spdlog::logger>("", begin(sinks), end(sinks));
    spdlog::set_default_logger(logger);
    spdlog::flush_every(std::chrono::seconds(3));
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("%Y%m%d %T.%f %t %L %v %s:%#");
}

static void set_log_level()
{
    spdlog::set_level(spdlog::level::info);
    if (getenv("TRACE") != nullptr)
    {
        spdlog::set_level(spdlog::level::trace);
    }
    else if (getenv("DEBUG") != nullptr)
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

static std::uint32_t get_log_file_size()
{
    constexpr auto kFileSize = 50 * 1024 * 1024;
    char* file_size = getenv("kLogFileSize");
    if (file_size != nullptr)
    {
        return static_cast<std::uint32_t>(atoi(file_size));
    }
    return kFileSize;
}

static std::uint32_t get_log_file_count()
{
    constexpr auto kFileCount = 5;
    char* file_count = getenv("kLogFileCount");
    if (file_count != nullptr)
    {
        return static_cast<std::uint32_t>(atoi(file_count));
    }
    return kFileCount;
}
