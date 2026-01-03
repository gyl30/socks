#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include "log.h"
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

static void init_default_log(const std::string& filename);
static void set_log_level();
static uint32_t get_log_file_size();
static uint32_t get_log_file_count();

void init_log(const std::string& filename)
{
    init_default_log(filename);

    set_log_level();
}
void set_level(const std::string& level)
{
    spdlog::set_level(spdlog::level::info);
    if (level == "debug")
    {
        spdlog::set_level(spdlog::level::debug);
    }
    else if (level == "warn" || level == "warning")
    {
        spdlog::set_level(spdlog::level::warn);
    }
    else if (level == "err" || level == "error")
    {
        spdlog::set_level(spdlog::level::err);
    }
    else if (level == "trace")
    {
        spdlog::set_level(spdlog::level::trace);
    }
}
void shutdown_log()
{
    spdlog::default_logger()->flush();
    spdlog::shutdown();
}

static void init_default_log(const std::string& filename)
{
    uint32_t file_size = get_log_file_size();
    uint32_t file_count = get_log_file_count();
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
static uint32_t get_log_file_size()
{
    constexpr auto kFileSize = 50 * 1024 * 1024;
    char* file_size = getenv("LOG_FILE_SIZE");
    if (file_size != nullptr)
    {
        return atoi(file_size);
    }
    return kFileSize;
}
static uint32_t get_log_file_count()
{
    constexpr auto kFileCount = 5;
    char* file_count = getenv("LOG_FILE_COUNT");
    if (file_count != nullptr)
    {
        return atoi(file_count);
    }
    return kFileCount;
}
