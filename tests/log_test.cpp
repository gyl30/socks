// NOLINTBEGIN(misc-include-cleaner)
#include <cstdlib>
#include <fstream>

#include <gtest/gtest.h>

#include "log.h"

namespace mux
{

TEST(LogTest, InitAndShutdown)
{
    init_log("test_run.log");
    LOG_INFO("Testing log initialization");
    set_level("debug");
    LOG_DEBUG("Testing debug level");
    set_level("trace");
    LOG_TRACE("Testing trace level");
    set_level("warn");
    LOG_WARN("Testing warn level");
    set_level("error");
    LOG_ERROR("Testing error level");
    shutdown_log();

    std::ifstream f("test_run.log");
    EXPECT_TRUE(f.good());
    f.close();
    std::remove("test_run.log");
}

TEST(LogTest, EnvVariables)
{
    setenv("TRACE", "1", 1);
    setenv("kLogFileSize", "1024", 1);
    setenv("kLogFileCount", "2", 1);

    init_log("test_env.log");
    LOG_TRACE("Should be visible");
    shutdown_log();

    unsetenv("TRACE");
    unsetenv("kLogFileSize");
    unsetenv("kLogFileCount");
    std::remove("test_env.log");
}

TEST(LogTest, SetLevelValues)
{
    set_level("warning");
    set_level("err");
    set_level("info");
    set_level("unknown");
}

}    // namespace mux
// NOLINTEND(misc-include-cleaner)
