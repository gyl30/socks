add_executable(ip_matcher_test ip_matcher_test.cpp)


target_link_libraries(ip_matcher_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Since 'socks' is an executable, we cannot link against it directly in standard CMake.
# We have two options:
# 1. Change 'socks' to be a library + executable wrapper.
# 2. Add the source files directly to the test executable.
#
# Given the current structure, Option 2 is less invasive for now, but Option 1 is better long term.
# For this immediate step, let's list the necessary sources.

target_sources(ip_matcher_test PRIVATE
    ../ip_matcher.cpp
    ../log.cpp
)

target_include_directories(ip_matcher_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)

include(GoogleTest)
gtest_discover_tests(ip_matcher_test)
