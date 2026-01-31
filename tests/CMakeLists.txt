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

add_executable(mux_codec_test mux_codec_test.cpp)
target_link_libraries(mux_codec_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(mux_codec_test PRIVATE
    ../mux_codec.cpp
    ../log.cpp
)
target_include_directories(mux_codec_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(mux_codec_test)

add_executable(socks_codec_test socks_codec_test.cpp)
target_link_libraries(socks_codec_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(socks_codec_test PRIVATE
    ../protocol.cpp
    ../log.cpp
)
target_include_directories(socks_codec_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(socks_codec_test)

add_executable(crypto_util_test crypto_util_test.cpp)
target_link_libraries(crypto_util_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(crypto_util_test PRIVATE
    ../crypto_util.cpp
    ../log.cpp
)
target_include_directories(crypto_util_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(crypto_util_test)

add_executable(router_test router_test.cpp)
target_link_libraries(router_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(router_test PRIVATE
    ../router.cpp
    ../ip_matcher.cpp
    ../log.cpp
)
target_include_directories(router_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(router_test)

add_executable(ch_parser_test ch_parser_test.cpp)
target_link_libraries(ch_parser_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(ch_parser_test PRIVATE
    ../ch_parser.cpp
    ../log.cpp
)
target_include_directories(ch_parser_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(ch_parser_test)

add_executable(reality_messages_test reality_messages_test.cpp)
target_link_libraries(reality_messages_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(reality_messages_test PRIVATE
    ../reality_messages.cpp
    ../reality_fingerprint.cpp
    ../crypto_util.cpp
    ../log.cpp
)
target_include_directories(reality_messages_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(reality_messages_test)

add_executable(tls_record_layer_test tls_record_layer_test.cpp)
target_link_libraries(tls_record_layer_test
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_sources(tls_record_layer_test PRIVATE
    ../tls_record_layer.cpp
    ../crypto_util.cpp
    ../log.cpp
)
target_include_directories(tls_record_layer_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
)
gtest_discover_tests(tls_record_layer_test)

add_executable(config_test config_test.cpp)
target_link_libraries(config_test
    GTest::gtest_main
    pthread
)
target_sources(config_test PRIVATE
    ../config.cpp
    ../log.cpp
)
target_include_directories(config_test PRIVATE
    ../
    ../third/asio/include
    ../third/spdlog/include
    ../third/rapidjson/include
)
gtest_discover_tests(config_test)
