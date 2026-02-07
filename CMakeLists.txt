cmake_minimum_required(VERSION 3.16)
project(socks VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer")

option(ENABLE_COVERAGE "Enable code coverage" OFF)
if(ENABLE_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
        add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
        add_link_options(-fprofile-instr-generate -fcoverage-mapping)
    else()
        add_compile_options(-fprofile-arcs -ftest-coverage)
        add_link_options(--coverage)
    endif()
endif()

add_compile_definitions(
    SPDLOG_SHORT_LEVEL_NAMES={"TRC","DBG","INF","WRN","ERR","CTL","OFF"}
)

find_package(OpenSSL REQUIRED)

set(SOCKS_SOURCES
    log.cpp
    config.cpp
    mux_connection.cpp
    remote_server.cpp
    local_client.cpp
    router.cpp
    socks_session.cpp
    tcp_socks_session.cpp
    udp_socks_session.cpp
    mux_dispatcher.cpp
    reality_messages.cpp
    cert_fetcher.cpp
    crypto_util.cpp
    reality_fingerprint.cpp
    ch_parser.cpp
    tls_record_layer.cpp
    ip_matcher.cpp
    remote_session.cpp
    remote_udp_session.cpp
    upstream.cpp
    mux_codec.cpp
    mux_stream.cpp
    protocol.cpp
    log_context.cpp
    context_pool.cpp
    transcript.cpp
    replay_cache.cpp
    reality_engine.cpp
    domain_matcher.cpp
    cert_manager.cpp
    key_rotator.cpp
    reality_auth.cpp
)

add_library(socks_core STATIC ${SOCKS_SOURCES})

target_include_directories(socks_core PUBLIC
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/third/asio/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/spdlog/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/rapidjson/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(socks_core PUBLIC OpenSSL::SSL OpenSSL::Crypto pthread)

add_executable(socks main.cpp)
target_link_libraries(socks PRIVATE socks_core)

find_package(GTest)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/heads/main.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

enable_testing()
add_subdirectory(tests)
