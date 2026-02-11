cmake_minimum_required(VERSION 3.16)
project(socks VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_BUILD_TYPE Debug)

option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
if(ENABLE_TSAN)
    if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang"))
        message(FATAL_ERROR "ENABLE_TSAN requires clang toolchain please reconfigure with -DENABLE_TSAN=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++")
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer -fsanitize=thread")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer -fsanitize=thread -g")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer -fsanitize=address")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer -fsanitize=address -g")
endif()

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

find_package(OpenSSL REQUIRED)

set(SOCKS_SOURCES
    log.cpp
    config.cpp
    net_utils.cpp
    mux_connection.cpp
    remote_server.cpp
    socks_client.cpp
    tproxy_client.cpp
    router.cpp
    socks_session.cpp
    tcp_socks_session.cpp
    udp_socks_session.cpp
    tproxy_tcp_session.cpp
    tproxy_udp_session.cpp
    tproxy_udp_sender.cpp
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
    client_tunnel_pool.cpp
    transcript.cpp
    replay_cache.cpp
    reality_engine.cpp
    domain_matcher.cpp
    cert_manager.cpp
    key_rotator.cpp
    reality_auth.cpp
    monitor_server.cpp
)

add_library(socks_core STATIC ${SOCKS_SOURCES})

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    target_compile_options(socks_core PRIVATE -Wno-unknown-warning-option)
endif()

target_include_directories(socks_core PUBLIC
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(socks_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third/asio/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/spdlog/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/rapidjson/include
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

option(ENABLE_FUZZING "Enable fuzz testing" OFF)
if(ENABLE_FUZZING)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "Fuzzing requires Clang compiler")
    endif()

    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-omit-frame-pointer)

    macro(add_fuzz_test NAME)
        add_executable(${NAME} fuzz/${NAME}.cpp)
        target_compile_options(${NAME} PRIVATE -fsanitize=fuzzer)
        target_link_options(${NAME} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${NAME} PRIVATE socks_core)
    endmacro()

    add_fuzz_test(fuzz_mux_codec)
    add_fuzz_test(fuzz_ch_parser)
    add_fuzz_test(fuzz_socks_codec)
    add_fuzz_test(fuzz_config)
    add_fuzz_test(fuzz_reality_auth)
    add_fuzz_test(fuzz_reality_decrypt)
    add_fuzz_test(fuzz_socks_handshake)
endif()
