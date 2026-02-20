cmake_minimum_required(VERSION 3.16)
project(
  socks
  VERSION 0.0.1
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE
      Debug
      CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
                                               "RelWithDebInfo" "MinSizeRel")
endif()

include(CheckCXXCompilerFlag)

add_compile_options(
  -Wall
  -Wextra
  -Wformat
  -Wformat=2
  -Wconversion
  -Wimplicit-fallthrough
  -Werror=format-security
  -fno-strict-aliasing)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                            "AppleClang")
  add_compile_options(-Wno-unknown-warning-option)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wtrampolines)
  check_cxx_compiler_flag("-fzero-init-padding-bits=all" HAS_ZERO_PADDING)
  if(HAS_ZERO_PADDING)
    add_compile_options(-fzero-init-padding-bits=all)
  endif()
endif()

add_compile_options(
  -D_GLIBCXX_ASSERTIONS
  -fstrict-flex-arrays=3
  -fstack-clash-protection
  -fstack-protector-strong
  -fno-delete-null-pointer-checks
  -fno-strict-overflow
  -ftrivial-auto-var-init=zero)

check_cxx_compiler_flag("-fcf-protection=full" HAS_CF_PROTECTION)
if(HAS_CF_PROTECTION)
  add_compile_options(-fcf-protection=full)
endif()

check_cxx_compiler_flag("-mbranch-protection=standard" HAS_BRANCH_PROTECTION)
if(HAS_BRANCH_PROTECTION)
  add_compile_options(-mbranch-protection=standard)
endif()

add_link_options(-Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now
                 -Wl,--as-needed -Wl,--no-copy-dt-needed-entries)

option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" ON)

add_compile_options(-fno-omit-frame-pointer)

if(ENABLE_TSAN)
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_TSAN requires Clang toolchain.")
  endif()
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
elseif(ENABLE_ASAN)
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
else()
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>")
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
endif()

option(ENABLE_COVERAGE "Enable code coverage" OFF)
if(ENABLE_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                              "AppleClang")
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
  else()
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
  endif()
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost 1.89 REQUIRED)

set(SOCKS_SOURCES
    log.cpp
    config.cpp
    net_utils.cpp
    mux_connection.cpp
    remote_server.cpp
    remote_server_stream.cpp
    socks_client.cpp
    router.cpp
    socks_session.cpp
    tcp_socks_session.cpp
    udp_socks_session.cpp
    mux_dispatcher.cpp
    reality_messages.cpp
    tls_cipher_suite.cpp
    tls_record_validation.cpp
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
    monitor_server.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND SOCKS_SOURCES tproxy_client.cpp tproxy_tcp_session.cpp
       tproxy_udp_session.cpp tproxy_udp_sender.cpp)
endif()

add_library(socks_core STATIC ${SOCKS_SOURCES})

target_include_directories(socks_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(
  socks_core SYSTEM
  PUBLIC ${OPENSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS}
         ${CMAKE_CURRENT_SOURCE_DIR}/third/spdlog/include
         ${CMAKE_CURRENT_SOURCE_DIR}/third/rapidjson/include)

target_link_libraries(socks_core PUBLIC OpenSSL::SSL OpenSSL::Crypto
                                        Threads::Threads)

add_executable(socks main.cpp)
target_link_libraries(socks PRIVATE socks_core)

find_package(GTest)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip)
  set(gtest_force_shared_crt
      ON
      CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

enable_testing()
add_subdirectory(tests)

option(ENABLE_FUZZING "Enable fuzz testing" OFF)
if(ENABLE_FUZZING)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzing requires Clang compiler")
  endif()

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
