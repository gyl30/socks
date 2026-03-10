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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(SOCKS_HAS_TPROXY ON)
else()
  set(SOCKS_HAS_TPROXY OFF)
endif()

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

add_compile_options(-D_GLIBCXX_ASSERTIONS -fstack-protector-strong
                    -fno-delete-null-pointer-checks -fno-strict-overflow)

check_cxx_compiler_flag("-fstrict-flex-arrays=3" HAS_STRICT_FLEX_ARRAYS)
if(HAS_STRICT_FLEX_ARRAYS)
  add_compile_options(-fstrict-flex-arrays=3)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  check_cxx_compiler_flag("-fstack-clash-protection" HAS_STACK_CLASH_PROTECTION)
  if(HAS_STACK_CLASH_PROTECTION)
    add_compile_options(-fstack-clash-protection)
  endif()
endif()

check_cxx_compiler_flag("-fcf-protection=full" HAS_CF_PROTECTION)
if(HAS_CF_PROTECTION)
  add_compile_options(-fcf-protection=full)
endif()

check_cxx_compiler_flag("-mbranch-protection=standard" HAS_BRANCH_PROTECTION)
if(HAS_BRANCH_PROTECTION)
  add_compile_options(-mbranch-protection=standard)
endif()

if(SOCKS_HAS_TPROXY)
  add_link_options(-Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now
                   -Wl,--as-needed -Wl,--no-copy-dt-needed-entries)
endif()

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
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_ASAN requires Clang toolchain.")
  endif()
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
else()
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>")
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
endif()

if(NOT ENABLE_TSAN AND NOT ENABLE_ASAN)
  check_cxx_compiler_flag("-ftrivial-auto-var-init=zero"
                          HAS_TRIVIAL_AUTO_VAR_INIT_ZERO)
  if(HAS_TRIVIAL_AUTO_VAR_INIT_ZERO)
    add_compile_options(-ftrivial-auto-var-init=zero)
  endif()
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

if(EXISTS "/home/gyl/openssl")
  set(OPENSSL_ROOT_DIR
      "/home/gyl/openssl"
      CACHE PATH "Custom OpenSSL root directory" FORCE)
  list(PREPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib64/cmake/OpenSSL")
    set(OpenSSL_DIR
        "${OPENSSL_ROOT_DIR}/lib64/cmake/OpenSSL"
        CACHE PATH "Custom OpenSSL config directory" FORCE)
  endif()
endif()

set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED CONFIG)
find_package(Boost 1.89 REQUIRED)
find_library(BROTLIDEC_LIBRARY NAMES brotlidec REQUIRED)
find_library(BROTLICOMMON_LIBRARY NAMES brotlicommon REQUIRED)

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
    reality_auth.cpp
    monitor_server.cpp
    cert_fetcher.cpp
    cert_manager.cpp
    certificate_compression.cpp)

if(SOCKS_HAS_TPROXY)
  list(APPEND SOCKS_SOURCES tproxy_client.cpp tproxy_tcp_session.cpp
       tproxy_udp_session.cpp)
endif()

add_library(core STATIC ${SOCKS_SOURCES})

if(SOCKS_HAS_TPROXY)
  target_compile_definitions(core PUBLIC SOCKS_HAS_TPROXY=1)
else()
  target_compile_definitions(core PUBLIC SOCKS_HAS_TPROXY=0)
endif()

target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(
  core SYSTEM
  PUBLIC ${Boost_INCLUDE_DIRS}
         ${CMAKE_CURRENT_SOURCE_DIR}/third/spdlog/include
         ${CMAKE_CURRENT_SOURCE_DIR}/third/rapidjson/include)

target_link_libraries(core PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(core PUBLIC ws2_32 mswsock)
endif()

add_executable(socks main.cpp)
target_link_libraries(socks PRIVATE core)

if(DEFINED OPENSSL_ROOT_DIR)
  set(OPENSSL_RUNTIME_DIRS "")
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib64")
    list(APPEND OPENSSL_RUNTIME_DIRS "${OPENSSL_ROOT_DIR}/lib64")
  endif()
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib")
    list(APPEND OPENSSL_RUNTIME_DIRS "${OPENSSL_ROOT_DIR}/lib")
  endif()
  if(OPENSSL_RUNTIME_DIRS)
    set_target_properties(
      socks
      PROPERTIES BUILD_RPATH "${OPENSSL_RUNTIME_DIRS}"
                 INSTALL_RPATH "${OPENSSL_RUNTIME_DIRS}")
  endif()
endif()
