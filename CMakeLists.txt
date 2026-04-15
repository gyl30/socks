cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
   CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(SOCKS_HAS_TUN ON)
else()
  set(SOCKS_HAS_TUN OFF)
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

option(ENABLE_STRICT_WARNINGS "Enable stricter C++ warning set" OFF)
if(ENABLE_STRICT_WARNINGS)
  add_compile_options(
    "$<$<COMPILE_LANGUAGE:CXX>:-Wshadow>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wcast-qual>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wsign-conversion>")
endif()

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
option(ENABLE_LSAN "Enable LeakSanitizer" OFF)
option(ENABLE_FUZZ "Enable libFuzzer targets" OFF)
option(ENABLE_STATIC_LINK "Link executable and third-party dependencies statically" OFF)

if(ENABLE_STATIC_LINK)
  set(BUILD_SHARED_LIBS OFF)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  add_link_options(-static)
endif()

if(ENABLE_FUZZ)
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_FUZZ requires Clang toolchain.")
  endif()
  add_compile_options(-fno-common)
  set(ENABLE_TSAN OFF)
  set(ENABLE_ASAN OFF)
  set(ENABLE_LSAN OFF)
endif()

add_compile_options(-fno-omit-frame-pointer)

if(ENABLE_LSAN)
  set(ENABLE_ASAN OFF)
endif()

if(ENABLE_TSAN AND ENABLE_LSAN)
  message(FATAL_ERROR "ENABLE_TSAN cannot be combined with ENABLE_LSAN.")
endif()

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
elseif(ENABLE_LSAN)
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_LSAN requires Clang toolchain.")
  endif()
  add_compile_options(-fsanitize=leak)
  add_link_options(-fsanitize=leak)
else()
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>")
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
endif()

if(NOT ENABLE_TSAN AND NOT ENABLE_ASAN AND NOT ENABLE_LSAN)
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

if(NOT DEFINED OPENSSL_ROOT_DIR AND DEFINED ENV{OPENSSL_ROOT_DIR} AND
   NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
  set(OPENSSL_ROOT_DIR
      "$ENV{OPENSSL_ROOT_DIR}"
      CACHE PATH "Custom OpenSSL root directory")
endif()

if(DEFINED OPENSSL_ROOT_DIR AND NOT "${OPENSSL_ROOT_DIR}" STREQUAL "")
  list(PREPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib64/cmake/OpenSSL")
    set(OpenSSL_DIR
        "${OPENSSL_ROOT_DIR}/lib64/cmake/OpenSSL"
        CACHE PATH "Custom OpenSSL config directory" FORCE)
  endif()
endif()

if(NOT DEFINED BROTLI_ROOT_DIR AND DEFINED ENV{BROTLI_ROOT_DIR} AND
   NOT "$ENV{BROTLI_ROOT_DIR}" STREQUAL "")
  set(BROTLI_ROOT_DIR
      "$ENV{BROTLI_ROOT_DIR}"
      CACHE PATH "Custom Brotli root directory")
endif()

set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED CONFIG)
find_package(Boost 1.89 REQUIRED)
set(SOCKS_BROTLI_HINTS "")
if(DEFINED BROTLI_ROOT_DIR AND NOT "${BROTLI_ROOT_DIR}" STREQUAL "")
  list(APPEND SOCKS_BROTLI_HINTS "${BROTLI_ROOT_DIR}")
endif()
find_library(BROTLIDEC_LIBRARY NAMES brotlidec REQUIRED
             HINTS ${SOCKS_BROTLI_HINTS}
             PATH_SUFFIXES lib lib64)
find_library(BROTLICOMMON_LIBRARY NAMES brotlicommon REQUIRED
             HINTS ${SOCKS_BROTLI_HINTS}
             PATH_SUFFIXES lib lib64)
find_path(BROTLI_INCLUDE_DIR NAMES brotli/decode.h REQUIRED
          HINTS ${SOCKS_BROTLI_HINTS}
          PATH_SUFFIXES include)

set(SOCKS_SOURCES
    app_runtime.cpp
    log.cpp
    config.cpp
    net_utils.cpp
    reality_inbound.cpp
    socks_inbound.cpp
    router.cpp
    socks_session.cpp
    tcp_socks_session.cpp
    udp_socks_session.cpp
    reality/handshake/client_hello_builder.cpp
    tls/cipher_suite.cpp
    tls/record_validation.cpp
    tls/crypto_util.cpp
    reality/handshake/fingerprint.cpp
    tls/ch_parser.cpp
    tls/record_layer.cpp
    tls/key_schedule.cpp
    ip_matcher.cpp
    reality_tcp_session.cpp
    reality_udp_session.cpp
    proxy_udp_upstream.cpp
    upstream.cpp
    proxy_protocol.cpp
    proxy_reality_connection.cpp
    protocol.cpp
    context_pool.cpp
    reality/handshake/client_handshaker.cpp
    reality/handshake/server_handshaker.cpp
    reality/policy/fallback_gate.cpp
    reality/policy/fallback_executor.cpp
    reality/material/material_provider.cpp
    reality/session/session.cpp
    tls/handshake_builder.cpp
    tls/handshake_message.cpp
    tls/handshake_reassembler.cpp
    tls/server_name.cpp
    tls/transcript.cpp
    replay_cache.cpp
    reality/session/engine.cpp
    domain_matcher.cpp
    reality/handshake/auth.cpp
    cert_fetcher.cpp
    tls/certificate_compression.cpp)

if(SOCKS_HAS_TPROXY)
  list(APPEND SOCKS_SOURCES tproxy_inbound.cpp tproxy_tcp_session.cpp
       tproxy_udp_session.cpp)
endif()

if(SOCKS_HAS_TUN)
  list(APPEND SOCKS_SOURCES
       tun_lwip.cpp
       tun_device.cpp
       tun_device_windows_helper.c
       tun_inbound.cpp
       tun_tcp_session.cpp
       tun_udp_session.cpp)
endif()

file(
  GLOB LWIP_SOURCES
  CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/core/*.c
  ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/core/ipv4/*.c
  ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/core/ipv6/*.c
  ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/api/err.c)

list(APPEND LWIP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/lwip_port.c)
list(APPEND LWIP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/ports/lib/mem.c)

add_library(lwip STATIC ${LWIP_SOURCES})
target_include_directories(
  lwip SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/include
                     ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/ports/include)
if(CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES
                                        "AppleClang" OR CMAKE_C_COMPILER_ID STREQUAL
                                        "GNU")
  target_compile_options(lwip PRIVATE -Wno-conversion -Wno-sign-conversion)
elseif(MSVC)
  target_compile_options(lwip PRIVATE /W0)
endif()

function(configure_core_target target_name)
  if(SOCKS_HAS_TPROXY)
    target_compile_definitions(${target_name} PUBLIC SOCKS_HAS_TPROXY=1)
  else()
    target_compile_definitions(${target_name} PUBLIC SOCKS_HAS_TPROXY=0)
  endif()
  if(SOCKS_HAS_TUN)
    target_compile_definitions(${target_name} PUBLIC SOCKS_HAS_TUN=1)
  else()
    target_compile_definitions(${target_name} PUBLIC SOCKS_HAS_TUN=0)
  endif()

  target_include_directories(${target_name} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

  target_include_directories(
    ${target_name} SYSTEM
    PUBLIC ${Boost_INCLUDE_DIRS}
           ${BROTLI_INCLUDE_DIR}
           ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/include
           ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip/src/ports/include
           ${CMAKE_CURRENT_SOURCE_DIR}/third/spdlog/include
           ${CMAKE_CURRENT_SOURCE_DIR}/third/rapidjson/include)

  if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_include_directories(${target_name} SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third/wintun/include)
  endif()

  target_link_libraries(${target_name} PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY} lwip)

  if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(${target_name} PUBLIC ws2_32 mswsock iphlpapi)
  endif()
endfunction()

add_library(core STATIC ${SOCKS_SOURCES})
configure_core_target(core)

if(ENABLE_FUZZ)
  add_library(
    fuzz_core STATIC
    log.cpp
    tls/ch_parser.cpp
    tls/server_name.cpp
    reality/handshake/fingerprint.cpp
    reality/handshake/client_hello_builder.cpp)
  configure_core_target(fuzz_core)
  target_compile_options(fuzz_core PRIVATE -fsanitize=fuzzer-no-link,address,undefined)
endif()

add_executable(socks main.cpp)
target_link_libraries(socks PRIVATE core)
if(UNIX AND NOT APPLE AND NOT ENABLE_STATIC_LINK)
  target_link_options(socks PRIVATE "-Wl,--no-as-needed" "${BROTLICOMMON_LIBRARY}" "-Wl,--as-needed")
endif()

if(ENABLE_FUZZ)
  add_executable(ch_parser_fuzz fuzz/ch_parser_fuzz.cpp)
  target_link_libraries(ch_parser_fuzz PRIVATE fuzz_core)
  target_compile_options(ch_parser_fuzz PRIVATE -fsanitize=fuzzer-no-link,address,undefined)
  target_link_options(ch_parser_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

set(SOCKS_RUNTIME_DIRS "")
if(DEFINED OPENSSL_ROOT_DIR)
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib64")
    list(APPEND SOCKS_RUNTIME_DIRS "${OPENSSL_ROOT_DIR}/lib64")
  endif()
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib")
    list(APPEND SOCKS_RUNTIME_DIRS "${OPENSSL_ROOT_DIR}/lib")
  endif()
endif()

get_filename_component(BROTLIDEC_RUNTIME_DIR "${BROTLIDEC_LIBRARY}" DIRECTORY)
get_filename_component(BROTLICOMMON_RUNTIME_DIR "${BROTLICOMMON_LIBRARY}" DIRECTORY)
list(APPEND SOCKS_RUNTIME_DIRS "${BROTLIDEC_RUNTIME_DIR}" "${BROTLICOMMON_RUNTIME_DIR}")
list(REMOVE_DUPLICATES SOCKS_RUNTIME_DIRS)

if(SOCKS_RUNTIME_DIRS)
  set_target_properties(
    socks
    PROPERTIES BUILD_RPATH "${SOCKS_RUNTIME_DIRS}"
               INSTALL_RPATH "${SOCKS_RUNTIME_DIRS}")
endif()
