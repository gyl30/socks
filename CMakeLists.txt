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

find_package(OpenSSL REQUIRED)

add_executable(socks main.cpp log.cpp config.cpp mux_connection.cpp remote_server.cpp local_client.cpp router.cpp socks_session.cpp tcp_socks_session.cpp udp_socks_session.cpp mux_dispatcher.cpp reality_messages.cpp cert_fetcher.cpp crypto_util.cpp reality_fingerprint.cpp ch_parser.cpp tls_record_layer.cpp)

target_include_directories(socks PRIVATE 
    ${OPENSSL_INCLUDE_DIR} 
    third/asio/include
    third/spdlog/include 
    third/rapidjson/include
)

target_link_libraries(socks PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
