cmake_minimum_required(VERSION 3.16)

macro(add_socks_test NAME SOURCES)
    add_executable(${NAME} ${NAME}.cpp ${SOURCES})
    target_link_libraries(${NAME} PRIVATE
        GTest::gtest_main
        GTest::gmock_main
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
    )
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../third/asio/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../third/spdlog/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../third/rapidjson/include
    )
    include(GoogleTest)
    gtest_discover_tests(${NAME} DISCOVERY_TIMEOUT 60)
endmacro()

set(COMMON_SOURCES ../log.cpp ../log_context.cpp ../reality_auth.cpp)
set(CRYPTO_SOURCES ../crypto_util.cpp)
set(REALITY_SOURCES ../tls_record_layer.cpp ../reality_fingerprint.cpp ../reality_messages.cpp ../transcript.cpp ../reality_engine.cpp ${CRYPTO_SOURCES})
set(MUX_SOURCES ../mux_connection.cpp ../mux_stream.cpp ../mux_dispatcher.cpp ../mux_codec.cpp ${REALITY_SOURCES})

add_socks_test(cert_manager_test "../cert_manager.cpp;${REALITY_SOURCES};${COMMON_SOURCES}")
add_socks_test(log_test "${COMMON_SOURCES}")
add_socks_test(transcript_test "${REALITY_SOURCES};${COMMON_SOURCES}")
add_socks_test(log_context_test "${COMMON_SOURCES}")
add_socks_test(context_pool_test "../context_pool.cpp;${COMMON_SOURCES}")
add_socks_test(reality_engine_test "${REALITY_SOURCES};${COMMON_SOURCES}")
add_socks_test(ip_matcher_test "../ip_matcher.cpp;${COMMON_SOURCES}")
add_socks_test(mux_codec_test "../mux_codec.cpp;${COMMON_SOURCES}")
add_socks_test(socks_codec_test "../protocol.cpp;${COMMON_SOURCES}")
add_socks_test(crypto_util_test "${CRYPTO_SOURCES};${COMMON_SOURCES}")
add_socks_test(router_test "../router.cpp;../ip_matcher.cpp;../domain_matcher.cpp;${COMMON_SOURCES}")
add_socks_test(domain_matcher_test "../domain_matcher.cpp;${COMMON_SOURCES}")
add_socks_test(ch_parser_test "../ch_parser.cpp;${COMMON_SOURCES}")
add_socks_test(reality_messages_test "../reality_messages.cpp;${REALITY_SOURCES};${COMMON_SOURCES}")
add_socks_test(tls_record_layer_test "../tls_record_layer.cpp;${CRYPTO_SOURCES};${COMMON_SOURCES}")
add_socks_test(config_test "../config.cpp;${COMMON_SOURCES}")
add_socks_test(reflect_test "${COMMON_SOURCES}")

add_socks_test(local_client_test 
    "../local_client.cpp;../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")

add_socks_test(reality_fingerprint_test "${REALITY_SOURCES};${COMMON_SOURCES}")
add_socks_test(reality_auth_test "../reality_auth.cpp;${COMMON_SOURCES}")
add_socks_test(mux_stream_test "${MUX_SOURCES};${COMMON_SOURCES}")
add_socks_test(mux_connection_test "${MUX_SOURCES};${COMMON_SOURCES}")
add_socks_test(mux_dispatcher_test "../mux_dispatcher.cpp;../mux_codec.cpp;${COMMON_SOURCES}")
add_socks_test(replay_cache_test "../replay_cache.cpp;${COMMON_SOURCES}")
add_socks_test(upstream_test "../upstream.cpp;${MUX_SOURCES};${COMMON_SOURCES}")

add_socks_test(cert_fetcher_test "../cert_fetcher.cpp;../tls_record_layer.cpp;../reality_fingerprint.cpp;../reality_messages.cpp;../transcript.cpp;../reality_engine.cpp;../ch_parser.cpp;${CRYPTO_SOURCES};${COMMON_SOURCES}")

add_socks_test(key_rotator_test "../key_rotator.cpp;${CRYPTO_SOURCES};${COMMON_SOURCES}")

add_socks_test(local_client_mock_test 
    "../local_client.cpp;../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")

add_socks_test(client_server_integration_test 
    "../local_client.cpp;../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")

add_socks_test(limits_test 
    "../local_client.cpp;../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")

add_socks_test(udp_integration_test 
    "../local_client.cpp;../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")
add_socks_test(remote_server_test 
    "../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")

add_socks_test(remote_server_mux_test 
    "../local_client.cpp;../remote_server.cpp;../router.cpp;../socks_session.cpp;../tcp_socks_session.cpp;../udp_socks_session.cpp;../cert_fetcher.cpp;../ch_parser.cpp;../ip_matcher.cpp;../remote_session.cpp;../remote_udp_session.cpp;../upstream.cpp;../protocol.cpp;../config.cpp;../context_pool.cpp;../replay_cache.cpp;../domain_matcher.cpp;../cert_manager.cpp;../key_rotator.cpp;${MUX_SOURCES};${COMMON_SOURCES}")
