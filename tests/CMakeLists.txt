cmake_minimum_required(VERSION 3.16)

macro(add_socks_test NAME)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE
        socks_core
        GTest::gtest_main
        GTest::gmock_main
    )
    include(GoogleTest)
    gtest_discover_tests(${NAME} DISCOVERY_TIMEOUT 60)
endmacro()

add_socks_test(cert_manager_test)
add_socks_test(log_test)
add_socks_test(transcript_test)
add_socks_test(log_context_test)
add_socks_test(context_pool_test)
add_socks_test(statistics_test)
add_socks_test(monitor_server_test)
add_socks_test(net_utils_test)
add_socks_test(reality_engine_test)
add_socks_test(ip_matcher_test)
add_socks_test(mux_codec_test)
add_socks_test(socks_codec_test)
add_socks_test(socks_session_test)
add_socks_test(crypto_util_test)
target_link_options(
    crypto_util_test
    PRIVATE
        -Wl,--wrap=EVP_PKEY_CTX_set1_hkdf_key
        -Wl,--wrap=EVP_PKEY_CTX_set1_hkdf_salt
        -Wl,--wrap=EVP_CIPHER_CTX_ctrl
)
add_socks_test(router_test)
add_socks_test(domain_matcher_test)
add_socks_test(ch_parser_test)
add_socks_test(reality_messages_test)
add_socks_test(tls_cipher_suite_test)
add_socks_test(tls_record_validation_test)
add_socks_test(tls_record_layer_test)
add_socks_test(config_test)
add_socks_test(reflect_test)
add_socks_test(tls_key_schedule_test)
add_socks_test(socks_client_test)
add_socks_test(reality_fingerprint_test)
add_socks_test(reality_auth_test)
add_socks_test(mux_stream_test)
add_socks_test(mux_connection_test)
add_socks_test(mux_heartbeat_test)
target_compile_definitions(mux_heartbeat_test PRIVATE SPDLOG_ACTIVE_LEVEL=0)
add_socks_test(mux_dispatcher_test)
add_socks_test(replay_cache_test)
add_socks_test(upstream_test)
add_socks_test(cert_fetcher_test)
add_socks_test(key_rotator_test)
add_socks_test(socks_client_mock_test)
add_socks_test(socks_client_handshake_test)
add_socks_test(client_tunnel_pool_policy_test)
add_socks_test(client_tunnel_pool_whitebox_test)
add_socks_test(client_server_integration_test)
add_socks_test(connection_pool_test)
add_socks_test(limits_test)
add_socks_test(udp_integration_test)
add_socks_test(protocol_edge_test)
add_socks_test(socks_protocol_test)
add_socks_test(remote_server_test)
add_socks_test(remote_server_mux_test)
add_socks_test(tproxy_udp_session_test)
target_link_options(
    tproxy_udp_session_test
    PRIVATE
        -Wl,--wrap=setsockopt
        -Wl,--wrap=recvmsg
)
add_socks_test(tproxy_tcp_session_test)
add_socks_test(tproxy_udp_sender_test)
add_socks_test(udp_socks_session_test)
add_socks_test(router_file_test)

add_test(NAME tproxy_integration_test COMMAND ${CMAKE_SOURCE_DIR}/tests/tproxy_integration_test.sh)
set_tests_properties(tproxy_integration_test PROPERTIES SKIP_RETURN_CODE 77)
set_tests_properties(tproxy_integration_test PROPERTIES ENVIRONMENT "BIN=${CMAKE_BINARY_DIR}/socks")
