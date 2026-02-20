cmake_minimum_required(VERSION 3.16)

set(MSAN_UMR_NOISE_OPTIONS
    "intercept_strlen=0:intercept_strcmp=0:intercept_strndup=0:intercept_strchr=0:intercept_memcmp=0:intercept_strstr=0:intercept_strspn=0:intercept_strtok=0:intercept_strpbrk=0:intercept_memmem=0")

function(register_socks_gtest_target TARGET_NAME LOCK_NAME)
    add_test(
        NAME ${TARGET_NAME}
        COMMAND
            ${CMAKE_COMMAND}
            -E
            env
            --unset=DART_TEST_FROM_DART
            --unset=CTEST_INTERACTIVE_DEBUG_MODE
            /bin/bash
            -c
            "exec 3>&-; \"\$1\" --gtest_brief=1"
            __socks_test_runner__
            $<TARGET_FILE:${TARGET_NAME}>
    )

    if(CMAKE_CXX_FLAGS MATCHES "-fsanitize=memory")
        set_tests_properties(
            ${TARGET_NAME}
            PROPERTIES
                ENVIRONMENT "MSAN_OPTIONS=${MSAN_UMR_NOISE_OPTIONS}"
                RESOURCE_LOCK "${LOCK_NAME}"
        )
    else()
        set_tests_properties(
            ${TARGET_NAME}
            PROPERTIES
                RESOURCE_LOCK "${LOCK_NAME}"
        )
    endif()
endfunction()

macro(add_socks_test NAME)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE
        socks_core
        GTest::gtest_main
        GTest::gmock_main
    )
    register_socks_gtest_target(${NAME} "net_ports")
endmacro()

macro(add_socks_locked_test NAME LOCK_NAME)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE
        socks_core
        GTest::gtest_main
        GTest::gmock_main
    )
    register_socks_gtest_target(${NAME} "${LOCK_NAME}")
endmacro()

add_socks_test(cert_manager_test)
add_socks_test(log_test)
add_socks_test(transcript_test)
add_socks_test(log_context_test)
add_socks_test(context_pool_test)
add_socks_test(statistics_test)

# Tests that use -Wl,--wrap (GNU ld only, not available on macOS Apple ld)
if(LINUX)
    add_socks_test(monitor_server_test)
    target_link_options(
        monitor_server_test
        PRIVATE
            -Wl,--wrap=socket
            -Wl,--wrap=setsockopt
            -Wl,--wrap=listen
            -Wl,--wrap=accept
            -Wl,--wrap=accept4
            -Wl,--wrap=close
    )
    add_socks_test(net_utils_test)
    target_link_options(
        net_utils_test
        PRIVATE
            -Wl,--wrap=setsockopt
    )
endif()

add_socks_test(reality_engine_test)
add_socks_test(ip_matcher_test)
add_socks_test(mux_codec_test)
add_socks_test(socks_codec_test)
add_socks_test(timeout_io_test)

if(LINUX)
    add_socks_test(socks_session_test)
    target_link_options(
        socks_session_test
        PRIVATE
            -Wl,--wrap=shutdown
            -Wl,--wrap=close
    )
    add_socks_test(crypto_util_test)
    target_link_options(
        crypto_util_test
        PRIVATE
            -Wl,--wrap=EVP_PKEY_CTX_set1_hkdf_key
            -Wl,--wrap=EVP_PKEY_CTX_set1_hkdf_salt
            -Wl,--wrap=EVP_CIPHER_CTX_ctrl
            -Wl,--wrap=X509_get_pubkey
            -Wl,--wrap=RAND_bytes
            -Wl,--wrap=EVP_PKEY_CTX_new_id
            -Wl,--wrap=EVP_PKEY_new_raw_private_key
            -Wl,--wrap=EVP_PKEY_CTX_add1_hkdf_info
            -Wl,--wrap=EVP_MD_CTX_new
            -Wl,--wrap=EVP_PKEY_derive
    )
endif()

add_socks_test(router_test)
add_socks_test(domain_matcher_test)
add_socks_test(ch_parser_test)

if(LINUX)
    add_socks_test(reality_messages_test)
    target_link_options(
        reality_messages_test
        PRIVATE
            -Wl,--wrap=RAND_bytes
            -Wl,--wrap=EVP_PKEY_CTX_new_id
            -Wl,--wrap=EVP_PKEY_keygen
            -Wl,--wrap=EVP_PKEY_get_octet_string_param
            -Wl,--wrap=EVP_MD_CTX_new
            -Wl,--wrap=EVP_DigestSign
    )
endif()

add_socks_test(tls_cipher_suite_test)
add_socks_test(tls_record_validation_test)

if(LINUX)
    add_socks_test(tls_record_layer_test)
    target_link_options(
        tls_record_layer_test
        PRIVATE
            -Wl,--wrap=RAND_bytes
    )
    add_socks_test(config_test)
    target_link_options(
        config_test
        PRIVATE
            -Wl,--wrap=fread
            -Wl,--wrap=ferror
    )
endif()

add_socks_test(reflect_test)

if(LINUX)
    add_socks_test(tls_key_schedule_test)
    target_link_options(
        tls_key_schedule_test
        PRIVATE
            -Wl,--wrap=EVP_PKEY_derive
    )
    add_socks_locked_test(socks_client_test net_ports)
    target_link_options(
        socks_client_test
        PRIVATE
            -Wl,--wrap=socket
            -Wl,--wrap=setsockopt
            -Wl,--wrap=bind
            -Wl,--wrap=accept
            -Wl,--wrap=accept4
            -Wl,--wrap=close
    )
endif()

add_socks_test(reality_fingerprint_test)
add_socks_test(reality_auth_test)
add_socks_test(mux_stream_test)
add_socks_test(mux_connection_test)
if(LINUX)
    target_link_options(
        mux_connection_test
        PRIVATE
            -Wl,--wrap=RAND_bytes
    )
endif()
add_socks_test(mux_tunnel_test)
add_socks_test(mux_heartbeat_test)
target_compile_definitions(mux_heartbeat_test PRIVATE SPDLOG_ACTIVE_LEVEL=0)
add_socks_test(mux_dispatcher_test)
add_socks_test(replay_cache_test)

if(LINUX)
    add_socks_test(upstream_test)
    target_link_options(
        upstream_test
        PRIVATE
            -Wl,--wrap=setsockopt
    )
    add_socks_test(cert_fetcher_test)
    target_link_options(
        cert_fetcher_test
        PRIVATE
            -Wl,--wrap=EVP_PKEY_CTX_set_hkdf_md
            -Wl,--wrap=EVP_PKEY_keygen
            -Wl,--wrap=RAND_bytes
    )
endif()

add_socks_test(key_rotator_test)
add_socks_test(socks_client_mock_test)
add_socks_test(socks_client_handshake_test)
add_socks_locked_test(client_tunnel_pool_policy_test net_ports)

if(LINUX)
    add_socks_locked_test(client_tunnel_pool_whitebox_test net_ports)
    target_link_options(
        client_tunnel_pool_whitebox_test
        PRIVATE
            -Wl,--wrap=RAND_bytes
            -Wl,--wrap=EVP_PKEY_CTX_add1_hkdf_info
            -Wl,--wrap=EVP_CIPHER_CTX_ctrl
            -Wl,--wrap=EVP_PKEY_derive
            -Wl,--wrap=EVP_EncryptInit_ex
            -Wl,--wrap=socket
            -Wl,--wrap=getsockname
    )
endif()

add_socks_locked_test(client_server_integration_test net_ports)
add_socks_test(connection_pool_test)
add_socks_test(limits_test)
add_socks_locked_test(udp_integration_test net_ports)
add_socks_test(protocol_edge_test)
add_socks_test(socks_protocol_test)

if(LINUX)
    add_socks_locked_test(remote_server_test net_ports)
    target_link_options(
        remote_server_test
        PRIVATE
            -Wl,--wrap=socket
            -Wl,--wrap=setsockopt
            -Wl,--wrap=listen
            -Wl,--wrap=shutdown
            -Wl,--wrap=close
            -Wl,--wrap=send
            -Wl,--wrap=sendmsg
            -Wl,--wrap=RAND_bytes
            -Wl,--wrap=EVP_PKEY_new_raw_private_key
            -Wl,--wrap=EVP_PKEY_derive
            -Wl,--wrap=EVP_PKEY_CTX_add1_hkdf_info
    )
endif()

add_socks_locked_test(remote_server_mux_test net_ports)

if(LINUX)
    add_socks_locked_test(tproxy_udp_session_test net_ports)
    target_link_options(
        tproxy_udp_session_test
        PRIVATE
            -Wl,--wrap=socket
            -Wl,--wrap=setsockopt
            -Wl,--wrap=bind
            -Wl,--wrap=recvmsg
            -Wl,--wrap=accept
            -Wl,--wrap=accept4
            -Wl,--wrap=getsockname
            -Wl,--wrap=close
    )
    add_socks_test(tproxy_tcp_session_test)
    target_link_options(
        tproxy_tcp_session_test
        PRIVATE
            -Wl,--wrap=shutdown
            -Wl,--wrap=close
    )
    add_socks_test(tproxy_udp_sender_test)
    target_link_options(
        tproxy_udp_sender_test
        PRIVATE
            -Wl,--wrap=socket
            -Wl,--wrap=setsockopt
    )
    add_socks_test(udp_socks_session_test)
    target_link_options(
        udp_socks_session_test
        PRIVATE
            -Wl,--wrap=bind
            -Wl,--wrap=setsockopt
            -Wl,--wrap=getsockname
            -Wl,--wrap=close
    )
    add_socks_locked_test(tcp_socks_session_test net_ports)
    target_link_options(
        tcp_socks_session_test
        PRIVATE
            -Wl,--wrap=shutdown
            -Wl,--wrap=close
    )
    add_socks_test(remote_session_test)
    target_link_options(
        remote_session_test
        PRIVATE
            -Wl,--wrap=setsockopt
    )
endif()

add_socks_test(remote_udp_session_test)
target_link_options(
    remote_udp_session_test
    PRIVATE
        -Wl,--wrap=getaddrinfo
)
add_socks_test(router_file_test)

if(LINUX)
    add_test(NAME tproxy_integration_test COMMAND ${CMAKE_SOURCE_DIR}/tests/tproxy_integration_test.sh)
    set_tests_properties(
        tproxy_integration_test
        PROPERTIES
            SKIP_RETURN_CODE 77
            RESOURCE_LOCK "net_ports"
    )
    if(CMAKE_CXX_FLAGS MATCHES "-fsanitize=memory")
        set_tests_properties(tproxy_integration_test PROPERTIES ENVIRONMENT "BIN=${CMAKE_BINARY_DIR}/socks;MSAN_OPTIONS=${MSAN_UMR_NOISE_OPTIONS}")
    else()
        set_tests_properties(tproxy_integration_test PROPERTIES ENVIRONMENT "BIN=${CMAKE_BINARY_DIR}/socks")
    endif()
endif()

if(RG_EXECUTABLE)
    set(NO_EXCEPTION_CHECK_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/no_exception_keywords_test.cmake")
    file(
        WRITE
        "${NO_EXCEPTION_CHECK_SCRIPT}"
        "if(NOT DEFINED PROJECT_SOURCE_DIR)\n"
        "    message(FATAL_ERROR \"PROJECT_SOURCE_DIR missing\")\n"
        "endif()\n"
        "if(NOT DEFINED RG_EXECUTABLE)\n"
        "    message(FATAL_ERROR \"RG_EXECUTABLE missing\")\n"
        "endif()\n"
        "execute_process(\n"
        "    COMMAND \"\${RG_EXECUTABLE}\" -n \"\\\\bthrow\\\\b|\\\\btry\\\\b|\\\\bcatch\\\\b\" --glob \"*.{cpp,h}\" --glob \"!third/**\" --glob \"!build/**\" --glob \"!**/build/**\" \"\${PROJECT_SOURCE_DIR}\"\n"
        "    RESULT_VARIABLE rg_exit\n"
        "    OUTPUT_VARIABLE rg_output\n"
        "    ERROR_VARIABLE rg_error\n"
        "    OUTPUT_STRIP_TRAILING_WHITESPACE\n"
        "    ERROR_STRIP_TRAILING_WHITESPACE\n"
        ")\n"
        "if(rg_exit EQUAL 0)\n"
        "    message(FATAL_ERROR \"exception keywords found\\n\${rg_output}\")\n"
        "endif()\n"
        "if(NOT rg_exit EQUAL 1)\n"
        "    message(FATAL_ERROR \"rg execution failed with code \${rg_exit}\\n\${rg_error}\")\n"
        "endif()\n"
    )
    add_test(
        NAME no_exception_keywords_test
        COMMAND
            ${CMAKE_COMMAND}
            -DPROJECT_SOURCE_DIR=${CMAKE_SOURCE_DIR}
            -DRG_EXECUTABLE=${RG_EXECUTABLE}
            -P
            ${NO_EXCEPTION_CHECK_SCRIPT}
    )
    set_tests_properties(no_exception_keywords_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
else()
    message(WARNING "rg not found no_exception_keywords_test disabled")
endif()

if(Python3_Interpreter_FOUND)
    add_test(
        NAME valgrind_script_args_test
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/script/valgrind_test.py --self-test-args
    )
endif()
