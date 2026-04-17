std::optional<server_accept_result> authenticate_client_hello(server_handshake_state& state,
                                                              const std::vector<uint8_t>& private_key,
                                                              const std::vector<uint8_t>& short_id_bytes,
                                                              boost::system::error_code& ec)
{
    auto auth = decrypt_auth_payload(state, private_key, ec);
    if (ec)
    {
        ec.clear();
        return make_decision_result(accept_mode::kFallbackToTarget, "decrypt_auth_payload_failed", state);
    }
    if (!verify_auth_payload_fields(auth, short_id_bytes, state))
    {
        return make_decision_result(accept_mode::kFallbackToTarget, "verify_auth_payload_failed", state);
    }
    if (!verify_auth_timestamp(auth.timestamp, state))
    {
        return make_decision_result(accept_mode::kFallbackToTarget, "verify_auth_timestamp_failed", state);
    }

    return std::nullopt;
}

std::optional<server_accept_result> finalize_client_hello_authentication(server_handshake_state& state, relay::replay_cache& replay_cache)
{
    LOG_INFO("{} conn {} local {}:{} remote {}:{} sni {} client hello selected key share group 0x{:04x} {} client hybrid {} client x25519 {}",
             relay::log_event::kHandshake,
             state.log_context.conn_id,
             state.log_context.local_addr,
             state.log_context.local_port,
             state.log_context.remote_addr,
             state.log_context.remote_port,
             server_log_sni(state.log_context),
             state.key_share_group,
             tls::named_group_name(state.key_share_group),
             state.client_hello.has_x25519_mlkem768_share,
             state.client_hello.has_x25519_share);
    if (state.client_hello_handshake.size() < 4)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} sni {} buffer too short",
                  relay::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "client_hello_message_too_short", state);
    }
    if (!verify_replay_guard(replay_cache, state))
    {
        return make_decision_result(accept_mode::kReject, "replay_attack", state);
    }

    state.transcript.update(state.client_hello_handshake);
    return std::nullopt;
}

std::optional<server_accept_result> validate_client_hello_and_authenticate(server_handshake_context& handshake_ctx,
                                                                           server_handshake_state& state,
                                                                           const relay::config& cfg,
                                                                           const relay::config::reality_inbound_t& settings,
                                                                           const std::vector<uint8_t>& private_key,
                                                                           const std::vector<uint8_t>& short_id_bytes,
                                                                           relay::replay_cache& replay_cache,
                                                                           boost::system::error_code& ec)
{
    (void)cfg;
    if (auto result = validate_client_hello_sni_and_extensions(handshake_ctx, state, settings); result.has_value())
    {
        return result;
    }
    if (auto result = validate_client_hello_tls13_requirements(state); result.has_value())
    {
        return result;
    }
    if (auto result = extract_client_key_share(state); result.has_value())
    {
        return result;
    }
    if (auto result = authenticate_client_hello(state, private_key, short_id_bytes, ec); result.has_value())
    {
        return result;
    }

    return finalize_client_hello_authentication(state, replay_cache);
}
