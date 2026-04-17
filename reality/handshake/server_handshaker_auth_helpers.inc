reality::auth_payload decrypt_auth_payload(server_handshake_state& state, const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    const auto inputs = build_auth_decrypt_inputs(state, private_key, ec);
    if (ec)
    {
        return {};
    }
    state.auth_key = inputs.auth_key;

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    auto plaintext = tls::crypto_util::aead_decrypt(auth_cipher, inputs.auth_key, inputs.nonce, state.client_hello.session_id, inputs.aad, ec);
    if (ec || plaintext.size() != 16)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} sni {} auth fail decrypt failed tag mismatch pt size {}",
                  relay::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  plaintext.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }

    auto payload = parse_auth_payload(plaintext);
    if (!payload)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    return *payload;
}

bool verify_auth_payload_fields(const auth_payload& auth, const std::vector<uint8_t>& short_id_bytes, const server_handshake_state& state)
{
    (void)state;
    if (auth.version_x != 1 || auth.version_y != 0 || auth.version_z != 0)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} auth fail version mismatch {}.{}.{}",
                 relay::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context),
                 auth.version_x,
                 auth.version_y,
                 auth.version_z);
        return false;
    }

    if (short_id_bytes.empty())
    {
        return true;
    }

    if (short_id_bytes.size() > kShortIdMaxLen)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} sni {} auth fail short id length invalid {}",
                  relay::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  short_id_bytes.size());
        return false;
    }

    std::array<uint8_t, kShortIdMaxLen> expected_short_id = {};
    std::ranges::copy(short_id_bytes, expected_short_id.begin());
    if (CRYPTO_memcmp(auth.short_id.data(), expected_short_id.data(), expected_short_id.size()) != 0)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} auth fail short id mismatch",
                 relay::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return false;
    }
    return true;
}

bool verify_auth_timestamp(uint32_t timestamp, const server_handshake_state& state)
{
    (void)state;
    const auto now_tp = std::chrono::system_clock::now();
    const auto ts_tp = std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
    const auto diff = (now_tp > ts_tp) ? (now_tp - ts_tp) : (ts_tp - now_tp);
    const auto diff_sec = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
    const auto max_diff = std::chrono::seconds(constants::auth::kMaxClockSkewSec);
    if (diff > max_diff)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} clock skew too large diff {}s",
                 relay::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context),
                 diff_sec);
        return false;
    }
    return true;
}

bool verify_replay_guard(relay::replay_cache& replay_cache, const server_handshake_state& state)
{
    if (!replay_cache.check_and_insert(state.client_hello.session_id))
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} replay attack detected",
                 relay::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return false;
    }
    return true;
}
