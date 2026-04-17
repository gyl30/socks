void verify_server_certificate_verify_message(const std::vector<uint8_t>& msg_data,
                                              const tls::transcript& trans,
                                              handshake_validation_state& validation_state,
                                              boost::system::error_code& ec)
{
    if (!validation_state.cert_checked)
    {
        LOG_ERROR("{} conn {} sni {} certificate verify received before certificate",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::asio::error::invalid_argument;
        return;
    }

    const auto cert_verify = tls::parse_certificate_verify(msg_data);
    if (!cert_verify.has_value())
    {
        LOG_ERROR("{} conn {} sni {} certificate verify parse failed",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!tls::is_supported_certificate_verify_scheme(cert_verify->scheme))
    {
        LOG_ERROR("{} conn {} sni {} unsupported certificate verify scheme {:x}",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context),
                  cert_verify->scheme);
        ec = boost::asio::error::no_protocol_option;
        return;
    }
    if (validation_state.client_hello == nullptr || validation_state.client_hello->signature_algorithms.empty())
    {
        LOG_ERROR("{} conn {} sni {} certificate verify validation missing client signature algorithms",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!client_offers_signature_scheme(*validation_state.client_hello, cert_verify->scheme))
    {
        LOG_ERROR("{} conn {} sni {} server selected certificate verify scheme {:x} not advertised by client",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context),
                  cert_verify->scheme);
        ec = boost::asio::error::no_protocol_option;
        return;
    }

    if (validation_state.server_pub_key != nullptr)
    {
        const auto transcript_hash = trans.finish();
        tls::crypto_util::verify_tls13_signature(
            validation_state.server_pub_key.get(), cert_verify->scheme, transcript_hash, cert_verify->signature, ec);
        if (ec)
        {
            LOG_DEBUG("{} conn {} sni {} certificate verify signature check failed code {} message {}",
                      relay::log_event::kHandshake,
                      validation_state.log_context.conn_id,
                      handshake_log_sni(validation_state.log_context),
                      ec.value(),
                      ec.message());
        }
        else
        {
            validation_state.cert_verify_signature_checked = true;
        }
    }

    validation_state.cert_verify_checked = true;
}

void verify_server_finished_message(const std::vector<uint8_t>& msg_data,
                                    const tls::handshake_keys& hs_keys,
                                    const EVP_MD* md,
                                    const tls::transcript& trans,
                                    const handshake_log_context& log_context,
                                    boost::system::error_code& ec)
{
    const uint32_t msg_len =
        (static_cast<uint32_t>(msg_data[1]) << 16) | (static_cast<uint32_t>(msg_data[2]) << 8) | static_cast<uint32_t>(msg_data[3]);

    const auto expected_verify_data =
        tls::key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} server finished verify derive failed {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  ec.message());
        return;
    }

    if (expected_verify_data.size() != msg_len)
    {
        LOG_ERROR("{} conn {} sni {} server finished verify size mismatch {} {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  expected_verify_data.size(),
                  msg_len);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    if (CRYPTO_memcmp(msg_data.data() + 4, expected_verify_data.data(), expected_verify_data.size()) != 0)
    {
        LOG_ERROR(
            "{} conn {} sni {} server finished verify mismatch", relay::log_event::kHandshake, log_context.conn_id, handshake_log_sni(log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
}

std::optional<std::vector<uint8_t>> extract_first_cert_der(const std::vector<uint8_t>& cert_msg)
{
    std::vector<uint8_t> cert_der;
    if (!tls::extract_first_certificate(cert_msg, cert_der))
    {
        return std::nullopt;
    }
    return cert_der;
}

struct encrypted_record
{
    uint8_t content_type = 0;
    std::vector<uint8_t> ciphertext;
};

boost::asio::awaitable<encrypted_record> read_encrypted_record(boost::asio::ip::tcp::socket& socket,
                                                               uint64_t handshake_start_ms,
                                                               uint32_t timeout_sec,
                                                               const handshake_log_context& log_context,
                                                               boost::system::error_code& ec)
{
    std::array<uint8_t, 5> record_header{};
    const auto header_timeout = relay::net::remaining_timeout_seconds(handshake_start_ms, timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} handshake overall timeout {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  ec.message());
        co_return encrypted_record{};
    }
    auto read_size = co_await relay::net::wait_read_with_timeout(socket, boost::asio::buffer(record_header), header_timeout, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} error reading record header {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  ec.message());
        co_return encrypted_record{};
    }

    if (read_size != record_header.size())
    {
        ec = boost::asio::error::fault;
        LOG_ERROR("{} conn {} sni {} short read record header {} of {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  read_size,
                  record_header.size());
        co_return encrypted_record{};
    }

    const auto record_body_size = static_cast<uint16_t>((record_header[3] << 8) | record_header[4]);
    if (record_body_size > constants::tls_limits::kMaxCiphertextRecordLen)
    {
        LOG_ERROR("{} conn {} sni {} record body too large {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  record_body_size);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return encrypted_record{};
    }
    std::vector<uint8_t> record_body(record_body_size);
    const auto body_timeout = relay::net::remaining_timeout_seconds(handshake_start_ms, timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} handshake overall timeout {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  ec.message());
        co_return encrypted_record{};
    }
    read_size = co_await relay::net::wait_read_with_timeout(socket, boost::asio::buffer(record_body), body_timeout, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} error reading record payload {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  ec.message());
        co_return encrypted_record{};
    }
    if (read_size != record_body_size)
    {
        ec = boost::asio::error::fault;
        LOG_ERROR("{} conn {} sni {} short read record payload {} of {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  read_size,
                  record_body_size);
        co_return encrypted_record{};
    }
    if (record_header[0] == tls::kContentTypeChangeCipherSpec)
    {
        const uint8_t ccs_body = record_body_size == 1 ? record_body[0] : 0;
        if (!tls::is_valid_tls13_compat_ccs(record_header, ccs_body))
        {
            LOG_ERROR("{} conn {} sni {} invalid tls13 compat ccs len {} body {}",
                      relay::log_event::kHandshake,
                      log_context.conn_id,
                      handshake_log_sni(log_context),
                      record_body_size,
                      ccs_body);
            ec = boost::asio::error::invalid_argument;
            co_return encrypted_record{};
        }
    }
    else if (record_header[0] != tls::kContentTypeApplicationData)
    {
        LOG_ERROR("{} conn {} sni {} unexpected encrypted record type {}",
                  relay::log_event::kHandshake,
                  log_context.conn_id,
                  handshake_log_sni(log_context),
                  static_cast<int>(record_header[0]));
        ec = boost::asio::error::invalid_argument;
        co_return encrypted_record{};
    }

    std::vector<uint8_t> ciphertext(record_header.size() + record_body_size);
    std::memcpy(ciphertext.data(), record_header.data(), record_header.size());
    std::memcpy(ciphertext.data() + record_header.size(), record_body.data(), record_body_size);
    co_return encrypted_record{.content_type = record_header[0], .ciphertext = std::move(ciphertext)};
}

void reject_unexpected_handshake_message(const handshake_validation_state& validation_state, const char* reason, boost::system::error_code& ec)
{
    LOG_ERROR("{} conn {} sni {} {}",
              relay::log_event::kHandshake,
              validation_state.log_context.conn_id,
              handshake_log_sni(validation_state.log_context),
              reason);
    ec = boost::asio::error::invalid_argument;
}

bool validate_encrypted_extensions_order(const handshake_validation_state& validation_state, const bool handshake_fin, boost::system::error_code& ec)
{
    if (validation_state.encrypted_extensions_checked || validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
    {
        reject_unexpected_handshake_message(validation_state, "unexpected encrypted extensions order", ec);
        return false;
    }
    if (validation_state.client_hello == nullptr)
    {
        LOG_ERROR("{} conn {} sni {} missing client hello for encrypted extensions",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::asio::error::fault;
        return false;
    }
    return true;
}

bool validate_certificate_message_order(const handshake_validation_state& validation_state,
                                        const bool handshake_fin,
                                        const char* before_reason,
                                        const char* duplicate_reason,
                                        boost::system::error_code& ec)
{
    if (!validation_state.encrypted_extensions_checked)
    {
        reject_unexpected_handshake_message(validation_state, before_reason, ec);
        return false;
    }
    if (validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
    {
        reject_unexpected_handshake_message(validation_state, duplicate_reason, ec);
        return false;
    }
    return true;
}

bool validate_certificate_verify_order(const handshake_validation_state& validation_state, const bool handshake_fin, boost::system::error_code& ec)
{
    if (validation_state.cert_verify_checked || handshake_fin)
    {
        reject_unexpected_handshake_message(validation_state, "unexpected certificate verify message order", ec);
        return false;
    }
    return true;
}

bool validate_finished_order(const handshake_validation_state& validation_state, const bool handshake_fin, boost::system::error_code& ec)
{
    if (handshake_fin)
    {
        reject_unexpected_handshake_message(validation_state, "duplicate server finished", ec);
        return false;
    }
    if (!validation_state.cert_verify_checked)
    {
        reject_unexpected_handshake_message(validation_state, "server finished before certificate verify", ec);
        return false;
    }
    return true;
}

bool validate_handshake_message_order(const server_handshake_message_type message_type,
                                      const handshake_validation_state& validation_state,
                                      const bool handshake_fin,
                                      boost::system::error_code& ec)
{
    switch (message_type)
    {
        case server_handshake_message_type::kEncryptedExtensions:
            return validate_encrypted_extensions_order(validation_state, handshake_fin, ec);
        case server_handshake_message_type::kCertificate:
            return validate_certificate_message_order(
                validation_state, handshake_fin, "certificate received before encrypted extensions", "unexpected certificate message order", ec);
        case server_handshake_message_type::kCompressedCertificate:
            return validate_certificate_message_order(validation_state,
                                                      handshake_fin,
                                                      "compressed certificate received before encrypted extensions",
                                                      "unexpected compressed certificate message order",
                                                      ec);
        case server_handshake_message_type::kCertificateVerify:
            return validate_certificate_verify_order(validation_state, handshake_fin, ec);
        case server_handshake_message_type::kFinished:
            return validate_finished_order(validation_state, handshake_fin, ec);
        case server_handshake_message_type::kUnknown:
            return true;
    }
    return true;
}

void handle_encrypted_extensions_message(const std::vector<uint8_t>& msg_data,
                                         handshake_validation_state& validation_state,
                                         boost::system::error_code& ec)
{
    validate_encrypted_extensions_message(
        msg_data, *validation_state.client_hello, validation_state.log_context, validation_state.negotiated_alpn, ec);
    if (ec)
    {
        return;
    }
    validation_state.encrypted_extensions_checked = true;
}

void handle_certificate_message(const std::vector<uint8_t>& msg_data,
                                const std::vector<uint8_t>& auth_key,
                                handshake_validation_state& validation_state,
                                boost::system::error_code& ec)
{
    load_server_public_key_from_certificate(msg_data, auth_key, validation_state, ec);
}

void handle_compressed_certificate_message(const std::vector<uint8_t>& msg_data,
                                           const std::vector<uint8_t>& auth_key,
                                           handshake_validation_state& validation_state,
                                           boost::system::error_code& ec)
{
    std::vector<uint8_t> certificate_msg;
    if (!tls::decompress_certificate_message(msg_data, constants::reality_limits::kMaxHandshakeMessageSize, certificate_msg, ec))
    {
        LOG_ERROR("{} conn {} sni {} compressed certificate decode failed {}",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context),
                  ec.message());
        return;
    }
    load_server_public_key_from_certificate(certificate_msg, auth_key, validation_state, ec);
}

void handle_certificate_verify_message(const std::vector<uint8_t>& msg_data,
                                       handshake_validation_state& validation_state,
                                       const tls::transcript& trans,
                                       boost::system::error_code& ec)
{
    verify_server_certificate_verify_message(msg_data, trans, validation_state, ec);
}

void handle_finished_message(const std::vector<uint8_t>& msg_data,
                             const tls::handshake_keys& hs_keys,
                             const EVP_MD* md,
                             const handshake_log_context& log_context,
                             const tls::transcript& trans,
                             bool& handshake_fin,
                             boost::system::error_code& ec)
{
    verify_server_finished_message(msg_data, hs_keys, md, trans, log_context, ec);
    if (ec)
    {
        return;
    }
    handshake_fin = true;
}

void handle_unknown_handshake_message(const uint8_t msg_type, const handshake_validation_state& validation_state, boost::system::error_code& ec)
{
    LOG_ERROR("{} conn {} sni {} unexpected handshake message type {}",
              relay::log_event::kHandshake,
              validation_state.log_context.conn_id,
              handshake_log_sni(validation_state.log_context),
              msg_type);
    ec = boost::asio::error::invalid_argument;
}

void dispatch_handshake_message(const server_handshake_message_type message_type,
                                const uint8_t raw_msg_type,
                                const std::vector<uint8_t>& msg_data,
                                const std::vector<uint8_t>& auth_key,
                                handshake_validation_state& validation_state,
                                bool& handshake_fin,
                                const tls::handshake_keys& hs_keys,
                                const EVP_MD* md,
                                const tls::transcript& trans,
                                boost::system::error_code& ec)
{
    switch (message_type)
    {
        case server_handshake_message_type::kEncryptedExtensions:
            handle_encrypted_extensions_message(msg_data, validation_state, ec);
            return;
        case server_handshake_message_type::kCertificate:
            handle_certificate_message(msg_data, auth_key, validation_state, ec);
            return;
        case server_handshake_message_type::kCompressedCertificate:
            handle_compressed_certificate_message(msg_data, auth_key, validation_state, ec);
            return;
        case server_handshake_message_type::kCertificateVerify:
            handle_certificate_verify_message(msg_data, validation_state, trans, ec);
            return;
        case server_handshake_message_type::kFinished:
            handle_finished_message(msg_data, hs_keys, md, validation_state.log_context, trans, handshake_fin, ec);
            return;
        case server_handshake_message_type::kUnknown:
            handle_unknown_handshake_message(raw_msg_type, validation_state, ec);
            return;
    }
}

void handle_handshake_message(uint8_t msg_type,
                              const std::vector<uint8_t>& msg_data,
                              const std::vector<uint8_t>& auth_key,
                              handshake_validation_state& validation_state,
                              bool& handshake_fin,
                              const tls::handshake_keys& hs_keys,
                              const EVP_MD* md,
                              const tls::transcript& trans,
                              boost::system::error_code& ec)
{
    const auto message_type = classify_server_handshake_message(msg_type);
    if (!validate_handshake_message_order(message_type, validation_state, handshake_fin, ec))
    {
        return;
    }
    dispatch_handshake_message(message_type, msg_type, msg_data, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
}

void consume_handshake_buffer(std::vector<uint8_t>& handshake_buffer,
                              std::size_t& handshake_buffer_pos,
                              const std::vector<uint8_t>& auth_key,
                              handshake_validation_state& validation_state,
                              bool& handshake_fin,
                              const tls::handshake_keys& hs_keys,
                              const EVP_MD* md,
                              tls::transcript& trans,
                              boost::system::error_code& ec)
{
    if (handshake_buffer_pos > handshake_buffer.size())
    {
        LOG_ERROR("{} conn {} sni {} handshake buffer position invalid {} {}",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context),
                  handshake_buffer_pos,
                  handshake_buffer.size());
        ec = boost::asio::error::invalid_argument;
        return;
    }

    std::size_t offset = handshake_buffer_pos;
    while (offset <= handshake_buffer.size() && handshake_buffer.size() - offset >= 4)
    {
        uint8_t msg_type = 0;
        uint32_t msg_len = 0;
        if (!read_handshake_message_header(handshake_buffer, offset, msg_type, msg_len))
        {
            break;
        }
        if (msg_len > constants::reality_limits::kMaxHandshakeMessageSize)
        {
            LOG_ERROR("{} conn {} sni {} handshake message too large {}",
                      relay::log_event::kHandshake,
                      validation_state.log_context.conn_id,
                      handshake_log_sni(validation_state.log_context),
                      msg_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return;
        }

        const auto full_msg_len = static_cast<std::size_t>(msg_len) + 4;
        if (handshake_buffer.size() - offset < full_msg_len)
        {
            break;
        }

        const auto msg_begin = handshake_buffer.begin() + static_cast<std::ptrdiff_t>(offset);
        const auto msg_end = msg_begin + static_cast<std::ptrdiff_t>(full_msg_len);
        const std::vector<uint8_t> msg_data(msg_begin, msg_end);
        handle_handshake_message(msg_type, msg_data, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
        if (ec)
        {
            return;
        }
        trans.update(msg_data);
        offset += full_msg_len;
    }
    handshake_buffer_pos = offset;
}

void consume_handshake_plaintext(const std::vector<uint8_t>& plaintext,
                                 std::vector<uint8_t>& handshake_buffer,
                                 std::size_t& handshake_buffer_pos,
                                 const std::vector<uint8_t>& auth_key,
                                 handshake_validation_state& validation_state,
                                 bool& handshake_fin,
                                 const tls::handshake_keys& hs_keys,
                                 const EVP_MD* md,
                                 tls::transcript& trans,
                                 boost::system::error_code& ec)
{
    if (handshake_buffer_pos > handshake_buffer.size())
    {
        LOG_ERROR("{} conn {} sni {} handshake buffer position invalid {} {}",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context),
                  handshake_buffer_pos,
                  handshake_buffer.size());
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (handshake_buffer_pos > 0 && handshake_buffer.size() + plaintext.size() > constants::reality_limits::kMaxHandshakeBufferSize)
    {
        compact_handshake_buffer(handshake_buffer, handshake_buffer_pos, validation_state.log_context);
    }

    const auto active_size = handshake_buffer.size() - handshake_buffer_pos;
    if (plaintext.size() > constants::reality_limits::kMaxHandshakeBufferSize ||
        active_size > constants::reality_limits::kMaxHandshakeBufferSize - plaintext.size())
    {
        LOG_ERROR("{} conn {} sni {} handshake buffer too large {} {}",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context),
                  active_size,
                  plaintext.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    handshake_buffer.insert(handshake_buffer.end(), plaintext.begin(), plaintext.end());
    consume_handshake_buffer(handshake_buffer, handshake_buffer_pos, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
    if (ec)
    {
        return;
    }
    compact_handshake_buffer(handshake_buffer, handshake_buffer_pos, validation_state.log_context);
}

void validate_server_handshake_chain(const handshake_validation_state& validation_state, boost::system::error_code& ec)
{
    if (!validation_state.cert_checked || !validation_state.cert_verify_checked)
    {
        LOG_ERROR("{} conn {} sni {} server auth chain incomplete",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    if (!validation_state.reality_cert_verified && !validation_state.real_cert_chain_verified)
    {
        LOG_ERROR("{} conn {} sni {} server certificate verification failed on all supported path",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    if (!validation_state.cert_verify_signature_checked)
    {
        LOG_ERROR("{} conn {} sni {} server certificate verify signature check failed",
                  relay::log_event::kHandshake,
                  validation_state.log_context.conn_id,
                  handshake_log_sni(validation_state.log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
}
