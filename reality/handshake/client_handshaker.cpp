#include <array>
#include <chrono>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <cstring>
#include <utility>
#include <optional>
#include <algorithm>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

extern "C"
{
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/x509_vfy.h>
}

#include "log.h"
#include "config.h"
#include "tls/core.h"
#include "constants.h"
#include "net_utils.h"
#include "reality/types.h"
#include "tls/ch_parser.h"
#include "tls/transcript.h"
#include "tls/crypto_util.h"
#include "tls/cipher_suite.h"
#include "tls/key_schedule.h"
#include "tls/record_layer.h"
#include "tls/handshake_builder.h"
#include "tls/handshake_message.h"
#include "tls/record_validation.h"
#include "reality/handshake/auth.h"
#include "tls/certificate_compression.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/client_handshaker.h"
#include "reality/handshake/client_hello_builder.h"
#include "reality/handshake/fingerprint_internal.h"

namespace reality
{

namespace
{

std::optional<std::vector<uint8_t>> extract_first_cert_der(const std::vector<uint8_t>& cert_msg);

bool read_handshake_message_header(const std::vector<uint8_t>& handshake_buffer, std::size_t offset, uint8_t& msg_type, uint32_t& msg_len)
{
    if (offset > handshake_buffer.size() || handshake_buffer.size() - offset < 4)
    {
        return false;
    }
    msg_type = handshake_buffer[offset];
    msg_len = (static_cast<uint32_t>(handshake_buffer[offset + 1]) << 16) | (static_cast<uint32_t>(handshake_buffer[offset + 2]) << 8) |
              static_cast<uint32_t>(handshake_buffer[offset + 3]);
    return true;
}

void compact_handshake_buffer(std::vector<uint8_t>& handshake_buffer, std::size_t& handshake_buffer_pos)
{
    if (handshake_buffer_pos == 0)
    {
        return;
    }
    if (handshake_buffer_pos > handshake_buffer.size())
    {
        LOG_ERROR("handshake buffer position invalid {} {}", handshake_buffer_pos, handshake_buffer.size());
        handshake_buffer.clear();
        handshake_buffer_pos = 0;
        return;
    }
    if (handshake_buffer_pos == handshake_buffer.size())
    {
        handshake_buffer.clear();
        handshake_buffer_pos = 0;
        return;
    }
    if (handshake_buffer_pos < constants::reality_limits::kHandshakeBufferCompactThreshold && handshake_buffer_pos * 2 < handshake_buffer.size())
    {
        return;
    }

    std::move(handshake_buffer.begin() + static_cast<std::ptrdiff_t>(handshake_buffer_pos), handshake_buffer.end(), handshake_buffer.begin());
    handshake_buffer.resize(handshake_buffer.size() - handshake_buffer_pos);
    handshake_buffer_pos = 0;
}

struct handshake_validation_state
{
    bool encrypted_extensions_checked = false;
    bool cert_checked = false;
    bool cert_verify_checked = false;
    bool cert_verify_signature_checked = false;
    bool reality_cert_verified = false;
    bool real_cert_chain_verified = false;
    std::string negotiated_alpn;
    const tls::client_hello_info* client_hello = nullptr;
    tls::openssl_ptrs::evp_pkey_ptr server_pub_key = nullptr;
};

struct client_handshake_read_result
{
    traffic_secrets secrets;
    std::string negotiated_alpn;
    client_auth_mode auth_mode = client_auth_mode::kRealityTunnel;
};

struct client_ephemeral_keys
{
    std::array<uint8_t, 32> public_key{};
    std::array<uint8_t, 32> private_key{};
    std::vector<uint8_t> mlkem768_public_key;
    std::vector<uint8_t> mlkem768_private_key;
    std::vector<uint8_t> hybrid_key_share;
    fingerprint_template template_spec;
    bool use_hybrid = false;
};

using x509_store_ptr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using x509_store_ctx_ptr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

class x509_stack_deleter
{
   public:
    void operator()(STACK_OF(X509) * p) const { sk_X509_free(p); }
};

using x509_stack_ptr = std::unique_ptr<STACK_OF(X509), x509_stack_deleter>;

bool client_offers_alpn(const tls::client_hello_info& client_hello, const std::string& alpn)
{
    return std::find(client_hello.alpn_protocols.begin(), client_hello.alpn_protocols.end(), alpn) != client_hello.alpn_protocols.end();
}

bool client_offers_signature_scheme(const tls::client_hello_info& client_hello, uint16_t scheme)
{
    return std::find(client_hello.signature_algorithms.begin(), client_hello.signature_algorithms.end(), scheme) !=
           client_hello.signature_algorithms.end();
}

void validate_encrypted_extensions_message(const std::vector<uint8_t>& msg_data,
                                           const tls::client_hello_info& client_hello,
                                           std::string& negotiated_alpn,
                                           boost::system::error_code& ec)
{
    negotiated_alpn.clear();
    const auto encrypted_extensions = tls::parse_encrypted_extensions(msg_data);
    if (!encrypted_extensions.has_value())
    {
        LOG_ERROR("encrypted extensions parse failed");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!encrypted_extensions->has_alpn)
    {
        return;
    }
    if (client_hello.alpn_protocols.empty())
    {
        LOG_ERROR("server advertised unrequested alpn");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!client_offers_alpn(client_hello, encrypted_extensions->alpn))
    {
        LOG_ERROR("server selected unadvertised alpn {}", encrypted_extensions->alpn);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    negotiated_alpn = encrypted_extensions->alpn;
}

void verify_reality_bound_certificate(const std::vector<uint8_t>& cert_der,
                                      const std::vector<uint8_t>& auth_key,
                                      handshake_validation_state& validation_state,
                                      boost::system::error_code& ec)
{
    auto server_pub_key = tls::crypto_util::extract_pubkey_from_cert(cert_der, ec);
    if (ec || server_pub_key == nullptr)
    {
        LOG_ERROR("extract server pubkey failed");
        if (!ec)
        {
            ec = boost::asio::error::invalid_argument;
        }
        return;
    }
    if (EVP_PKEY_base_id(server_pub_key.get()) != EVP_PKEY_ED25519)
    {
        LOG_ERROR("server certificate pubkey is not ed25519");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    auto raw_pub_key = tls::crypto_util::extract_raw_public_key(server_pub_key.get(), ec);
    if (ec)
    {
        return;
    }
    auto cert_signature = tls::crypto_util::extract_certificate_signature(cert_der, ec);
    if (ec)
    {
        return;
    }
    auto expected_signature = tls::crypto_util::hmac_sha512(auth_key, raw_pub_key, ec);
    if (ec)
    {
        return;
    }
    if (expected_signature.size() != cert_signature.size() ||
        CRYPTO_memcmp(expected_signature.data(), cert_signature.data(), expected_signature.size()) != 0)
    {
        LOG_ERROR("server certificate reality binding mismatch");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    validation_state.server_pub_key = std::move(server_pub_key);
    validation_state.reality_cert_verified = true;
}

tls::openssl_ptrs::x509_ptr parse_x509_from_der_local(const std::vector<uint8_t>& cert_der, boost::system::error_code& ec)
{
    if (cert_der.empty() || cert_der.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return nullptr;
    }

    using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    const bio_ptr cert_bio(BIO_new_mem_buf(cert_der.data(), static_cast<int>(cert_der.size())), &BIO_free);
    if (cert_bio == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return nullptr;
    }

    tls::openssl_ptrs::x509_ptr x509(d2i_X509_bio(cert_bio.get(), nullptr));
    if (x509 == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }
    return x509;
}

void verify_real_certificate_chain(const std::vector<uint8_t>& msg_data, handshake_validation_state& validation_state, boost::system::error_code& ec)
{
    if (validation_state.client_hello == nullptr || validation_state.client_hello->sni.empty())
    {
        ec = boost::asio::error::invalid_argument;
        return;
    }

    std::vector<std::vector<uint8_t>> cert_chain_der;
    if (!tls::parse_certificate_chain(msg_data, cert_chain_der))
    {
        ec = boost::asio::error::invalid_argument;
        return;
    }

    std::vector<tls::openssl_ptrs::x509_ptr> cert_chain;
    cert_chain.reserve(cert_chain_der.size());
    for (const auto& cert_der : cert_chain_der)
    {
        auto cert = parse_x509_from_der_local(cert_der, ec);
        if (ec || cert == nullptr)
        {
            return;
        }
        cert_chain.push_back(std::move(cert));
    }

    const x509_store_ptr store(X509_STORE_new(), &X509_STORE_free);
    const x509_store_ctx_ptr store_ctx(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
    const x509_stack_ptr untrusted(sk_X509_new_null());
    if (store == nullptr || store_ctx == nullptr || untrusted == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return;
    }

    if (X509_STORE_set_default_paths(store.get()) != 1)
    {
        ec = boost::asio::error::fault;
        return;
    }

    for (std::size_t i = 1; i < cert_chain.size(); ++i)
    {
        if (sk_X509_push(untrusted.get(), cert_chain[i].get()) == 0)
        {
            ec = boost::asio::error::fault;
            return;
        }
    }

    if (X509_STORE_CTX_init(store_ctx.get(), store.get(), cert_chain.front().get(), untrusted.get()) != 1)
    {
        ec = boost::asio::error::fault;
        return;
    }

    auto* verify_param = X509_STORE_CTX_get0_param(store_ctx.get());
    if (verify_param == nullptr || X509_VERIFY_PARAM_set1_host(verify_param, validation_state.client_hello->sni.c_str(), 0) != 1)
    {
        ec = boost::asio::error::invalid_argument;
        return;
    }

    if (X509_verify_cert(store_ctx.get()) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    EVP_PKEY* leaf_pub_key = X509_get_pubkey(cert_chain.front().get());
    if (leaf_pub_key == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }

    validation_state.server_pub_key.reset(leaf_pub_key);
    validation_state.real_cert_chain_verified = true;
}

void load_server_public_key_from_certificate(const std::vector<uint8_t>& msg_data,
                                             const std::vector<uint8_t>& auth_key,
                                             handshake_validation_state& validation_state,
                                             boost::system::error_code& ec)
{
    LOG_DEBUG("received certificate message size {}", msg_data.size());
    if (validation_state.cert_checked)
    {
        return;
    }

    const auto cert_der = extract_first_cert_der(msg_data);
    if (!cert_der.has_value())
    {
        LOG_ERROR("certificate message parse failed");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    boost::system::error_code reality_ec;
    verify_reality_bound_certificate(*cert_der, auth_key, validation_state, reality_ec);
    if (!reality_ec)
    {
        validation_state.cert_checked = true;
        return;
    }

    boost::system::error_code real_cert_ec;
    verify_real_certificate_chain(msg_data, validation_state, real_cert_ec);
    if (!real_cert_ec)
    {
        LOG_WARN("received real certificate for sni {}", validation_state.client_hello->sni);
        validation_state.cert_checked = true;
        return;
    }

    ec = reality_ec;
    if (!ec)
    {
        ec = real_cert_ec;
    }
    if (!ec)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
    }
    LOG_ERROR("server certificate verification failed on reality and real certificate path");
}

void verify_server_certificate_verify_message(const std::vector<uint8_t>& msg_data,
                                              const tls::transcript& trans,
                                              handshake_validation_state& validation_state,
                                              boost::system::error_code& ec)
{
    if (!validation_state.cert_checked)
    {
        LOG_ERROR("certificate verify received before certificate");
        ec = boost::asio::error::invalid_argument;
        return;
    }

    const auto cert_verify = tls::parse_certificate_verify(msg_data);
    if (!cert_verify.has_value())
    {
        LOG_ERROR("certificate verify parse failed");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!tls::is_supported_certificate_verify_scheme(cert_verify->scheme))
    {
        LOG_ERROR("unsupported certificate verify scheme {:x}", cert_verify->scheme);
        ec = boost::asio::error::no_protocol_option;
        return;
    }
    if (validation_state.client_hello == nullptr || validation_state.client_hello->signature_algorithms.empty())
    {
        LOG_ERROR("certificate verify validation missing client signature algorithms");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!client_offers_signature_scheme(*validation_state.client_hello, cert_verify->scheme))
    {
        LOG_ERROR("server selected certificate verify scheme {:x} not advertised by client", cert_verify->scheme);
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
            LOG_DEBUG("certificate verify signature check failed code {} message {}", ec.value(), ec.message());
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
                                    boost::system::error_code& ec)
{
    const uint32_t msg_len =
        (static_cast<uint32_t>(msg_data[1]) << 16) | (static_cast<uint32_t>(msg_data[2]) << 8) | static_cast<uint32_t>(msg_data[3]);

    const auto expected_verify_data =
        tls::key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("server finished verify derive failed {}", ec.message());
        return;
    }

    if (expected_verify_data.size() != msg_len)
    {
        LOG_ERROR("server finished verify size mismatch {} {}", expected_verify_data.size(), msg_len);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    if (CRYPTO_memcmp(msg_data.data() + 4, expected_verify_data.data(), expected_verify_data.size()) != 0)
    {
        LOG_ERROR("server finished verify mismatch");
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
                                                               boost::system::error_code& ec)
{
    std::array<uint8_t, 5> record_header{};
    const auto header_timeout = mux::net::remaining_timeout_seconds(handshake_start_ms, timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("handshake overall timeout {}", ec.message());
        co_return encrypted_record{};
    }
    auto read_size = co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(record_header), header_timeout, ec);
    if (ec)
    {
        LOG_ERROR("error reading record header {}", ec.message());
        co_return encrypted_record{};
    }

    if (read_size != record_header.size())
    {
        ec = boost::asio::error::fault;
        LOG_ERROR("short read record header {} of {}", read_size, record_header.size());
        co_return encrypted_record{};
    }

    const auto record_body_size = static_cast<uint16_t>((record_header[3] << 8) | record_header[4]);
    if (record_body_size > constants::tls_limits::kMaxCiphertextRecordLen)
    {
        LOG_ERROR("record body too large {}", record_body_size);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return encrypted_record{};
    }
    std::vector<uint8_t> record_body(record_body_size);
    const auto body_timeout = mux::net::remaining_timeout_seconds(handshake_start_ms, timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("handshake overall timeout {}", ec.message());
        co_return encrypted_record{};
    }
    read_size = co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(record_body), body_timeout, ec);
    if (ec)
    {
        LOG_ERROR("error reading record payload {}", ec.message());
        co_return encrypted_record{};
    }
    if (read_size != record_body_size)
    {
        ec = boost::asio::error::fault;
        LOG_ERROR("short read record payload {} of {}", read_size, record_body_size);
        co_return encrypted_record{};
    }
    if (record_header[0] == tls::kContentTypeChangeCipherSpec)
    {
        const uint8_t ccs_body = record_body_size == 1 ? record_body[0] : 0;
        if (!tls::is_valid_tls13_compat_ccs(record_header, ccs_body))
        {
            LOG_ERROR("invalid tls13 compat ccs len {} body {}", record_body_size, ccs_body);
            ec = boost::asio::error::invalid_argument;
            co_return encrypted_record{};
        }
    }
    else if (record_header[0] != tls::kContentTypeApplicationData)
    {
        LOG_ERROR("unexpected encrypted record type {}", static_cast<int>(record_header[0]));
        ec = boost::asio::error::invalid_argument;
        co_return encrypted_record{};
    }

    std::vector<uint8_t> ciphertext(record_header.size() + record_body_size);
    std::memcpy(ciphertext.data(), record_header.data(), record_header.size());
    std::memcpy(ciphertext.data() + record_header.size(), record_body.data(), record_body_size);
    co_return encrypted_record{.content_type = record_header[0], .ciphertext = std::move(ciphertext)};
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
    if (msg_type == 0x08)
    {
        if (validation_state.encrypted_extensions_checked || validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected encrypted extensions order");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (validation_state.client_hello == nullptr)
        {
            LOG_ERROR("missing client hello for encrypted extensions");
            ec = boost::asio::error::fault;
            return;
        }
        validate_encrypted_extensions_message(msg_data, *validation_state.client_hello, validation_state.negotiated_alpn, ec);
        if (ec)
        {
            return;
        }
        validation_state.encrypted_extensions_checked = true;
        return;
    }
    if (msg_type == 0x0b)
    {
        if (!validation_state.encrypted_extensions_checked)
        {
            LOG_ERROR("certificate received before encrypted extensions");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected certificate message order");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        load_server_public_key_from_certificate(msg_data, auth_key, validation_state, ec);
        return;
    }
    if (msg_type == 0x19)
    {
        if (!validation_state.encrypted_extensions_checked)
        {
            LOG_ERROR("compressed certificate received before encrypted extensions");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected compressed certificate message order");
            ec = boost::asio::error::invalid_argument;
            return;
        }

        std::vector<uint8_t> certificate_msg;
        if (!tls::decompress_certificate_message(msg_data, constants::reality_limits::kMaxHandshakeMessageSize, certificate_msg, ec))
        {
            LOG_ERROR("compressed certificate decode failed {}", ec.message());
            return;
        }
        load_server_public_key_from_certificate(certificate_msg, auth_key, validation_state, ec);
        return;
    }
    if (msg_type == 0x0f)
    {
        if (validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected certificate verify message order");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        verify_server_certificate_verify_message(msg_data, trans, validation_state, ec);
        return;
    }
    if (msg_type == 0x14)
    {
        if (handshake_fin)
        {
            LOG_ERROR("duplicate server finished");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (!validation_state.cert_verify_checked)
        {
            LOG_ERROR("server finished before certificate verify");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        verify_server_finished_message(msg_data, hs_keys, md, trans, ec);
        if (ec)
        {
            return;
        }
        handshake_fin = true;
        return;
    }
    LOG_ERROR("unexpected handshake message type {}", msg_type);
    ec = boost::asio::error::invalid_argument;
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
        LOG_ERROR("handshake buffer position invalid {} {}", handshake_buffer_pos, handshake_buffer.size());
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
            LOG_ERROR("handshake message too large {}", msg_len);
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
        LOG_ERROR("handshake buffer position invalid {} {}", handshake_buffer_pos, handshake_buffer.size());
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (handshake_buffer_pos > 0 && handshake_buffer.size() + plaintext.size() > constants::reality_limits::kMaxHandshakeBufferSize)
    {
        compact_handshake_buffer(handshake_buffer, handshake_buffer_pos);
    }

    const auto active_size = handshake_buffer.size() - handshake_buffer_pos;
    if (plaintext.size() > constants::reality_limits::kMaxHandshakeBufferSize ||
        active_size > constants::reality_limits::kMaxHandshakeBufferSize - plaintext.size())
    {
        LOG_ERROR("handshake buffer too large {} {}", active_size, plaintext.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    handshake_buffer.insert(handshake_buffer.end(), plaintext.begin(), plaintext.end());
    consume_handshake_buffer(handshake_buffer, handshake_buffer_pos, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
    if (ec)
    {
        return;
    }
    compact_handshake_buffer(handshake_buffer, handshake_buffer_pos);
}

void validate_server_handshake_chain(const handshake_validation_state& validation_state, const std::string& sni, boost::system::error_code& ec)
{
    (void)sni;
    if (!validation_state.cert_checked || !validation_state.cert_verify_checked)
    {
        LOG_ERROR("server auth chain incomplete");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    if (!validation_state.reality_cert_verified && !validation_state.real_cert_chain_verified)
    {
        LOG_ERROR("server certificate verification failed on all supported path");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    if (!validation_state.cert_verify_signature_checked)
    {
        LOG_ERROR("server certificate verify signature check failed");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
}

boost::asio::awaitable<bool> read_handshake_bytes(boost::asio::ip::tcp::socket& socket,
                                                  uint64_t handshake_start_ms,
                                                  uint32_t timeout_sec,
                                                  const boost::asio::mutable_buffer& buffer,
                                                  boost::system::error_code& ec)
{
    auto* data = static_cast<uint8_t*>(buffer.data());
    const auto size = buffer.size();
    std::size_t total_read = 0;
    while (total_read < size)
    {
        const auto read_timeout = mux::net::remaining_timeout_seconds(handshake_start_ms, timeout_sec, ec);
        if (ec)
        {
            co_return false;
        }

        const auto read_size =
            co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(data + total_read, size - total_read), read_timeout, ec);
        if (ec)
        {
            co_return false;
        }
        if (read_size == 0)
        {
            ec = boost::asio::error::eof;
            co_return false;
        }
        total_read += read_size;
    }

    co_return true;
}

bool validate_handshake_record_header(const std::array<uint8_t, 5>& header, const char* step, boost::system::error_code& ec)
{
    if (header[1] != 0x03 || header[2] != 0x03)
    {
        LOG_ERROR("invalid tls record version for {} {} {}", step, header[1], header[2]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return false;
    }

    const auto body_len = static_cast<uint16_t>((header[3] << 8) | header[4]);
    if (body_len > tls::kMaxTlsPlaintextLen)
    {
        LOG_ERROR("oversized {} body {}", step, body_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return false;
    }

    return true;
}

boost::asio::awaitable<bool> read_handshake_record(boost::asio::ip::tcp::socket& socket,
                                                   const char* step,
                                                   uint64_t handshake_start_ms,
                                                   uint32_t timeout_sec,
                                                   std::array<uint8_t, 5>& header,
                                                   std::vector<uint8_t>& body,
                                                   boost::system::error_code& ec)
{
    if (!(co_await read_handshake_bytes(socket, handshake_start_ms, timeout_sec, boost::asio::buffer(header), ec)))
    {
        LOG_ERROR("error reading {} header {}", step, ec.message());
        co_return false;
    }
    if (!validate_handshake_record_header(header, step, ec))
    {
        co_return false;
    }

    const auto body_len = static_cast<uint16_t>((header[3] << 8) | header[4]);
    body.resize(body_len);
    if (!(co_await read_handshake_bytes(socket, handshake_start_ms, timeout_sec, boost::asio::buffer(body), ec)))
    {
        LOG_ERROR("error reading {} body {}", step, ec.message());
        co_return false;
    }

    co_return true;
}

bool try_skip_tls13_compat_ccs_record(const std::array<uint8_t, 5>& header,
                                      const std::vector<uint8_t>& body,
                                      const char* step,
                                      const std::vector<uint8_t>& handshake_data,
                                      uint32_t& tls13_compat_ccs_count,
                                      boost::system::error_code& ec)
{
    if (header[0] != tls::kContentTypeChangeCipherSpec)
    {
        return false;
    }

    const uint8_t ccs_body = body.size() == 1 ? body[0] : 0;
    if (!handshake_data.empty())
    {
        LOG_ERROR("unexpected ccs during fragmented {}", step);
        ec = boost::asio::error::invalid_argument;
        return false;
    }
    if (!tls::is_valid_tls13_compat_ccs(header, ccs_body))
    {
        LOG_ERROR("invalid tls13 compat ccs before {}", step);
        ec = boost::asio::error::invalid_argument;
        return false;
    }
    if (tls13_compat_ccs_count >= constants::tls_limits::kMaxCompatCcsRecords)
    {
        LOG_ERROR("too many tls13 compat ccs before {}", step);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return false;
    }

    tls13_compat_ccs_count++;
    LOG_DEBUG("skip tls13 compat ccs before {} count {}", step, tls13_compat_ccs_count);
    return true;
}

bool try_complete_handshake_message(const std::array<uint8_t, 5>& header,
                                    const std::vector<uint8_t>& body,
                                    const char* step,
                                    std::vector<uint8_t>& handshake_data,
                                    std::vector<uint8_t>& extra_handshake_data,
                                    boost::system::error_code& ec)
{
    if (header[0] != tls::kContentTypeHandshake)
    {
        LOG_ERROR("unexpected record type for {} {}", step, header[0]);
        ec = boost::asio::error::invalid_argument;
        return false;
    }

    handshake_data.insert(handshake_data.end(), body.begin(), body.end());
    if (handshake_data.size() < 4)
    {
        return false;
    }
    if (handshake_data[0] != 0x02)
    {
        LOG_ERROR("unexpected handshake type for {} {}", step, handshake_data[0]);
        ec = boost::asio::error::invalid_argument;
        return false;
    }

    const auto msg_len =
        (static_cast<uint32_t>(handshake_data[1]) << 16) | (static_cast<uint32_t>(handshake_data[2]) << 8) | static_cast<uint32_t>(handshake_data[3]);
    if (msg_len > constants::reality_limits::kMaxHandshakeMessageSize)
    {
        LOG_ERROR("oversized {} message {}", step, msg_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return false;
    }

    const auto total_len = static_cast<std::size_t>(msg_len) + 4;
    if (handshake_data.size() < total_len)
    {
        return false;
    }
    if (handshake_data.size() > total_len)
    {
        extra_handshake_data.assign(handshake_data.begin() + static_cast<std::ptrdiff_t>(total_len), handshake_data.end());
        handshake_data.resize(total_len);
        LOG_DEBUG("extra handshake bytes in {} {}", step, extra_handshake_data.size());
    }

    return true;
}

boost::asio::awaitable<std::vector<uint8_t>> read_handshake_record_body(boost::asio::ip::tcp::socket& socket,
                                                                        const char* step,
                                                                        uint32_t timeout_sec,
                                                                        uint32_t& tls13_compat_ccs_count,
                                                                        std::vector<uint8_t>& extra_handshake_data,
                                                                        boost::system::error_code& ec)
{
    extra_handshake_data.clear();
    const auto handshake_start_ms = mux::net::now_ms();
    std::vector<uint8_t> handshake_data;
    while (true)
    {
        std::array<uint8_t, 5> header = {};
        std::vector<uint8_t> body;
        if (!(co_await read_handshake_record(socket, step, handshake_start_ms, timeout_sec, header, body, ec)))
        {
            co_return std::vector<uint8_t>{};
        }

        if (try_skip_tls13_compat_ccs_record(header, body, step, handshake_data, tls13_compat_ccs_count, ec))
        {
            continue;
        }
        if (ec)
        {
            co_return std::vector<uint8_t>{};
        }

        if (try_complete_handshake_message(header, body, step, handshake_data, extra_handshake_data, ec))
        {
            co_return handshake_data;
        }
        if (ec)
        {
            co_return std::vector<uint8_t>{};
        }
    }
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_client_auth_key_material(const uint8_t* private_key,
                                                                                      const std::vector<uint8_t>& server_pub_key,
                                                                                      boost::system::error_code& ec)
{
    auto shared = tls::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), server_pub_key, ec);
    LOG_DEBUG("using server pub key size {}", server_pub_key.size());
    if (ec)
    {
        return {};
    }

    std::vector<uint8_t> client_random(32);
    if (RAND_bytes(client_random.data(), 32) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }

    const std::vector<uint8_t> salt(client_random.begin(), client_random.begin() + constants::auth::kSaltLen);
    const auto reality_label_info = tls::crypto_util::hex_to_bytes("5245414c495459");
    auto pseudo_random_key = tls::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    if (ec)
    {
        return {};
    }
    auto auth_key = tls::crypto_util::hkdf_expand(pseudo_random_key, reality_label_info, 16, EVP_sha256(), ec);
    if (ec)
    {
        return {};
    }
    LOG_DEBUG("client auth material ready random {} bytes eph pub {} bytes", client_random.size(), 32);
    return std::make_pair(std::move(client_random), std::move(auth_key));
}

void build_client_hello_with_placeholder_sid(const fingerprint_template& spec,
                                             const std::vector<uint8_t>& client_random,
                                             const uint8_t* public_key,
                                             const std::vector<uint8_t>& x25519_mlkem768_key_share,
                                             const std::string& sni,
                                             std::vector<uint8_t>& hello_body,
                                             uint32_t& absolute_sid_offset,
                                             boost::system::error_code& ec)
{
    const std::vector<uint8_t> placeholder_session_id(32, 0);
    hello_body = client_hello_builder::build(
        spec, placeholder_session_id, client_random, std::vector<uint8_t>(public_key, public_key + 32), x25519_mlkem768_key_share, sni);
    if (hello_body.empty())
    {
        LOG_ERROR("generated client hello body invalid for configured sni");
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (hello_body.size() > std::numeric_limits<uint16_t>::max())
    {
        LOG_ERROR("generated client hello body too large {}", hello_body.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    const tls::client_hello_info ch_info = tls::client_hello_parser::parse(hello_body);
    if (ch_info.sid_offset == 0)
    {
        LOG_ERROR("generated client hello session id offset invalid {}", ch_info.sid_offset);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (ch_info.malformed_signature_algorithms || ch_info.signature_algorithms.empty() ||
        !client_offers_signature_scheme(ch_info, tls::consts::sig_alg::kEd25519))
    {
        LOG_ERROR("generated client hello missing usable signature algorithms");
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }

    absolute_sid_offset = ch_info.sid_offset;
    if (absolute_sid_offset + 32 > hello_body.size())
    {
        LOG_ERROR("session id offset out of bounds {} {}", absolute_sid_offset, hello_body.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
}

std::vector<uint8_t> encrypt_client_session_id(const std::vector<uint8_t>& auth_key,
                                               const std::vector<uint8_t>& client_random,
                                               const std::array<uint8_t, kAuthPayloadLen>& payload,
                                               const std::vector<uint8_t>& hello_body,
                                               boost::system::error_code& ec)
{
    auto sid = tls::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                              auth_key,
                                              std::vector<uint8_t>(client_random.begin() + constants::auth::kSaltLen, client_random.end()),
                                              std::vector<uint8_t>(payload.begin(), payload.end()),
                                              hello_body,
                                              ec);
    if (ec || sid.size() != 32)
    {
        LOG_ERROR("auth encryption failed ct size {}", sid.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }
    return sid;
}

struct authenticated_client_hello
{
    std::vector<uint8_t> hello_body;
    std::vector<uint8_t> auth_key;
    tls::client_hello_info hello_info;
};

authenticated_client_hello build_authenticated_client_hello(const uint8_t* public_key,
                                                            const uint8_t* private_key,
                                                            const std::vector<uint8_t>& x25519_mlkem768_key_share,
                                                            const std::vector<uint8_t>& server_pub_key,
                                                            const std::vector<uint8_t>& short_id_bytes,
                                                            const std::array<uint8_t, 3>& client_ver,
                                                            const fingerprint_template& spec,
                                                            const std::string& sni,
                                                            boost::system::error_code& ec)
{
    auto auth_material = derive_client_auth_key_material(private_key, server_pub_key, ec);
    if (ec)
    {
        return {};
    }
    auto [client_random, auth_key] = std::move(auth_material);

    const auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const auto now = static_cast<uint32_t>(now_seconds);
    std::array<uint8_t, kAuthPayloadLen> payload{};
    if (!build_auth_payload(short_id_bytes, client_ver, now, payload))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::vector<uint8_t> hello_body;
    uint32_t absolute_sid_offset = 0;
    build_client_hello_with_placeholder_sid(spec, client_random, public_key, x25519_mlkem768_key_share, sni, hello_body, absolute_sid_offset, ec);
    if (ec)
    {
        return {};
    }

    auto sid = encrypt_client_session_id(auth_key, client_random, payload, hello_body, ec);
    if (ec)
    {
        return {};
    }

    std::memcpy(hello_body.data() + absolute_sid_offset, sid.data(), 32);
    auto hello_info = tls::client_hello_parser::parse(hello_body);
    return authenticated_client_hello{
        .hello_body = std::move(hello_body),
        .auth_key = std::move(auth_key),
        .hello_info = std::move(hello_info),
    };
}

fingerprint_template select_fingerprint_template(const std::optional<reality::fingerprint_type>& selected_fingerprint_type)
{
    if (selected_fingerprint_type.has_value())
    {
        return fingerprint_factory::get(*selected_fingerprint_type);
    }

    static thread_local std::mt19937 fp_gen(std::random_device{}());
    std::uniform_int_distribution<std::size_t> fp_dist(0, constants::reality_limits::kFetchFingerprints.size() - 1);
    return fingerprint_factory::get(constants::reality_limits::kFetchFingerprints[fp_dist(fp_gen)]);
}

bool fingerprint_uses_hybrid_key_share(const fingerprint_template& spec)
{
    return fingerprint_has_key_share_group(spec, tls::consts::group::kX25519MLKEM768);
}

client_ephemeral_keys prepare_client_ephemeral_keys(const std::optional<reality::fingerprint_type>& selected_fingerprint_type,
                                                    boost::system::error_code& ec)
{
    client_ephemeral_keys keys;
    keys.template_spec = select_fingerprint_template(selected_fingerprint_type);
    keys.use_hybrid = fingerprint_uses_hybrid_key_share(keys.template_spec);

    if (!tls::crypto_util::generate_x25519_keypair(keys.public_key.data(), keys.private_key.data()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }

    if (!keys.use_hybrid)
    {
        return keys;
    }

    if (!tls::crypto_util::generate_mlkem768_keypair(keys.mlkem768_public_key, keys.mlkem768_private_key, ec))
    {
        return {};
    }

    keys.hybrid_key_share = keys.mlkem768_public_key;
    keys.hybrid_key_share.insert(keys.hybrid_key_share.end(), keys.public_key.begin(), keys.public_key.end());
    return keys;
}

class sensitive_client_key_guard
{
   public:
    explicit sensitive_client_key_guard(client_ephemeral_keys& keys) : keys_(keys) {}

    sensitive_client_key_guard(const sensitive_client_key_guard&) = delete;
    sensitive_client_key_guard& operator=(const sensitive_client_key_guard&) = delete;

    ~sensitive_client_key_guard()
    {
        OPENSSL_cleanse(keys_.private_key.data(), keys_.private_key.size());
        if (!keys_.mlkem768_private_key.empty())
        {
            OPENSSL_cleanse(keys_.mlkem768_private_key.data(), keys_.mlkem768_private_key.size());
        }
    }

   private:
    client_ephemeral_keys& keys_;
};

void log_selected_client_key_share(uint32_t conn_id, const std::string_view sni, const client_ephemeral_keys& keys)
{
    if (keys.use_hybrid)
    {
        LOG_INFO("event {} conn_id {} sni {} client hello keep fingerprint hybrid key share group 0x{:04x} {} hybrid share len {} mlkem768 pub len {}",
                 mux::log_event::kHandshake,
                 conn_id,
                 sni,
                 tls::consts::group::kX25519MLKEM768,
                 tls::named_group_name(tls::consts::group::kX25519MLKEM768),
                 keys.hybrid_key_share.size(),
                 keys.mlkem768_public_key.size());
        return;
    }

    LOG_INFO("event {} conn_id {} sni {} client hello preserve fingerprint without forced hybrid key share",
             mux::log_event::kHandshake,
             conn_id,
             sni);
}

struct handshake_traffic_keys
{
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_hs_keys;
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> s_hs_keys;
};

handshake_traffic_keys derive_handshake_traffic_keys(const tls::handshake_keys& hs_keys,
                                                     uint16_t cipher_suite,
                                                     const EVP_MD* negotiated_md,
                                                     boost::system::error_code& ec)
{
    const auto suite = tls::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    const std::size_t key_len = suite->key_len;
    auto c_hs =
        tls::key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec, key_len, constants::crypto::kIvLen, negotiated_md);
    if (ec)
    {
        return {};
    }
    auto s_hs =
        tls::key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, key_len, constants::crypto::kIvLen, negotiated_md);
    if (ec)
    {
        return {};
    }
    return handshake_traffic_keys{.c_hs_keys = std::move(c_hs), .s_hs_keys = std::move(s_hs)};
}

void prepare_server_hello_crypto(const std::vector<uint8_t>& sh_data,
                                 const tls::client_hello_info& client_hello,
                                 tls::transcript& trans,
                                 tls::server_hello_info& server_hello,
                                 uint16_t& cipher_suite,
                                 const EVP_MD*& md,
                                 const EVP_CIPHER*& cipher,
                                 boost::system::error_code& ec)
{
    trans.update(sh_data);
    const auto parsed_server_hello = tls::parse_server_hello(sh_data);
    if (!parsed_server_hello.has_value())
    {
        LOG_ERROR("bad server hello");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    server_hello = *parsed_server_hello;
    if (server_hello.is_hello_retry_request)
    {
        LOG_ERROR("hello retry request not supported");
        ec = boost::asio::error::operation_not_supported;
        return;
    }
    if (!server_hello.has_supported_version)
    {
        LOG_ERROR("server hello missing supported version");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.supported_version != tls::consts::kVer13)
    {
        LOG_ERROR("server hello selected invalid tls version {:x}", server_hello.supported_version);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.legacy_version != tls::consts::kVer12)
    {
        LOG_ERROR("server hello legacy version invalid {:x}", server_hello.legacy_version);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.session_id != client_hello.session_id)
    {
        LOG_ERROR("server hello session id mismatch");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.compression_method != 0x00)
    {
        LOG_ERROR("server hello compression method invalid {:x}", server_hello.compression_method);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.has_forbidden_tls13_extension)
    {
        LOG_ERROR("server hello has forbidden tls13 extension");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!server_hello.has_key_share)
    {
        LOG_ERROR("bad server hello key share");
        ec = boost::asio::error::invalid_argument;
        return;
    }

    cipher_suite = server_hello.cipher_suite;
    const auto suite = tls::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        LOG_ERROR("unsupported server hello cipher suite {:x}", cipher_suite);
        ec = boost::asio::error::no_protocol_option;
        return;
    }
    if (std::find(client_hello.cipher_suites.begin(), client_hello.cipher_suites.end(), cipher_suite) == client_hello.cipher_suites.end())
    {
        LOG_ERROR("server hello selected unoffered cipher suite {:x}", cipher_suite);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    md = suite->md;
    cipher = suite->cipher;
    trans.set_protocol_hash(md);
}

std::vector<uint8_t> derive_server_hello_shared_secret(const uint8_t* private_key,
                                                       const std::vector<uint8_t>& mlkem768_private_key,
                                                       uint16_t key_share_group,
                                                       const std::vector<uint8_t>& key_share_data,
                                                       boost::system::error_code& ec)
{
    if (key_share_group == tls::consts::group::kX25519)
    {
        if (key_share_data.size() != 32)
        {
            LOG_ERROR("invalid x25519 key share length {}", key_share_data.size());
            ec = boost::asio::error::invalid_argument;
            return {};
        }

        auto hs_shared = tls::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), key_share_data, ec);
        if (ec)
        {
            LOG_ERROR("handshake shared secret failed {}", ec.message());
            return {};
        }
        return hs_shared;
    }
    if (key_share_group != tls::consts::group::kX25519MLKEM768)
    {
        LOG_ERROR("unsupported key share group {}", key_share_group);
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    if (key_share_data.size() != tls::kMlkem768CiphertextSize + 32)
    {
        LOG_ERROR("invalid x25519 mlkem768 key share length {}", key_share_data.size());
        ec = boost::asio::error::invalid_argument;
        return {};
    }
    if (mlkem768_private_key.empty())
    {
        LOG_ERROR("missing mlkem768 private key");
        ec = boost::asio::error::operation_not_supported;
        return {};
    }

    const std::vector<uint8_t> ciphertext(key_share_data.begin(), key_share_data.begin() + static_cast<std::ptrdiff_t>(tls::kMlkem768CiphertextSize));
    auto mlkem768_shared = tls::crypto_util::mlkem768_decapsulate(mlkem768_private_key, ciphertext, ec);
    if (ec)
    {
        LOG_ERROR("mlkem768 decapsulate failed {}", ec.message());
        return {};
    }

    const std::vector<uint8_t> peer_pub(key_share_data.end() - 32, key_share_data.end());
    auto x25519_shared = tls::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), peer_pub, ec);
    if (ec)
    {
        LOG_ERROR("x25519 derive failed {}", ec.message());
        return {};
    }

    mlkem768_shared.insert(mlkem768_shared.end(), x25519_shared.begin(), x25519_shared.end());
    return mlkem768_shared;
}

boost::asio::awaitable<void> process_handshake_record(boost::asio::ip::tcp::socket& socket,
                                                      const std::pair<std::vector<uint8_t>, std::vector<uint8_t>>& s_hs_keys,
                                                      const std::vector<uint8_t>& auth_key,
                                                      tls::transcript& trans,
                                                      const EVP_CIPHER* cipher,
                                                      std::vector<uint8_t>& handshake_buffer,
                                                      std::size_t& handshake_buffer_pos,
                                                      handshake_validation_state& validation_state,
                                                      bool& handshake_fin,
                                                      const tls::handshake_keys& hs_keys,
                                                      const EVP_MD* md,
                                                      uint64_t& seq,
                                                      uint32_t& tls13_compat_ccs_count,
                                                      uint64_t handshake_start_ms,
                                                      uint32_t timeout_sec,
                                                      boost::system::error_code& ec)
{
    const auto record = co_await read_encrypted_record(socket, handshake_start_ms, timeout_sec, ec);
    if (ec)
    {
        co_return;
    }
    if (record.content_type == tls::kContentTypeChangeCipherSpec)
    {
        if (tls13_compat_ccs_count >= constants::tls_limits::kMaxCompatCcsRecords)
        {
            LOG_ERROR("received too many tls13 compat ccs records {}", tls13_compat_ccs_count);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
        tls13_compat_ccs_count++;
        LOG_DEBUG("received change cipher spec skip count {}", tls13_compat_ccs_count);
        co_return;
    }

    uint8_t type = 0;
    auto plaintext = tls::record_layer::decrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, seq++, record.ciphertext, type, ec);
    if (ec)
    {
        LOG_ERROR("error decrypting record {}", ec.message());
        co_return;
    }
    if (type == tls::kContentTypeAlert)
    {
        LOG_ERROR("received alert during handshake");
        ec = boost::asio::error::eof;
        co_return;
    }
    if (type != tls::kContentTypeHandshake)
    {
        LOG_ERROR("unexpected record content type during handshake {}", type);
        ec = boost::asio::error::invalid_argument;
        co_return;
    }

    consume_handshake_plaintext(plaintext, handshake_buffer, handshake_buffer_pos, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
}

struct server_hello_res
{
    tls::handshake_keys hs_keys;
    const EVP_MD* negotiated_md = nullptr;
    const EVP_CIPHER* negotiated_cipher = nullptr;
    uint16_t cipher_suite = 0;
    uint16_t key_share_group = 0;
};

boost::asio::awaitable<void> generate_and_send_client_hello(boost::asio::ip::tcp::socket& socket,
                                                            const uint8_t* public_key,
                                                            const uint8_t* private_key,
                                                            const std::vector<uint8_t>& x25519_mlkem768_key_share,
                                                            const fingerprint_template& spec,
                                                            const std::vector<uint8_t>& server_pub_key,
                                                            const std::vector<uint8_t>& short_id_bytes,
                                                            const std::string& sni,
                                                            tls::transcript& trans,
                                                            std::vector<uint8_t>& auth_key,
                                                            tls::client_hello_info& client_hello,
                                                            uint32_t write_timeout_sec,
                                                            boost::system::error_code& ec)
{
    constexpr std::array<uint8_t, 3> client_ver_{1, 0, 0};
    auto client_hello_result = build_authenticated_client_hello(
        public_key, private_key, x25519_mlkem768_key_share, server_pub_key, short_id_bytes, client_ver_, spec, sni, ec);
    if (ec)
    {
        co_return;
    }
    const auto& hello_body = client_hello_result.hello_body;
    if (hello_body.size() > std::numeric_limits<uint16_t>::max())
    {
        LOG_ERROR("client hello too large {}", hello_body.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return;
    }

    auto client_hello_record = tls::write_record_header(tls::kContentTypeHandshake, static_cast<uint16_t>(hello_body.size()));
    client_hello_record.insert(client_hello_record.end(), hello_body.begin(), hello_body.end());
    const auto write_size =
        co_await mux::net::wait_write_with_timeout(socket, boost::asio::buffer(client_hello_record), write_timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("error sending client hello {}", ec.message());
        co_return;
    }
    if (write_size != client_hello_record.size())
    {
        LOG_ERROR("short write client hello {} of {}", write_size, client_hello_record.size());
        ec = boost::asio::error::fault;
        co_return;
    }
    LOG_DEBUG("sending client hello record size {}", client_hello_record.size());
    auth_key = std::move(client_hello_result.auth_key);
    client_hello = std::move(client_hello_result.hello_info);
    trans.update(hello_body);
}

boost::asio::awaitable<server_hello_res> process_server_hello(boost::asio::ip::tcp::socket& socket,
                                                              const uint8_t* private_key,
                                                              const std::vector<uint8_t>& mlkem768_private_key,
                                                              const tls::client_hello_info& client_hello,
                                                              tls::transcript& trans,
                                                              std::vector<uint8_t>& extra_handshake_data,
                                                              uint32_t read_timeout_sec,
                                                              boost::system::error_code& ec)
{
    uint32_t tls13_compat_ccs_count = 0;
    const auto sh_data =
        co_await read_handshake_record_body(socket, "server hello", read_timeout_sec, tls13_compat_ccs_count, extra_handshake_data, ec);
    if (ec)
    {
        co_return server_hello_res{};
    }
    LOG_DEBUG("server hello received size {}", sh_data.size());

    tls::server_hello_info server_hello;
    uint16_t cipher_suite = 0;
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    prepare_server_hello_crypto(sh_data, client_hello, trans, server_hello, cipher_suite, md, cipher, ec);
    if (ec)
    {
        co_return server_hello_res{};
    }

    auto handshake_shared_secret =
        derive_server_hello_shared_secret(private_key, mlkem768_private_key, server_hello.key_share.group, server_hello.key_share.data, ec);
    if (ec)
    {
        co_return server_hello_res{};
    }

    auto hs_keys = tls::key_schedule::derive_handshake_keys(handshake_shared_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("derive handshake keys failed {}", ec.message());
        co_return server_hello_res{};
    }

    co_return server_hello_res{
        .hs_keys = hs_keys,
        .negotiated_md = md,
        .negotiated_cipher = cipher,
        .cipher_suite = cipher_suite,
        .key_share_group = server_hello.key_share.group,
    };
}

boost::asio::awaitable<client_handshake_read_result> handshake_read_loop(boost::asio::ip::tcp::socket& socket,
                                                                         const std::pair<std::vector<uint8_t>, std::vector<uint8_t>>& s_hs_keys,
                                                                         const tls::handshake_keys& hs_keys,
                                                                         const std::vector<uint8_t>& auth_key,
                                                                         const tls::client_hello_info& client_hello,
                                                                         const std::string& sni,
                                                                         tls::transcript& trans,
                                                                         std::vector<uint8_t> initial_handshake_data,
                                                                         const EVP_CIPHER* cipher,
                                                                         const EVP_MD* md,
                                                                         uint32_t max_handshake_records,
                                                                         uint32_t read_timeout_sec,
                                                                         boost::system::error_code& ec)
{
    const auto handshake_start_ms = mux::net::now_ms();
    bool handshake_fin = false;
    handshake_validation_state validation_state;
    validation_state.client_hello = &client_hello;
    uint64_t seq = 0;
    uint32_t tls13_compat_ccs_count = 0;
    uint32_t handshake_record_count = 0;
    std::vector<uint8_t> handshake_buffer;
    std::size_t handshake_buffer_pos = 0;

    if (!initial_handshake_data.empty())
    {
        consume_handshake_plaintext(
            initial_handshake_data, handshake_buffer, handshake_buffer_pos, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
        if (ec)
        {
            co_return client_handshake_read_result{};
        }
    }

    while (!handshake_fin)
    {
        if (handshake_record_count >= max_handshake_records)
        {
            LOG_ERROR("too many handshake records {} limit {}", handshake_record_count, max_handshake_records);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return client_handshake_read_result{};
        }
        co_await process_handshake_record(socket,
                                          s_hs_keys,
                                          auth_key,
                                          trans,
                                          cipher,
                                          handshake_buffer,
                                          handshake_buffer_pos,
                                          validation_state,
                                          handshake_fin,
                                          hs_keys,
                                          md,
                                          seq,
                                          tls13_compat_ccs_count,
                                          handshake_start_ms,
                                          read_timeout_sec,
                                          ec);
        if (ec)
        {
            co_return client_handshake_read_result{};
        }
        handshake_record_count++;
    }

    validate_server_handshake_chain(validation_state, sni, ec);
    if (ec)
    {
        co_return client_handshake_read_result{};
    }

    auto app_sec = tls::key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("derive app secrets failed {}", ec.message());
        co_return client_handshake_read_result{};
    }

    client_handshake_read_result result{
        .secrets =
            {
                .c_app_secret = std::move(app_sec.first),
                .s_app_secret = std::move(app_sec.second),
            },
        .negotiated_alpn = std::move(validation_state.negotiated_alpn),
        .auth_mode = validation_state.real_cert_chain_verified ? client_auth_mode::kRealCertificateFallback : client_auth_mode::kRealityTunnel,
    };
    co_return result;
}

boost::asio::awaitable<void> send_client_finished(boost::asio::ip::tcp::socket& socket,
                                                  const std::pair<std::vector<uint8_t>, std::vector<uint8_t>>& c_hs_keys,
                                                  const std::vector<uint8_t>& c_hs_secret,
                                                  const tls::transcript& trans,
                                                  const EVP_CIPHER* cipher,
                                                  const EVP_MD* md,
                                                  uint32_t write_timeout_sec,
                                                  boost::system::error_code& ec)
{
    auto fin_verify = tls::key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), md, ec);
    if (ec)
    {
        co_return;
    }
    const auto fin_msg = tls::construct_finished(fin_verify);
    const tls::cipher_context record_ctx;
    const traffic_key_material key_material{
        .key = c_hs_keys.first,
        .iv = c_hs_keys.second,
    };
    std::vector<uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    tls::record_layer::encrypt_tls_record(record_ctx, cipher, key_material, 0, fin_msg, tls::kContentTypeHandshake, out_flight, ec);
    if (ec)
    {
        co_return;
    }

    const auto write_res = co_await mux::net::wait_write_with_timeout(socket, boost::asio::buffer(out_flight), write_timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("send client finished flight error {}", ec.message());
        co_return;
    }
    LOG_DEBUG("sending client finished flight size {}", write_res);
}

client_handshake_result build_client_handshake_result(const server_hello_res& server_hello_result, client_handshake_read_result handshake_read_result)
{
    return client_handshake_result{
        .secrets =
            {
                .c_app_secret = std::move(handshake_read_result.secrets.c_app_secret),
                .s_app_secret = std::move(handshake_read_result.secrets.s_app_secret),
            },
        .negotiated =
            {
                .cipher_suite = server_hello_result.cipher_suite,
                .key_share_group = server_hello_result.key_share_group,
                .negotiated_alpn = std::move(handshake_read_result.negotiated_alpn),
                .md = server_hello_result.negotiated_md,
                .cipher = server_hello_result.negotiated_cipher,
            },
        .auth_mode = handshake_read_result.auth_mode,
    };
}

boost::asio::awaitable<client_handshake_result> execute_client_handshake(boost::asio::ip::tcp::socket& socket,
                                                                         uint32_t conn_id,
                                                                         const client_ephemeral_keys& keys,
                                                                         const std::vector<uint8_t>& server_public_key,
                                                                         const std::vector<uint8_t>& short_id_bytes,
                                                                         const std::string& sni,
                                                                         uint32_t max_handshake_records,
                                                                         uint32_t read_timeout_sec,
                                                                         uint32_t write_timeout_sec,
                                                                         boost::system::error_code& ec)
{
    tls::transcript trans;
    std::vector<uint8_t> auth_key;
    tls::client_hello_info client_hello;
    co_await generate_and_send_client_hello(socket,
                                            keys.public_key.data(),
                                            keys.private_key.data(),
                                            keys.hybrid_key_share,
                                            keys.template_spec,
                                            server_public_key,
                                            short_id_bytes,
                                            sni,
                                            trans,
                                            auth_key,
                                            client_hello,
                                            write_timeout_sec,
                                            ec);
    if (ec)
    {
        co_return client_handshake_result{};
    }

    std::vector<uint8_t> extra_handshake_data;
    const auto server_hello_result = co_await process_server_hello(
        socket, keys.private_key.data(), keys.mlkem768_private_key, client_hello, trans, extra_handshake_data, read_timeout_sec, ec);
    if (ec)
    {
        co_return client_handshake_result{};
    }
    LOG_INFO("event {} conn_id {} sni {} server hello key share group 0x{:04x} {}",
             mux::log_event::kHandshake,
             conn_id,
             sni,
             server_hello_result.key_share_group,
             tls::named_group_name(server_hello_result.key_share_group));

    const auto hs_keys =
        derive_handshake_traffic_keys(server_hello_result.hs_keys, server_hello_result.cipher_suite, server_hello_result.negotiated_md, ec);
    if (ec)
    {
        co_return client_handshake_result{};
    }

    auto handshake_read_result = co_await handshake_read_loop(socket,
                                                              hs_keys.s_hs_keys,
                                                              server_hello_result.hs_keys,
                                                              auth_key,
                                                              client_hello,
                                                              sni,
                                                              trans,
                                                              std::move(extra_handshake_data),
                                                              server_hello_result.negotiated_cipher,
                                                              server_hello_result.negotiated_md,
                                                              max_handshake_records,
                                                              read_timeout_sec,
                                                              ec);
    if (ec)
    {
        co_return client_handshake_result{};
    }

    co_await send_client_finished(socket,
                                  hs_keys.c_hs_keys,
                                  server_hello_result.hs_keys.client_handshake_traffic_secret,
                                  trans,
                                  server_hello_result.negotiated_cipher,
                                  server_hello_result.negotiated_md,
                                  write_timeout_sec,
                                  ec);
    if (ec)
    {
        co_return client_handshake_result{};
    }

    co_return build_client_handshake_result(server_hello_result, std::move(handshake_read_result));
}

}    // namespace

client_handshaker::client_handshaker(const mux::config& cfg,
                                     std::string_view sni,
                                     const std::vector<uint8_t>& server_public_key,
                                     const std::vector<uint8_t>& short_id_bytes,
                                     std::optional<fingerprint_type> fingerprint_type,
                                     uint32_t max_handshake_records)
    : cfg_(cfg),
      sni_(sni),
      server_public_key_(server_public_key),
      short_id_bytes_(short_id_bytes),
      fingerprint_type_(fingerprint_type),
      max_handshake_records_(max_handshake_records)
{
}

boost::asio::awaitable<client_handshake_result> client_handshaker::run(boost::asio::ip::tcp::socket& socket,
                                                                       uint32_t conn_id,
                                                                       boost::system::error_code& ec) const
{
    auto keys = prepare_client_ephemeral_keys(fingerprint_type_, ec);
    if (ec)
    {
        co_return client_handshake_result{};
    }
    const sensitive_client_key_guard sensitive_keys(keys);
    log_selected_client_key_share(conn_id, sni_, keys);

    auto result = co_await execute_client_handshake(
        socket, conn_id, keys, server_public_key_, short_id_bytes_, sni_, max_handshake_records_, cfg_.timeout.read, cfg_.timeout.write, ec);
    co_return result;
}

}    // namespace reality
