#include <vector>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include "constants.h"
#include "reality/types.h"
#include "tls/cipher_suite.h"
#include "tls/key_schedule.h"
#include "reality/session/session.h"

namespace reality
{

namespace
{

enum class perspective : uint8_t
{
    kClient,
    kServer,
};

traffic_key_material make_traffic_key_material(std::pair<std::vector<uint8_t>, std::vector<uint8_t>> material)
{
    return {
        .key = std::move(material.first),
        .iv = std::move(material.second),
    };
}

bool validate_negotiated_params(const negotiated_params& negotiated, boost::system::error_code& ec)
{
    if (negotiated.md == nullptr || negotiated.cipher == nullptr)
    {
        ec = boost::asio::error::invalid_argument;
        return false;
    }
    return true;
}

}    // namespace

reality_record_context build_reality_record_context_from_parts(const negotiated_params& negotiated,
                                                               const traffic_secrets& secrets,
                                                               const perspective session_perspective,
                                                               boost::system::error_code& ec)
{
    if (!validate_negotiated_params(negotiated, ec))
    {
        return {};
    }

    const auto suite = tls::select_tls13_suite(negotiated.cipher_suite);
    if (!suite.has_value())
    {
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    const auto key_len = suite->key_len;

    auto client_keys = tls::key_schedule::derive_traffic_keys(secrets.c_app_secret, ec, key_len, constants::crypto::kIvLen, negotiated.md);
    if (ec)
    {
        return {};
    }
    auto server_keys = tls::key_schedule::derive_traffic_keys(secrets.s_app_secret, ec, key_len, constants::crypto::kIvLen, negotiated.md);
    if (ec)
    {
        return {};
    }

    auto read_keys = make_traffic_key_material(session_perspective == perspective::kClient ? std::move(server_keys) : std::move(client_keys));
    auto write_keys = make_traffic_key_material(session_perspective == perspective::kClient ? std::move(client_keys) : std::move(server_keys));
    return {
        .negotiated = negotiated,
        .read_keys = std::move(read_keys),
        .write_keys = std::move(write_keys),
    };
}

reality_record_context build_reality_record_context(const client_handshake_result& handshake_result, boost::system::error_code& ec)
{
    return build_reality_record_context_from_parts(handshake_result.negotiated, handshake_result.secrets, perspective::kClient, ec);
}

reality_record_context build_reality_record_context(const authenticated_session& authenticated, boost::system::error_code& ec)
{
    return build_reality_record_context_from_parts(authenticated.negotiated, authenticated.secrets, perspective::kServer, ec);
}

}    // namespace reality
