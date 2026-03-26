#include <vector>
#include <cstdint>
#include <utility>

#include <boost/system/error_code.hpp>

#include "constants.h"
#include "reality/types.h"
#include "tls/cipher_suite.h"
#include "tls/key_schedule.h"
#include "reality/session/engine.h"
#include "reality/session/session.h"

namespace reality
{

namespace
{

traffic_key_material make_traffic_key_material(std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> material)
{
    return {
        .key = std::move(material.first),
        .iv = std::move(material.second),
    };
}

bool validate_negotiated_params(const negotiated_params& negotiated, boost::system::error_code& ec)
{
    ec.clear();
    if (negotiated.md == nullptr || negotiated.cipher == nullptr)
    {
        ec = boost::asio::error::invalid_argument;
        return false;
    }
    return true;
}

}    // namespace

reality_session::reality_session(negotiated_params negotiated, traffic_key_material read_keys, traffic_key_material write_keys)
    : negotiated_(std::move(negotiated)), read_keys_(std::move(read_keys)), write_keys_(std::move(write_keys))
{
}

reality_session reality_session::build_from_parts(const negotiated_params& negotiated,
                                                  const traffic_secrets& secrets,
                                                  const perspective session_perspective,
                                                  boost::system::error_code& ec)
{
    ec.clear();
    if (!validate_negotiated_params(negotiated, ec))
    {
        return {};
    }

    const auto suite = ::tls::select_tls13_suite(negotiated.cipher_suite);
    if (!suite.has_value())
    {
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    const auto key_len = suite->key_len;

    auto client_keys = ::tls::key_schedule::derive_traffic_keys(secrets.c_app_secret, ec, key_len, constants::crypto::kIvLen, negotiated.md);
    if (ec)
    {
        return {};
    }
    auto server_keys = ::tls::key_schedule::derive_traffic_keys(secrets.s_app_secret, ec, key_len, constants::crypto::kIvLen, negotiated.md);
    if (ec)
    {
        return {};
    }

    auto read_keys = make_traffic_key_material(session_perspective == perspective::kClient ? std::move(server_keys) : std::move(client_keys));
    auto write_keys = make_traffic_key_material(session_perspective == perspective::kClient ? std::move(client_keys) : std::move(server_keys));
    return {negotiated, std::move(read_keys), std::move(write_keys)};
}

reality_session reality_session::from_client_handshake(const client_handshake_result& handshake_result, boost::system::error_code& ec)
{
    return build_from_parts(handshake_result.negotiated, handshake_result.secrets, perspective::kClient, ec);
}

reality_session reality_session::from_authenticated_session(const authenticated_session& authenticated, boost::system::error_code& ec)
{
    return build_from_parts(authenticated.negotiated, authenticated.secrets, perspective::kServer, ec);
}

mux::reality_engine reality_session::take_engine() &&
{
    return {std::move(read_keys_.key), std::move(read_keys_.iv), std::move(write_keys_.key), std::move(write_keys_.iv), negotiated_.cipher};
}

}    // namespace reality
