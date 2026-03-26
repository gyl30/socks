#ifndef REALITY_SERVER_HANDSHAKER_H
#define REALITY_SERVER_HANDSHAKER_H

#include <array>
#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "connection_context.h"
#include "reality/types.h"

namespace mux
{

struct config;
class replay_cache;

}    // namespace mux

namespace reality
{

struct site_material;

struct server_handshake_context
{
    boost::asio::ip::tcp::socket* socket = nullptr;
    mux::connection_context ctx;
};

class server_handshaker
{
   public:
    struct dependencies
    {
        const mux::config& cfg;
        const std::vector<std::uint8_t>& private_key;
        const std::vector<std::uint8_t>& short_id_bytes;
        mux::replay_cache& replay_cache;
        const site_material* site_material_ptr = nullptr;
        const std::array<std::uint8_t, 32>& reality_cert_private_key;
        const std::vector<std::uint8_t>& reality_cert_public_key;
        const std::vector<std::uint8_t>& reality_cert_template;
    };

    explicit server_handshaker(dependencies deps);

    [[nodiscard]] boost::asio::awaitable<server_accept_result> accept(server_handshake_context& handshake_ctx,
                                                                      boost::system::error_code& ec) const;

   private:
    const mux::config& cfg_;
    const std::vector<std::uint8_t>& private_key_;
    const std::vector<std::uint8_t>& short_id_bytes_;
    mux::replay_cache& replay_cache_;
    const site_material* site_material_ = nullptr;
    const std::array<std::uint8_t, 32>& reality_cert_private_key_;
    const std::vector<std::uint8_t>& reality_cert_public_key_;
    const std::vector<std::uint8_t>& reality_cert_template_;
};

}    // namespace reality

#endif
