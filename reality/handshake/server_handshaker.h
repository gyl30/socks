#ifndef REALITY_SERVER_HANDSHAKER_H
#define REALITY_SERVER_HANDSHAKER_H

#include <array>
#include <vector>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "replay_cache.h"
#include "reality/types.h"
#include "site_material.h"
#include "reality/handshake/server_handshake_context.h"

namespace reality
{

class server_handshaker
{
   public:
    struct dependencies
    {
        const relay::config& cfg;
        const std::vector<uint8_t>& private_key;
        const std::vector<uint8_t>& short_id_bytes;
        relay::replay_cache& replay_cache;
        const site_material* site_material_ptr = nullptr;
        const std::array<uint8_t, 32>& reality_cert_private_key;
        const std::vector<uint8_t>& reality_cert_public_key;
        const std::vector<uint8_t>& reality_cert_template;
    };

    explicit server_handshaker(const dependencies& deps);

    [[nodiscard]] boost::asio::awaitable<server_accept_result> accept(server_handshake_context& handshake_ctx, boost::system::error_code& ec) const;

   private:
    const relay::config& cfg_;
    const std::vector<uint8_t>& private_key_;
    const std::vector<uint8_t>& short_id_bytes_;
    relay::replay_cache& replay_cache_;
    const site_material* site_material_ = nullptr;
    const std::array<uint8_t, 32>& reality_cert_private_key_;
    const std::vector<uint8_t>& reality_cert_public_key_;
    const std::vector<uint8_t>& reality_cert_template_;
};

}    // namespace reality

#endif
