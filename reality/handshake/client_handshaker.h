#ifndef REALITY_CLIENT_HANDSHAKER_H
#define REALITY_CLIENT_HANDSHAKER_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "reality/types.h"

namespace mux
{

struct config;
class connection_context;

}    // namespace mux

namespace reality
{

enum class fingerprint_type : std::uint8_t;

class client_handshaker
{
   public:
    client_handshaker(const mux::config& cfg,
                      std::string_view sni,
                      const std::vector<std::uint8_t>& server_public_key,
                      const std::vector<std::uint8_t>& short_id_bytes,
                      std::optional<fingerprint_type> fingerprint_type,
                      std::uint32_t max_handshake_records);

    [[nodiscard]] boost::asio::awaitable<client_handshake_result> run(boost::asio::ip::tcp::socket& socket,
                                                                      const mux::connection_context& ctx,
                                                                      boost::system::error_code& ec) const;

   private:
    const mux::config& cfg_;
    std::string sni_;
    std::vector<std::uint8_t> server_public_key_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::optional<fingerprint_type> fingerprint_type_;
    std::uint32_t max_handshake_records_ = 0;
};

}    // namespace reality

#endif
