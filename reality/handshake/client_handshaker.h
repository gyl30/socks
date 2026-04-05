#ifndef REALITY_CLIENT_HANDSHAKER_H
#define REALITY_CLIENT_HANDSHAKER_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "reality/handshake/fingerprint.h"
#include "reality/types.h"

namespace reality
{

class client_handshaker
{
   public:
    client_handshaker(const mux::config& cfg,
                      std::string_view sni,
                      const std::vector<uint8_t>& server_public_key,
                      const std::vector<uint8_t>& short_id_bytes,
                      std::optional<fingerprint_type> fingerprint_type,
                      uint32_t max_handshake_records);

    [[nodiscard]] boost::asio::awaitable<client_handshake_result> run(boost::asio::ip::tcp::socket& socket,
                                                                      uint32_t conn_id,
                                                                      boost::system::error_code& ec) const;

   private:
    const mux::config& cfg_;
    std::string sni_;
    std::vector<uint8_t> server_public_key_;
    std::vector<uint8_t> short_id_bytes_;
    std::optional<fingerprint_type> fingerprint_type_;
    uint32_t max_handshake_records_ = 0;
};

}    // namespace reality

#endif
