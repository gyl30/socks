#ifndef CLIENT_TUNNEL_POOL_H
#define CLIENT_TUNNEL_POOL_H

#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <utility>
#include <expected>
#include <optional>

#include <openssl/types.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "context_pool.h"
#include "mux_connection.h"
#include "reality/types.h"
#include "tls/core.h"
#include "tls/ch_parser.h"
#include "reality/handshake/fingerprint.h"

namespace mux
{

class connection_context;

class client_tunnel_pool : public std::enable_shared_from_this<client_tunnel_pool>
{
   public:
    client_tunnel_pool(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::shared_ptr<mux_connection> select_tunnel();
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<mux_connection>> wait_for_tunnel(boost::asio::io_context& io_context,
                                                                                           boost::system::error_code& ec);

    [[nodiscard]] std::uint32_t next_session_id();

   private:
    using handshake_auth_mode = reality::client_auth_mode;
    using handshake_result = reality::client_handshake_result;

    boost::asio::awaitable<void> connect_remote_loop(std::uint32_t index, boost::asio::io_context& io_context);
    [[nodiscard]] boost::asio::awaitable<void> tcp_connect_remote(boost::asio::io_context& io_context,
                                                                  boost::asio::ip::tcp::socket& socket,
                                                                  const connection_context& ctx,
                                                                  boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::awaitable<handshake_result> perform_reality_handshake_with_timeout(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const connection_context& ctx, boost::system::error_code& ec) const;
    [[nodiscard]] std::shared_ptr<mux_connection> build_tunnel(boost::asio::ip::tcp::socket socket,
                                                               boost::asio::io_context& io_context,
                                                               std::uint32_t cid,
                                                               const handshake_result& handshake_ret,
                                                               const std::string& trace_id) const;
    [[nodiscard]] boost::asio::awaitable<void> run_real_certificate_fallback(boost::asio::ip::tcp::socket& socket,
                                                                             const handshake_result& handshake_ret,
                                                                             const connection_context& ctx) const;

   private:
    std::string sni_;
    std::string remote_host_;
    std::string remote_port_;
    const config& cfg_;
    io_context_pool& pool_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::atomic<std::uint32_t> next_tunnel_index_{0};
    std::atomic<std::uint32_t> next_conn_id_{1};
    std::atomic<std::uint32_t> next_session_id_{1};
    std::uint32_t max_handshake_records_ = 256;
    std::vector<std::uint8_t> server_pub_key_;
    std::optional<reality::fingerprint_type> fingerprint_type_;
    std::mutex tunnel_mutex_;
    std::vector<std::shared_ptr<mux_connection>> tunnel_pool_;
    std::once_flag stop_once_;
};

}    // namespace mux

#endif
