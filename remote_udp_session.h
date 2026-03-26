#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <atomic>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include "lru_cache.h"
#include "net_utils.h"
#include "mux_protocol.h"
#include "connection_context.h"

namespace mux
{

class remote_udp_session : public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(boost::asio::io_context& io_context,
                       const std::shared_ptr<mux_connection>& connection,
                       std::uint32_t id,
                       const connection_context& ctx,
                       const config& cfg);

    boost::asio::awaitable<void> start();

   private:
    boost::asio::awaitable<void> start_impl();
    boost::asio::awaitable<void> on_frame(const mux_frame& frame, boost::system::error_code& ec);

    boost::asio::awaitable<void> mux_to_udp();
    boost::asio::awaitable<void> udp_to_mux();
    boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint(const std::string& host,
                                                                                                 std::uint16_t port,
                                                                                                 boost::system::error_code& ec);

   private:
    struct endpoint_cache_entry
    {
        boost::asio::ip::udp::endpoint endpoint;
        std::uint64_t expires_at = 0;
        boost::system::error_code last_error;
        bool negative = false;
    };

    struct peer_cache_entry
    {
        std::uint64_t expires_at = 0;
    };

    std::uint32_t id_;
    const config& cfg_;
    connection_context ctx_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    std::shared_ptr<mux_stream> stream_;
    std::weak_ptr<mux_connection> connection_;
    std::uint64_t last_activity_time_ms_{0};
    lru_cache<std::string, endpoint_cache_entry> resolved_targets_;
    lru_cache<boost::asio::ip::udp::endpoint, peer_cache_entry, net::udp_endpoint_hash, net::udp_endpoint_equal> allowed_reply_peers_;
    std::atomic<std::uint8_t> stream_close_command_{0};
};

}    // namespace mux

#endif
