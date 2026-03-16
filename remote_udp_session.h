#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "lru_cache.h"

namespace mux
{

class mux_connection;

class remote_udp_session : public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(const std::shared_ptr<mux_connection>& connection,
                       std::uint32_t id,
                       boost::asio::io_context& io_context,
                       const connection_context& ctx,
                       const config& cfg);

    boost::asio::awaitable<void> start();

    void on_data(std::vector<std::uint8_t> data);
    void on_close();
    void on_reset();
    void set_manager(const std::shared_ptr<mux_tunnel_impl>& m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> start_impl();
    boost::asio::awaitable<bool> setup_udp_socket(const std::shared_ptr<mux_connection>& conn);
    boost::asio::awaitable<boost::system::error_code> send_ack_payload(const std::shared_ptr<mux_connection>& conn, const ack_payload& ack) const;
    boost::asio::awaitable<void> handle_start_failure(const std::shared_ptr<mux_connection>& conn,
                                                      const char* step,
                                                      const boost::system::error_code& ec);
    boost::asio::awaitable<void> on_frame(const mux_frame& frame, boost::system::error_code& ec);
    bool switch_udp_socket_to_v4();
    bool switch_udp_socket_to_v6();
    void log_udp_local_endpoint();
    boost::asio::awaitable<void> run_udp_session_loops();
    boost::asio::awaitable<void> cleanup_after_stop();
    void record_udp_write(std::size_t bytes);
    boost::asio::awaitable<void> mux_to_udp();
    boost::asio::awaitable<void> udp_to_mux();
    boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint(const std::string& host,
                                                                                                  std::uint16_t port,
                                                                                                  boost::system::error_code& ec);
    void request_stop();
    void close_socket();

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
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    std::shared_ptr<mux_stream> stream_;
    std::weak_ptr<mux_connection> connection_;
    std::uint64_t last_activity_time_ms_{0};
    lru_cache<std::string, endpoint_cache_entry> resolved_targets_;
    lru_cache<std::uint64_t, peer_cache_entry> allowed_reply_peers_;
    std::weak_ptr<mux_tunnel_impl> manager_;
    std::atomic<std::uint8_t> stream_close_command_{0};
};

}    // namespace mux

#endif
