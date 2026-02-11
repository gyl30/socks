#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <vector>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/experimental/concurrent_channel.hpp>

#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_connection;

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection,
                       std::uint32_t id,
                       asio::io_context& io_context,
                       const connection_context& ctx);

    asio::awaitable<void> start();

    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;
    void set_manager(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& m) { manager_ = m; }

   private:
    asio::awaitable<void> start_impl(std::shared_ptr<remote_udp_session> self);
    asio::awaitable<void> watchdog();
    asio::awaitable<void> mux_to_udp();
    asio::awaitable<void> udp_to_mux();
    asio::awaitable<void> idle_watchdog();
    void request_stop();
    void close_socket();

   private:
    std::uint32_t id_;
    connection_context ctx_;
    asio::io_context& io_context_;
    asio::steady_timer timer_;
    asio::steady_timer idle_timer_;
    asio::ip::udp::socket udp_socket_;
    asio::ip::udp::resolver udp_resolver_;
    std::weak_ptr<mux_connection> connection_;
    std::atomic<std::uint64_t> last_read_time_ms_{0};
    std::atomic<std::uint64_t> last_write_time_ms_{0};
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
