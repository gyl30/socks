#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <vector>
#include <chrono>
#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection, uint32_t id, const asio::any_io_executor& ex, const connection_context& ctx);

    asio::awaitable<void> start();

    void on_data(std::vector<uint8_t> data) override;
    void on_close() override;
    void on_reset() override;
    void set_manager(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& m) { manager_ = m; }

   private:
    asio::awaitable<void> watchdog();
    asio::awaitable<void> mux_to_udp();
    asio::awaitable<void> udp_to_mux();

   private:
    uint32_t id_;
    connection_context ctx_;
    asio::steady_timer timer_;
    asio::ip::udp::socket udp_socket_;
    asio::ip::udp::resolver udp_resolver_;
    std::shared_ptr<mux_connection> connection_;
    std::chrono::steady_clock::time_point last_read_time_;
    std::chrono::steady_clock::time_point last_write_time_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
