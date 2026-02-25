#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_connection;

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(const std::shared_ptr<mux_connection>& connection,
                       std::uint32_t id,
                       boost::asio::io_context& io_context,
                       const connection_context& ctx,
                       const config::timeout_t& timeout_cfg = {},
                       std::size_t recv_channel_capacity = 128);

    boost::asio::awaitable<void> start();

    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;
    void set_manager(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> start_impl(std::shared_ptr<remote_udp_session> self);
    boost::asio::awaitable<bool> setup_udp_socket(const std::shared_ptr<mux_connection>& conn);
    boost::asio::awaitable<boost::system::error_code> send_ack_payload(const std::shared_ptr<mux_connection>& conn, const ack_payload& ack) const;
    boost::asio::awaitable<void> handle_start_failure(const std::shared_ptr<mux_connection>& conn,
                                                      const char* step,
                                                      const boost::system::error_code& ec);
    boost::asio::awaitable<void> forward_mux_payload(const std::vector<std::uint8_t>& data);
    bool switch_udp_socket_to_v4();
    bool switch_udp_socket_to_v6();
    void log_udp_local_endpoint();
    boost::asio::awaitable<void> run_udp_session_loops();
    boost::asio::awaitable<void> cleanup_after_stop();
    void record_udp_write(std::size_t bytes);
    boost::asio::awaitable<void> watchdog();
    boost::asio::awaitable<void> mux_to_udp();
    boost::asio::awaitable<void> udp_to_mux();
    boost::asio::awaitable<void> idle_watchdog();
    void request_stop();
    void close_socket();

   private:
    std::uint32_t id_;
    connection_context ctx_;
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer timer_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    std::weak_ptr<mux_connection> connection_;
    bool udp_socket_use_v6_ = true;
    bool udp_socket_dual_stack_ = true;
    std::atomic<bool> terminated_{false};
    std::atomic<bool> cleaned_up_{false};
    std::atomic<std::uint64_t> last_read_time_ms_{0};
    std::atomic<std::uint64_t> last_write_time_ms_{0};
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::uint64_t read_timeout_ms_ = 0;
    std::uint64_t write_timeout_ms_ = 0;
    std::uint64_t idle_timeout_ms_ = 0;
    std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
