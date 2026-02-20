#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <atomic>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;
namespace detail
{
std::vector<std::uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, std::uint16_t udp_bind_port);
}

class udp_socks_session : public mux_stream_interface, public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(boost::asio::ip::tcp::socket socket,
                      boost::asio::io_context& io_context,
                      std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager,
                      std::uint32_t sid,
                      const config::timeout_t& timeout_cfg,
                      std::shared_ptr<void> active_connection_guard = nullptr,
                      std::size_t recv_channel_capacity = 128);

    void start(const std::string& host, std::uint16_t port);

   private:
    boost::asio::awaitable<void> run(const std::string& host, std::uint16_t port);

   public:
    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;

   private:
    boost::asio::awaitable<void> udp_sock_to_stream(std::shared_ptr<mux_stream> stream);

    boost::asio::awaitable<void> stream_to_udp_sock(std::shared_ptr<mux_stream> stream);
    boost::asio::awaitable<std::shared_ptr<mux_stream>> prepare_udp_associate(boost::asio::ip::address& local_addr, std::uint16_t& udp_bind_port);
    boost::asio::awaitable<void> finalize_udp_associate(const std::shared_ptr<mux_stream>& stream);
    [[nodiscard]] bool should_stop_stream_to_udp(const boost::system::error_code& ec, const std::vector<std::uint8_t>& data) const;
    boost::asio::awaitable<void> forward_stream_data_to_client(const std::vector<std::uint8_t>& data);

    boost::asio::awaitable<void> keep_tcp_alive();
    boost::asio::awaitable<void> idle_watchdog();
    void close_impl();

   private:
    connection_context ctx_;
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer timer_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::udp::socket udp_socket_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::atomic<bool> closed_{false};
    boost::asio::ip::udp::endpoint client_ep_;
    bool has_client_ep_ = false;
    std::shared_ptr<void> active_connection_guard_;
    config::timeout_t timeout_config_;
};

}    // namespace mux

#endif
