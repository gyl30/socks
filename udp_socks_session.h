#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "mux_tunnel.h"
#include "task_group.h"
#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;
namespace detail
{
std::vector<std::uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, std::uint16_t udp_bind_port);
}

class udp_socks_session : public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(boost::asio::ip::tcp::socket socket,
                      boost::asio::io_context& io_context,
                      std::shared_ptr<mux_tunnel_impl> tunnel_manager,
                      std::uint32_t sid,
                      const config& cfg,
                      task_group& group,
                      std::shared_ptr<void> active_connection_guard = nullptr);

    void start(const std::string& host, std::uint16_t port);
    void stop();

   private:
    boost::asio::awaitable<void> run(const std::string& host, std::uint16_t port);

   private:
    boost::asio::awaitable<void> udp_sock_to_stream(std::shared_ptr<mux_stream> stream);

    boost::asio::awaitable<void> stream_to_udp_sock(std::shared_ptr<mux_stream> stream);

    boost::asio::awaitable<void> keep_tcp_alive();
    boost::asio::awaitable<void> idle_watchdog();
    void close_impl();

   private:
    connection_context ctx_;
    const config& cfg_;
    task_group& group_;
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer timer_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::udp::socket udp_socket_;
    std::shared_ptr<mux_tunnel_impl> tunnel_manager_;
    std::uint64_t last_activity_time_ms_{0};
    bool has_client_addr_ = false;
    boost::asio::ip::udp::endpoint client_addr_;
    std::shared_ptr<void> active_connection_guard_;
};

}    // namespace mux

#endif
