#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/experimental/concurrent_channel.hpp>

#include "router.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;

class udp_socks_session : public mux_stream_interface, public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager, std::uint32_t sid);

    void start(const std::string& host, std::uint16_t port);

   private:
    asio::awaitable<void> run(const std::string& host, std::uint16_t port);

   public:
    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;

   private:
    asio::awaitable<void> udp_sock_to_stream(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep);

    asio::awaitable<void> stream_to_udp_sock(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep);

    asio::awaitable<void> keep_tcp_alive();

   private:
    connection_context ctx_;
    asio::steady_timer timer_;
    asio::ip::tcp::socket socket_;
    asio::ip::udp::socket udp_socket_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
