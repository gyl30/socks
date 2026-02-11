#ifndef TPROXY_UDP_SESSION_H
#define TPROXY_UDP_SESSION_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <asio/ip/udp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "tproxy_udp_sender.h"
#include "client_tunnel_pool.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;

class tproxy_udp_session : public mux_stream_interface, public std::enable_shared_from_this<tproxy_udp_session>
{
   public:
    tproxy_udp_session(const asio::io_context::executor_type& ex,
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       std::shared_ptr<router> router,
                       std::shared_ptr<tproxy_udp_sender> sender,
                       std::uint32_t sid,
                       const config& cfg,
                       asio::ip::udp::endpoint client_ep);

    void start();

    asio::awaitable<void> handle_packet(const asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, std::size_t len);

    void stop();

    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;

    [[nodiscard]] bool is_idle(std::uint64_t now_ms, std::uint64_t idle_ms) const;

   private:
    static std::uint64_t now_ms();

    void touch();
    asio::awaitable<void> handle_packet_inner(asio::ip::udp::endpoint dst_ep, std::vector<std::uint8_t> data);

    asio::awaitable<bool> ensure_proxy_stream();

    asio::awaitable<void> send_proxy(const asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, std::size_t len);

    asio::awaitable<void> send_direct(const asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, std::size_t len);

    asio::awaitable<void> direct_read_loop();

    asio::awaitable<void> proxy_read_loop();

   private:
    connection_context ctx_;
    asio::io_context::executor_type ex_;
    asio::ip::udp::socket direct_socket_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    std::shared_ptr<tproxy_udp_sender> sender_;
    std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_;
    std::shared_ptr<mux_stream> stream_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
    asio::ip::udp::endpoint client_ep_;
    std::uint32_t mark_ = 0;
    std::atomic<std::uint64_t> last_activity_ms_{0};
    bool proxy_reader_started_ = false;
};

}    // namespace mux

#endif
