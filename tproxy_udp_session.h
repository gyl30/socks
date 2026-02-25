#ifndef TPROXY_UDP_SESSION_H
#define TPROXY_UDP_SESSION_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
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
    tproxy_udp_session(boost::asio::io_context& io_context,
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       std::shared_ptr<router> router,
                       std::shared_ptr<tproxy_udp_sender> sender,
                       std::uint32_t sid,
                       const config& cfg,
                       const boost::asio::ip::udp::endpoint& client_ep);

    bool start();

    boost::asio::awaitable<void> handle_packet(const boost::asio::ip::udp::endpoint& dst_ep, std::vector<std::uint8_t> data);

    boost::asio::awaitable<void> handle_packet(const boost::asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, std::size_t len);

    void stop();

    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;

    [[nodiscard]] bool is_idle(std::uint64_t now_ms, std::uint64_t idle_ms) const;
    [[nodiscard]] bool terminated() const { return terminated_.load(std::memory_order_acquire); }

   private:
    static std::uint64_t now_ms();
    [[nodiscard]] static boost::asio::awaitable<void> direct_read_loop_detached(std::shared_ptr<tproxy_udp_session> self);
    [[nodiscard]] static boost::asio::awaitable<void> proxy_read_loop_detached(std::shared_ptr<tproxy_udp_session> self);

    void touch();
    boost::asio::awaitable<void> handle_packet_inner(boost::asio::ip::udp::endpoint dst_ep, std::vector<std::uint8_t> data);

    [[nodiscard]] boost::asio::awaitable<bool> negotiate_proxy_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                                      const std::shared_ptr<mux_stream>& stream) const;

    [[nodiscard]] static boost::asio::awaitable<void> cleanup_proxy_stream(
        const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel, const std::shared_ptr<mux_stream>& stream);

    bool install_proxy_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                              const std::shared_ptr<mux_stream>& stream,
                              bool& should_start_reader);
    boost::asio::awaitable<std::optional<bool>> open_proxy_stream();
    void maybe_start_proxy_reader(bool should_start_reader);
    bool decode_proxy_packet(const std::vector<std::uint8_t>& data, boost::asio::ip::udp::endpoint& src_ep, std::size_t& payload_offset) const;

    boost::asio::awaitable<bool> ensure_proxy_stream();

    boost::asio::awaitable<void> send_proxy(const boost::asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, std::size_t len);
    void refresh_cached_proxy_header(const boost::asio::ip::udp::endpoint& dst_ep);
    [[nodiscard]] bool build_proxy_packet(const boost::asio::ip::udp::endpoint& dst_ep,
                                          const std::uint8_t* data,
                                          std::size_t len,
                                          std::vector<std::uint8_t>& packet);
    boost::asio::awaitable<void> handle_proxy_write_failure(const std::shared_ptr<mux_stream>& stream, const boost::system::error_code& write_ec);

    boost::asio::awaitable<void> send_direct(const boost::asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, std::size_t len);
    bool switch_direct_socket_to_v4();
    bool switch_direct_socket_to_v6();

    boost::asio::awaitable<void> direct_read_loop();

    boost::asio::awaitable<void> proxy_read_loop();
    void stop_local(bool allow_async_stream_close);
    void on_close_local();

   private:
    connection_context ctx_;
    boost::asio::io_context& io_context_;
    boost::asio::ip::udp::socket direct_socket_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    std::shared_ptr<tproxy_udp_sender> sender_;
    std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_;
    std::shared_ptr<mux_stream> stream_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    boost::asio::ip::udp::endpoint client_ep_;
    std::uint32_t mark_ = 0;
    std::uint32_t connect_timeout_sec_ = 0;
    std::atomic<std::uint64_t> last_activity_ms_{0};
    std::atomic<bool> terminated_{false};
    bool direct_socket_use_v6_ = true;
    bool direct_socket_dual_stack_ = true;
    bool proxy_reader_started_ = false;
    bool has_cached_proxy_header_ = false;
    boost::asio::ip::udp::endpoint cached_proxy_dst_ep_;
    std::vector<std::uint8_t> cached_proxy_header_;
};

}    // namespace mux

#endif
