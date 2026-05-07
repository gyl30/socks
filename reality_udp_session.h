#ifndef REALITY_UDP_ASSOCIATE_SESSION_H
#define REALITY_UDP_ASSOCIATE_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
#include "lru_cache.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "session_result.h"
#include "request_context.h"
#include "udp_session_cache.h"
#include "task_group.h"
#include "udp_proxy_outbound.h"
#include "udp_proxy_outbound_registry.h"
#include "proxy_reality_connection.h"

namespace relay
{

class reality_udp_session : public std::enable_shared_from_this<reality_udp_session>
{
   public:
    reality_udp_session(boost::asio::io_context& io_context,
                                  std::shared_ptr<proxy_reality_connection> connection,
                                  std::shared_ptr<router> router,
                                  uint32_t conn_id,
                                  uint64_t trace_id,
                                  std::string inbound_tag,
                                  const config& cfg);

    boost::asio::awaitable<void> start(const proxy::udp_associate_request& request);

   private:
    boost::asio::awaitable<void> start_impl(const proxy::udp_associate_request& request);
    [[nodiscard]] boost::asio::awaitable<bool> establish_udp_associate();
    [[nodiscard]] boost::asio::awaitable<bool> send_udp_associate_reply(uint8_t socks_rep);
    [[nodiscard]] bool open_bind_udp_socket();
    void close_udp_socket();
    [[nodiscard]] request_context make_route_request(const proxy::udp_datagram& datagram) const;
    [[nodiscard]] request_context make_proxy_outbound_request() const;
    [[nodiscard]] boost::asio::awaitable<bool> forward_direct_datagram(const proxy::udp_datagram& datagram, const std::string& route_name);
    [[nodiscard]] boost::asio::awaitable<bool> forward_proxy_datagram(const proxy::udp_datagram& datagram,
                                                                      const route_decision& decision,
                                                                      const std::string& route_name);
    [[nodiscard]] boost::asio::awaitable<bool> process_connection_datagram(const proxy::udp_datagram& datagram,
                                                                            const route_decision& decision,
                                                                            const std::string& route_name);
    [[nodiscard]] boost::asio::awaitable<std::size_t> forward_proxy_reply_to_connection(const proxy::udp_datagram& datagram,
                                                                                        const std::string& outbound_tag,
                                                                                        boost::system::error_code& ec);
    boost::asio::awaitable<void> connection_to_udp();
    boost::asio::awaitable<void> udp_to_connection();
    boost::asio::awaitable<void> proxy_to_connection(const std::string& outbound_tag, const std::shared_ptr<udp_proxy_outbound>& upstream);
    boost::asio::awaitable<void> connection_writer();
    [[nodiscard]] boost::asio::awaitable<bool> enqueue_connection_packet(std::vector<uint8_t> packet, boost::system::error_code& ec);
    boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<route_decision> decide_route(const proxy::udp_datagram& datagram) const;
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> get_proxy_outbound(const std::string& outbound_tag);
    void record_proxy_outbound_connect_result(const std::string& outbound_tag,
                                              bool success,
                                              const boost::system::error_code& ec) const;
    boost::asio::awaitable<void> close_proxy_outbounds();
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint(const std::string& host,
                                                                                                 uint16_t port,
                                                                                                 boost::system::error_code& ec);

    using connection_write_channel_type =
        boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<uint8_t>)>;

    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    std::string inbound_tag_;
    std::string inbound_type_ = "reality";
    const config& cfg_;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    uint32_t request_timeout_sec_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    connection_write_channel_type connection_write_channel_;
    task_group proxy_reader_group_;
    std::shared_ptr<proxy_reality_connection> connection_;
    std::shared_ptr<router> router_;
    uint64_t last_activity_time_ms_{0};
    udp_proxy_outbound_registry proxy_outbounds_;
    lru_cache<std::string, udp_endpoint_cache_entry> resolved_targets_;
    lru_cache<boost::asio::ip::udp::endpoint, udp_peer_cache_entry, net::udp_endpoint_hash, net::udp_endpoint_equal> allowed_reply_peers_;
    std::atomic<bool> stopping_{false};
    udp_close_reason close_reason_ = udp_close_reason::kUnknown;
};

}    // namespace relay

#endif
