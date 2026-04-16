#ifndef REALITY_UDP_ASSOCIATE_SESSION_H
#define REALITY_UDP_ASSOCIATE_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include "config.h"
#include "lru_cache.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "request_context.h"
#include "router.h"
#include "udp_proxy_outbound.h"

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
    boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<route_decision> decide_route(const proxy::udp_datagram& datagram) const;
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> get_proxy_outbound(const std::string& outbound_tag);
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> apply_proxy_outbound_connect_result(
        const std::string& outbound_tag,
        const udp_proxy_outbound_connect_result& connect_result);
    void record_proxy_outbound_connect_result(const std::string& outbound_tag,
                                              bool success,
                                              const boost::system::error_code& ec) const;
    boost::asio::awaitable<void> close_proxy_outbounds();
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint(const std::string& host,
                                                                                                 uint16_t port,
                                                                                                 boost::system::error_code& ec);

   private:
    struct endpoint_cache_entry
    {
        boost::asio::ip::udp::endpoint endpoint;
        uint64_t expires_at = 0;
        boost::system::error_code last_error;
        bool negative = false;
    };

    struct peer_cache_entry
    {
        uint64_t expires_at = 0;
    };

    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    std::string inbound_tag_;
    std::string inbound_type_ = "reality";
    const config& cfg_;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    std::shared_ptr<proxy_reality_connection> connection_;
    std::shared_ptr<router> router_;
    uint64_t last_activity_time_ms_{0};
    std::unordered_map<std::string, std::shared_ptr<udp_proxy_outbound>> proxy_outbounds_;
    lru_cache<std::string, endpoint_cache_entry> resolved_targets_;
    lru_cache<boost::asio::ip::udp::endpoint, peer_cache_entry, net::udp_endpoint_hash, net::udp_endpoint_equal> allowed_reply_peers_;
    std::atomic<bool> stopping_{false};
};

}    // namespace relay

#endif
