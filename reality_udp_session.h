#ifndef REALITY_UDP_SESSION_H
#define REALITY_UDP_SESSION_H

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
#include "router.h"
#include "proxy_protocol.h"
#include "udp_proxy_outbound.h"
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
                        const config& cfg);

    boost::asio::awaitable<void> start(const proxy::udp_associate_request& request);

   private:
    boost::asio::awaitable<void> start_impl(const proxy::udp_associate_request& request);
    boost::asio::awaitable<void> connection_to_udp();
    boost::asio::awaitable<void> udp_to_connection();
    boost::asio::awaitable<void> proxy_to_connection(const std::string& outbound_tag, const std::shared_ptr<udp_proxy_outbound>& upstream);
    boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<route_decision> decide_route(const proxy::udp_datagram& datagram) const;
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> get_proxy_outbound(const std::string& outbound_tag);
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
