#ifndef REALITY_INBOUND_H
#define REALITY_INBOUND_H

#include <array>
#include <atomic>
#include <memory>
#include <vector>
#include <optional>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "context_pool.h"
#include "replay_cache.h"
#include "site_material.h"
#include "router.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "reality/policy/fallback_gate.h"
#include "reality/policy/fallback_executor.h"
#include "reality/handshake/server_handshake_context.h"

namespace relay
{

class reality_inbound : public std::enable_shared_from_this<reality_inbound>
{
   public:
    reality_inbound(io_context_pool& pool, const config& cfg, std::string inbound_tag, const config::reality_inbound_t& settings);
    virtual ~reality_inbound();

   public:
    void start();
    void stop();

   private:
    boost::asio::awaitable<void> accept_loop();
    boost::asio::awaitable<void> fallback_to_target_site(reality::fallback_request&& request, const char* reason);
    boost::asio::awaitable<void> handle(io_worker& worker, std::shared_ptr<boost::asio::ip::tcp::socket> s, uint32_t conn_id);
    boost::asio::awaitable<void> process_proxy_request(io_worker& worker,
                                                       std::shared_ptr<proxy_reality_connection> connection,
                                                       const reality::server_handshake_context& reality_ctx) const;

   private:
    const config& cfg_;
    std::string inbound_tag_;
    config::reality_inbound_t settings_;
    io_context_pool& pool_;
    io_worker& owner_worker_;
    boost::asio::ip::tcp::acceptor acceptor_{owner_worker_.io_context};
    std::vector<uint8_t> private_key_;
    std::vector<uint8_t> short_id_bytes_;
    std::array<uint8_t, 32> reality_cert_private_key_{};
    std::vector<uint8_t> reality_cert_public_key_;
    std::vector<uint8_t> reality_cert_template_;
    uint32_t next_conn_id_{1};
    replay_cache replay_cache_;
    std::optional<reality::site_material> site_material_;
    std::shared_ptr<router> router_;
    reality::fallback_gate fallback_gate_;
    reality::fallback_executor fallback_executor_;
    std::atomic<bool> stopping_{false};
};

}    // namespace relay

#endif
