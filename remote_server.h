#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <array>
#include <atomic>
#include <memory>
#include <vector>
#include <optional>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "context_pool.h"
#include "mux_connection.h"
#include "mux_protocol.h"
#include "replay_cache.h"
#include "site_material.h"
#include "reality/handshake/server_handshake_context.h"
#include "reality/policy/fallback_gate.h"
#include "reality/policy/fallback_executor.h"

namespace mux
{

class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    remote_server(io_context_pool& pool, const config& cfg);
    virtual ~remote_server();

   public:
    void start();
    void stop();

   private:
    boost::asio::awaitable<void> accept_loop();
    boost::asio::awaitable<void> fallback_to_target_site(reality::fallback_request&& request, const char* reason);
    boost::asio::awaitable<void> handle(io_worker& worker, std::shared_ptr<boost::asio::ip::tcp::socket> s, uint32_t conn_id);

    boost::asio::awaitable<void> process_stream_request(io_worker& worker,
                                                        std::shared_ptr<mux_connection> connection,
                                                        const reality::server_handshake_context& reality_ctx,
                                                        mux_frame frame) const;

   private:
    const config& cfg_;
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
    reality::fallback_gate fallback_gate_;
    reality::fallback_executor fallback_executor_;
    std::atomic<bool> stopping_{false};
};

}    // namespace mux

#endif
