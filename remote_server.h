#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <array>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <utility>

#include <openssl/types.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include "config.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "replay_cache.h"
#include "mux_connection.h"
#include "reality/policy/fallback_executor.h"
#include "reality/policy/fallback_gate.h"
#include "reality/material/material_provider.h"

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
    boost::asio::awaitable<void> wait_stopped();

   private:
    boost::asio::awaitable<void> accept_loop();
    boost::asio::awaitable<void> fallback_to_target_site(reality::fallback_request request, const char* reason);
    boost::asio::awaitable<void> handle(boost::asio::io_context& io, std::shared_ptr<boost::asio::ip::tcp::socket> s, std::uint32_t conn_id);

    boost::asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl> tunnel,
                                                        const connection_context& ctx,
                                                        mux_frame frame);

   private:
    const config& cfg_;
    io_context_pool& pool_;
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_{io_context_};
    std::vector<std::uint8_t> private_key_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::array<std::uint8_t, 32> reality_cert_private_key_{};
    std::vector<std::uint8_t> reality_cert_public_key_;
    std::vector<std::uint8_t> reality_cert_template_;
    std::uint32_t next_conn_id_{1};
    replay_cache replay_cache_;
    reality::material_provider material_provider_;
    reality::fallback_gate fallback_gate_;
    reality::fallback_executor fallback_executor_;
    std::atomic<bool> stopping_{false};
};

}    // namespace mux

#endif
