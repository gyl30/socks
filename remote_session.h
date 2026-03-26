#ifndef REMOTE_SESSION_H
#define REMOTE_SESSION_H

#include <memory>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "mux_stream.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "connection_context.h"

namespace mux
{


class remote_tcp_session : public std::enable_shared_from_this<remote_tcp_session>
{
   public:
    remote_tcp_session(boost::asio::io_context& io_context,
                       const std::shared_ptr<mux_connection>& connection,
                       std::uint32_t id,
                       const connection_context& ctx,
                       const config& cfg);

    [[nodiscard]] boost::asio::awaitable<void> start(const syn_payload& syn);

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const syn_payload& syn);
    [[nodiscard]] boost::asio::awaitable<void> upstream();
    [[nodiscard]] boost::asio::awaitable<void> downstream();
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    void close_from_fin();
    void close_from_reset();

   private:
    std::uint32_t id_;
    const config& cfg_;
    connection_context ctx_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    std::shared_ptr<mux_stream> stream_;
    std::weak_ptr<mux_connection> connection_;
    std::uint64_t last_activity_time_ms_{0};
};

}    // namespace mux

#endif
