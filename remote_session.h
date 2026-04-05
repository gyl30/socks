#ifndef REMOTE_SESSION_H
#define REMOTE_SESSION_H

#include <cstdint>
#include <chrono>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "mux_protocol.h"
#include "mux_stream.h"
#include "mux_connection.h"
#include "config.h"
namespace mux
{

class remote_tcp_session : public std::enable_shared_from_this<remote_tcp_session>
{
   public:
    remote_tcp_session(boost::asio::io_context& io_context,
                       const std::shared_ptr<mux_connection>& connection,
                       uint32_t id,
                       uint32_t conn_id,
                       uint64_t trace_id,
                       const config& cfg);

    [[nodiscard]] bool has_stream() const;
    [[nodiscard]] boost::asio::awaitable<void> start(const syn_payload& syn);

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const syn_payload& syn);
    void initialize_target(const syn_payload& syn);
    void log_connecting() const;
    [[nodiscard]] boost::asio::awaitable<bool> resolve_target(boost::asio::ip::tcp::resolver& resolver,
                                                              boost::asio::ip::tcp::resolver::results_type& resolve_res);
    [[nodiscard]] boost::asio::awaitable<bool> connect_target(const boost::asio::ip::tcp::resolver::results_type& resolve_res);
    [[nodiscard]] boost::asio::awaitable<bool> send_success_ack();
    [[nodiscard]] boost::asio::awaitable<void> relay_target();
    [[nodiscard]] boost::asio::awaitable<void> upstream();
    [[nodiscard]] boost::asio::awaitable<void> downstream();
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    void close_from_fin();
    void close_from_reset();
    void log_close_summary() const;

   private:
    uint32_t id_;
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    const config& cfg_;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    std::shared_ptr<mux_stream> stream_;
    std::weak_ptr<mux_connection> connection_;
    uint64_t last_activity_time_ms_{0};
};

}    // namespace mux

#endif
