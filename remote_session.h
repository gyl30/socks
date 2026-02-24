#ifndef REMOTE_SESSION_H
#define REMOTE_SESSION_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "mux_stream_interface.h"

namespace mux
{

class remote_session : public mux_stream_interface, public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(const std::shared_ptr<mux_connection>& connection,
                   std::uint32_t id,
                   boost::asio::io_context& io_context,
                   const connection_context& ctx,
                   std::uint32_t connect_timeout_sec = 10);

    [[nodiscard]] boost::asio::awaitable<void> start(const syn_payload& syn);

    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;
    void set_manager(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& m) { manager_ = m; }

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const syn_payload& syn);
    [[nodiscard]] boost::asio::awaitable<void> upstream();
    [[nodiscard]] boost::asio::awaitable<void> downstream();
    void close_from_fin();
    void close_from_reset();

   private:
    std::uint32_t id_;
    connection_context ctx_;
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket target_socket_;
    std::weak_ptr<mux_connection> connection_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager_;
    std::atomic<bool> reset_requested_{false};
    std::atomic<bool> fin_requested_{false};
    std::uint32_t connect_timeout_sec_ = 10;
};

}    // namespace mux

#endif
