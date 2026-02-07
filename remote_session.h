#ifndef REMOTE_SESSION_H
#define REMOTE_SESSION_H

#include <memory>
#include <vector>
#include <cstdint>
#include <asio.hpp>

#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class remote_session : public mux_stream_interface, public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_connection> connection, std::uint32_t id, const asio::any_io_executor& ex, const connection_context& ctx);

    [[nodiscard]] asio::awaitable<void> start(const syn_payload& syn);

    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;
    void set_manager(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& m) { manager_ = m; }

   private:
    [[nodiscard]] asio::awaitable<void> upstream();
    [[nodiscard]] asio::awaitable<void> downstream();

   private:
    std::uint32_t id_;
    connection_context ctx_;
    asio::ip::tcp::resolver resolver_;
    asio::ip::tcp::socket target_socket_;
    std::shared_ptr<mux_connection> connection_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager_;
};

}    // namespace mux

#endif
