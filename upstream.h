#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <expected>
#include <utility>
#include <system_error>

#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>

#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class upstream
{
   public:
    virtual ~upstream() = default;

    [[nodiscard]] virtual asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) = 0;

    [[nodiscard]] virtual asio::awaitable<std::pair<std::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) = 0;

    [[nodiscard]] virtual asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) = 0;

    virtual asio::awaitable<void> close() = 0;
};

class direct_upstream : public upstream
{
   public:
    explicit direct_upstream(asio::io_context& io_context,
                             connection_context ctx,
                             const std::uint32_t mark = 0,
                             const std::uint32_t timeout_sec = 10)
        : socket_(io_context), resolver_(io_context), ctx_(std::move(ctx)), mark_(mark), timeout_sec_(timeout_sec)
    {
    }

    asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override;

    asio::awaitable<std::pair<std::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override;

    asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override;

    asio::awaitable<void> close() override;

   private:
    std::expected<void, std::error_code> open_socket_for_endpoint(const asio::ip::tcp::endpoint& endpoint);
    void apply_socket_mark();
    void apply_no_delay();

   private:
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
    connection_context ctx_;
    std::uint32_t mark_ = 0;
    std::uint32_t timeout_sec_ = 10;
};

class proxy_upstream : public upstream
{
   public:
    explicit proxy_upstream(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel, connection_context ctx);

    asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override;

    asio::awaitable<std::pair<std::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override;

    asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override;

    asio::awaitable<void> close() override;

  private:
    [[nodiscard]] bool is_tunnel_ready() const;
    asio::awaitable<bool> send_syn_request(const std::shared_ptr<mux_stream>& stream, const std::string& host, std::uint16_t port);
    asio::awaitable<bool> wait_connect_ack(const std::shared_ptr<mux_stream>& stream);
    asio::awaitable<void> cleanup_stream(const std::shared_ptr<mux_stream>& stream);

   private:
    connection_context ctx_;
    std::shared_ptr<mux_stream> stream_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_;
};

}    // namespace mux

#endif
