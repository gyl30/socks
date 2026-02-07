#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/any_io_executor.hpp>

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
    explicit direct_upstream(const asio::any_io_executor& ex, connection_context ctx) : socket_(ex), resolver_(ex), ctx_(std::move(ctx)) {}

    asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override;

    asio::awaitable<std::pair<std::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override;

    asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override;

    asio::awaitable<void> close() override;

   private:
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
    connection_context ctx_;
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
    connection_context ctx_;
    std::shared_ptr<mux_stream> stream_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_;
};

}    // namespace mux

#endif
