#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <system_error>

#include <asio.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"

namespace mux
{

class upstream
{
   public:
    virtual ~upstream() = default;

    [[nodiscard]] virtual asio::awaitable<bool> connect(const std::string& host, uint16_t port) = 0;

    [[nodiscard]] virtual asio::awaitable<std::pair<std::error_code, size_t>> read(std::vector<uint8_t>& buf) = 0;

    [[nodiscard]] virtual asio::awaitable<size_t> write(const std::vector<uint8_t>& data) = 0;

    virtual asio::awaitable<void> close() = 0;
};

class direct_upstream : public upstream
{
   public:
    explicit direct_upstream(const asio::any_io_executor& ex, connection_context ctx) : socket_(ex), resolver_(ex), ctx_(std::move(ctx)) {}

    asio::awaitable<bool> connect(const std::string& host, uint16_t port) override;

    asio::awaitable<std::pair<std::error_code, size_t>> read(std::vector<uint8_t>& buf) override;

    asio::awaitable<size_t> write(const std::vector<uint8_t>& data) override;

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

    asio::awaitable<bool> connect(const std::string& host, uint16_t port) override;

    asio::awaitable<std::pair<std::error_code, size_t>> read(std::vector<uint8_t>& buf) override;

    asio::awaitable<size_t> write(const std::vector<uint8_t>& data) override;

    asio::awaitable<void> close() override;

   private:
    connection_context ctx_;
    std::shared_ptr<mux_stream> stream_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_;
};

}    // namespace mux

#endif
