#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <expected>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "mux_stream.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "protocol.h"

namespace mux
{

class upstream
{
   public:
    virtual ~upstream() = default;

    [[nodiscard]] virtual boost::asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) = 0;
    [[nodiscard]] virtual std::uint8_t connect_failure_reply() const = 0;

    [[nodiscard]] virtual boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) = 0;

    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) = 0;

    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> write(const std::uint8_t* data, const std::size_t len)
    {
        if (data == nullptr || len == 0)
        {
            co_return 0;
        }
        const std::vector<std::uint8_t> payload(data, data + len);
        co_return co_await write(payload);
    }

    virtual boost::asio::awaitable<void> shutdown_send() = 0;
    virtual boost::asio::awaitable<void> close() = 0;
};

class direct_upstream : public upstream
{
   public:
    explicit direct_upstream(boost::asio::io_context& io_context,
                             connection_context ctx,
                             const std::uint32_t mark = 0,
                             const std::uint32_t timeout_sec = 10)
        : socket_(io_context), resolver_(io_context), ctx_(std::move(ctx)), mark_(mark), timeout_sec_(timeout_sec)
    {
    }

    boost::asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override;
    std::uint8_t connect_failure_reply() const override;

    boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override;

    boost::asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override;
    boost::asio::awaitable<std::size_t> write(const std::uint8_t* data, std::size_t len) override;

    boost::asio::awaitable<void> shutdown_send() override;
    boost::asio::awaitable<void> close() override;

   private:
    std::expected<void, boost::system::error_code> open_socket_for_endpoint(const boost::asio::ip::tcp::endpoint& endpoint);
    void apply_socket_mark();
    void apply_no_delay();

   private:
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
    connection_context ctx_;
    std::uint32_t mark_ = 0;
    std::uint32_t timeout_sec_ = 10;
    std::uint8_t last_connect_reply_ = socks::kRepHostUnreach;
};

class proxy_upstream : public upstream
{
   public:
    explicit proxy_upstream(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel, connection_context ctx);

    boost::asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override;
    std::uint8_t connect_failure_reply() const override;

    boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override;

    boost::asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override;
    boost::asio::awaitable<std::size_t> write(const std::uint8_t* data, std::size_t len) override;

    boost::asio::awaitable<void> shutdown_send() override;
    boost::asio::awaitable<void> close() override;

   private:
    [[nodiscard]] bool is_tunnel_ready() const;
    boost::asio::awaitable<bool> send_syn_request(const std::shared_ptr<mux_stream>& stream, const std::string& host, std::uint16_t port);
    boost::asio::awaitable<bool> wait_connect_ack(const std::shared_ptr<mux_stream>& stream, const std::string& host, std::uint16_t port);
    boost::asio::awaitable<void> cleanup_stream(const std::shared_ptr<mux_stream>& stream);

   private:
    connection_context ctx_;
    std::shared_ptr<mux_stream> stream_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_;
    std::uint8_t last_connect_reply_ = socks::kRepHostUnreach;
};

}    // namespace mux

#endif
