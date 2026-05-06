#ifndef PROXY_STREAM_RELAY_TRANSPORT_H
#define PROXY_STREAM_RELAY_TRANSPORT_H

#include <memory>
#include <span>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "stream_relay_transport.h"

namespace relay
{

class proxy_connection_tcp_stream
{
   public:
    explicit proxy_connection_tcp_stream(std::shared_ptr<proxy_reality_connection> connection = nullptr);

    void reset(std::shared_ptr<proxy_reality_connection> connection = nullptr);
    [[nodiscard]] bool has_connection() const { return connection_ != nullptr; }
    [[nodiscard]] std::shared_ptr<proxy_reality_connection> connection() const { return connection_; }
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(
        std::span<uint8_t> buffer, uint32_t read_timeout, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec);
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);
    boost::asio::awaitable<void> close();

   private:
    std::shared_ptr<proxy_reality_connection> connection_;
    std::vector<uint8_t> pending_read_data_;
    std::size_t pending_read_offset_ = 0;
    relay::proxy::tcp_stream_recv_state recv_state_;
    relay::proxy::tcp_stream_send_state send_state_;
};

class proxy_connection_stream_relay_transport final : public stream_relay_transport
{
   public:
    proxy_connection_stream_relay_transport(std::shared_ptr<proxy_reality_connection> connection, const config::timeout_t& timeout);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<uint8_t> buffer, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> close() override;

   private:
    proxy_connection_tcp_stream stream_;
    const config::timeout_t& timeout_;
};

}    // namespace relay

#endif
