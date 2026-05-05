#ifndef STREAM_RELAY_TRANSPORT_H
#define STREAM_RELAY_TRANSPORT_H

#include <span>
#include <memory>
#include <vector>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"

namespace relay
{

class stream_relay_transport
{
   public:
    virtual ~stream_relay_transport() = default;

    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buffer, boost::system::error_code& ec) = 0;
    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) = 0;
    virtual boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) = 0;
    virtual boost::asio::awaitable<void> close() = 0;
};

class tcp_socket_stream_relay_transport final : public stream_relay_transport
{
   public:
    tcp_socket_stream_relay_transport(boost::asio::ip::tcp::socket& socket, const config::timeout_t& timeout);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buffer, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> close() override;

   private:
    boost::asio::ip::tcp::socket& socket_;
    const config::timeout_t& timeout_;
};

class proxy_connection_stream_relay_transport final : public stream_relay_transport
{
   public:
    proxy_connection_stream_relay_transport(std::shared_ptr<proxy_reality_connection> connection, const config::timeout_t& timeout);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buffer, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> close() override;

   private:
    std::shared_ptr<proxy_reality_connection> connection_;
    const config::timeout_t& timeout_;
    std::vector<uint8_t> pending_read_data_;
    std::size_t pending_read_offset_ = 0;
    relay::proxy::tcp_stream_recv_state recv_state_;
    relay::proxy::tcp_stream_send_state send_state_;
};

}    // namespace relay

#endif
