#ifndef PROXY_UDP_UPSTREAM_H
#define PROXY_UDP_UPSTREAM_H

#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"

namespace relay
{

struct proxy_udp_connect_result
{
    boost::system::error_code ec;
    uint8_t socks_rep = 0;
    boost::asio::ip::address bind_addr;
    uint16_t bind_port = 0;
    bool has_bind_endpoint = false;
    std::shared_ptr<class proxy_udp_upstream> upstream = nullptr;
};

class proxy_udp_upstream : public std::enable_shared_from_this<proxy_udp_upstream>
{
   public:
    proxy_udp_upstream(std::shared_ptr<proxy_reality_connection> connection, const config& cfg);
    proxy_udp_upstream(std::shared_ptr<boost::asio::ip::tcp::socket> control_socket,
                       std::shared_ptr<boost::asio::ip::udp::socket> udp_socket,
                       boost::asio::ip::udp::endpoint udp_server_endpoint,
                       const config& cfg);

    [[nodiscard]] static boost::asio::awaitable<proxy_udp_connect_result> connect(const boost::asio::any_io_executor& executor,
                                                                                  uint32_t conn_id,
                                                                                  uint64_t trace_id,
                                                                                  const config& cfg,
                                                                                  const std::string& outbound_tag);

    boost::asio::awaitable<void> close();
    boost::asio::awaitable<void> send_datagram(
        const std::string& host, uint16_t port, const uint8_t* payload, std::size_t payload_len, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<proxy::udp_datagram> receive_datagram(uint32_t timeout_sec, boost::system::error_code& ec);

    [[nodiscard]] std::string_view bind_host() const { return bind_host_; }
    [[nodiscard]] uint16_t bind_port() const { return bind_port_; }

   private:
    enum class upstream_mode : uint8_t
    {
        kReality,
        kSocks,
    };

    [[nodiscard]] uint32_t associate_reply_timeout() const;

   private:
    const config& cfg_;
    upstream_mode mode_ = upstream_mode::kReality;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    std::shared_ptr<proxy_reality_connection> connection_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socks_control_socket_;
    std::shared_ptr<boost::asio::ip::udp::socket> socks_udp_socket_;
    boost::asio::ip::udp::endpoint socks_udp_server_endpoint_;
};

}    // namespace relay

#endif
