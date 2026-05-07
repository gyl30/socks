#ifndef UDP_PROXY_OUTBOUND_H
#define UDP_PROXY_OUTBOUND_H

#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "proxy_protocol.h"

namespace relay
{

struct udp_proxy_outbound_connect_result
{
    boost::system::error_code ec;
    uint8_t socks_rep = 0;
    boost::asio::ip::address bind_addr;
    uint16_t bind_port = 0;
    bool has_bind_endpoint = false;
    std::shared_ptr<class udp_proxy_outbound> outbound = nullptr;
};

class udp_proxy_outbound
{
   public:
    virtual ~udp_proxy_outbound() = default;

    [[nodiscard]] static boost::asio::awaitable<udp_proxy_outbound_connect_result> connect(const boost::asio::any_io_executor& executor,
                                                                                           uint32_t conn_id,
                                                                                           uint64_t trace_id,
                                                                                           const config& cfg,
                                                                                           const config::outbound_entry_t& outbound,
                                                                                           uint32_t connect_mark,
                                                                                           uint32_t timeout_sec);

    [[nodiscard]] static boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_reality_outbound(
        const boost::asio::any_io_executor& executor,
        uint32_t conn_id,
        uint64_t trace_id,
        const config& cfg,
        const config::outbound_entry_t& outbound,
        uint32_t connect_mark,
        uint32_t timeout_sec);
    [[nodiscard]] static boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_socks_outbound(
        const boost::asio::any_io_executor& executor,
        uint32_t conn_id,
        uint64_t trace_id,
        const config& cfg,
        const config::outbound_entry_t& outbound,
        uint32_t connect_mark,
        uint32_t timeout_sec);

    virtual boost::asio::awaitable<void> close() = 0;
    virtual boost::asio::awaitable<void> send_datagram(
        const std::string& host, uint16_t port, const uint8_t* payload, std::size_t payload_len, boost::system::error_code& ec) = 0;
    [[nodiscard]] virtual boost::asio::awaitable<proxy::udp_datagram> receive_datagram(uint32_t timeout_sec,
                                                                                        boost::system::error_code& ec) = 0;

    [[nodiscard]] std::string_view bind_host() const { return bind_host_; }
    [[nodiscard]] uint16_t bind_port() const { return bind_port_; }

   protected:
    explicit udp_proxy_outbound(const config& cfg) : cfg_(cfg) {}
    [[nodiscard]] const config& cfg() const { return cfg_; }
    void set_bind_endpoint(std::string host, uint16_t port);

   private:
    const config& cfg_;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
};

}    // namespace relay

#endif
