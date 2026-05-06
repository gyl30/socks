#ifndef TCP_OUTBOUND_STREAM_H
#define TCP_OUTBOUND_STREAM_H

#include <span>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "stream_relay_transport.h"

namespace relay
{

struct tcp_outbound_connect_result
{
    boost::system::error_code ec;
    boost::asio::ip::address bind_addr;
    uint16_t bind_port = 0;
    boost::asio::ip::address resolved_target_addr;
    uint16_t resolved_target_port = 0;
    uint8_t socks_rep = 0;
    bool has_bind_endpoint = false;
    bool has_resolved_target_endpoint = false;
    bool vision_accepted = false;
};

class tcp_outbound_stream : public stream_relay_transport
{
   public:
    virtual ~tcp_outbound_stream() = default;

   public:
    [[nodiscard]] virtual boost::asio::awaitable<tcp_outbound_connect_result> connect(const std::string& host, uint16_t port) = 0;
    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) = 0;
};

[[nodiscard]] std::shared_ptr<tcp_outbound_stream> make_direct_tcp_outbound_stream(const boost::asio::any_io_executor& executor,
                                                                                    uint32_t conn_id,
                                                                                    uint64_t trace_id,
                                                                                    const config& cfg,
                                                                                    uint32_t connect_mark);
[[nodiscard]] std::shared_ptr<tcp_outbound_stream> make_proxy_tcp_outbound_stream(const boost::asio::any_io_executor& executor,
                                                                                   uint32_t conn_id,
                                                                                   uint64_t trace_id,
                                                                                   const config& cfg,
                                                                                   const std::string& outbound_tag,
                                                                                   uint32_t connect_mark);

}    // namespace relay

#endif
