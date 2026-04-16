#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>

#include "config.h"
#include "outbound.h"
#include "outbound_factory.h"
#include "protocol.h"

namespace relay
{

namespace
{

class direct_outbound final : public outbound_handler
{
   public:
    explicit direct_outbound(std::string tag) : outbound_handler(std::move(tag), "direct") {}

    [[nodiscard]] std::shared_ptr<tcp_outbound_stream> create_tcp_outbound(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const override
    {
        return make_direct_tcp_outbound_stream(executor, conn_id, trace_id, cfg);
    }

    [[nodiscard]] boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_outbound(
        const boost::asio::any_io_executor&, uint32_t, uint64_t, const config&) const override
    {
        udp_proxy_outbound_connect_result result;
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
};

}    // namespace

std::shared_ptr<outbound_handler> make_direct_outbound_handler(const std::string& outbound_tag)
{
    return std::make_shared<direct_outbound>(outbound_tag);
}

}    // namespace relay
