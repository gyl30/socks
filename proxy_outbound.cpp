#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "outbound.h"
#include "outbound_factory.h"

namespace relay
{

namespace
{

class proxy_outbound final : public outbound_handler
{
   public:
    proxy_outbound(std::string tag, std::string type) : outbound_handler(std::move(tag), std::move(type)) {}

    [[nodiscard]] std::shared_ptr<tcp_outbound_stream> create_tcp_outbound(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const override
    {
        return make_proxy_tcp_outbound_stream(executor, conn_id, trace_id, cfg, tag());
    }

    [[nodiscard]] boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_outbound(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const override
    {
        co_return co_await udp_proxy_outbound::connect(executor, conn_id, trace_id, cfg, tag());
    }
};

}    // namespace

std::shared_ptr<outbound_handler> make_proxy_outbound_handler(const std::string& outbound_tag, const std::string& outbound_type)
{
    return std::make_shared<proxy_outbound>(outbound_tag, outbound_type);
}

}    // namespace relay
