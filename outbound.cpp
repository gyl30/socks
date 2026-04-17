#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>

#include "config.h"
#include "config_type_facts.h"
#include "outbound.h"
#include "outbound_factory.h"
#include "protocol.h"

namespace relay
{

outbound_handler::outbound_handler(std::string tag, std::string type) : tag_(std::move(tag)), type_(std::move(type)) {}

std::shared_ptr<outbound_handler> make_outbound_handler(const config& cfg, const std::string& outbound_tag)
{
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr)
    {
        return nullptr;
    }
    const auto outbound_class = config_type::classify_outbound_type(outbound->type);
    if (outbound_class == config_type::outbound_class::kDirect)
    {
        return make_direct_outbound_handler(outbound_tag);
    }
    if (outbound_class == config_type::outbound_class::kBlock)
    {
        return make_block_outbound_handler(outbound_tag);
    }
    if (outbound_class == config_type::outbound_class::kProxy)
    {
        return make_proxy_outbound_handler(outbound_tag, outbound->type);
    }
    return nullptr;
}

boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_proxy_outbound(const boost::asio::any_io_executor& executor,
                                                                             uint32_t conn_id,
                                                                             uint64_t trace_id,
                                                                             const config& cfg,
                                                                             const std::string& outbound_tag)
{
    const auto handler = make_outbound_handler(cfg, outbound_tag);
    if (handler == nullptr)
    {
        udp_proxy_outbound_connect_result result;
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    co_return co_await handler->connect_udp_outbound(executor, conn_id, trace_id, cfg);
}

}    // namespace relay
