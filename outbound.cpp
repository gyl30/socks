#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>

#include "config.h"
#include "config_type_facts.h"
#include "outbound.h"
#include "protocol.h"

namespace relay
{

config_type::outbound_class resolve_outbound_class(const config& cfg, const std::string_view outbound_tag)
{
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr)
    {
        return config_type::outbound_class::kUnsupported;
    }
    return config_type::classify_outbound_type(outbound->type);
}

std::shared_ptr<tcp_outbound_stream> create_tcp_outbound_for_tag(const boost::asio::any_io_executor& executor,
                                                                 const uint32_t conn_id,
                                                                 const uint64_t trace_id,
                                                                 const config& cfg,
                                                                 const std::string& outbound_tag,
                                                                 const uint32_t connect_mark)
{
    const auto outbound_class = resolve_outbound_class(cfg, outbound_tag);
    if (outbound_class == config_type::outbound_class::kDirect)
    {
        return make_direct_tcp_outbound_stream(executor, conn_id, trace_id, cfg, connect_mark);
    }
    if (outbound_class == config_type::outbound_class::kProxy)
    {
        return make_proxy_tcp_outbound_stream(executor, conn_id, trace_id, cfg, outbound_tag, connect_mark);
    }
    return nullptr;
}

boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_proxy_outbound(const boost::asio::any_io_executor& executor,
                                                                                      uint32_t conn_id,
                                                                                      uint64_t trace_id,
                                                                                      const config& cfg,
                                                                                      const std::string& outbound_tag,
                                                                                      const uint32_t connect_mark)
{
    const auto outbound_class = resolve_outbound_class(cfg, outbound_tag);
    if (outbound_class == config_type::outbound_class::kBlock)
    {
        udp_proxy_outbound_connect_result result;
        result.ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    if (outbound_class != config_type::outbound_class::kProxy)
    {
        udp_proxy_outbound_connect_result result;
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    co_return co_await udp_proxy_outbound::connect(executor, conn_id, trace_id, cfg, outbound_tag, connect_mark);
}

}    // namespace relay
