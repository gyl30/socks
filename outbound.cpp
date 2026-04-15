#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>

#include "config.h"
#include "outbound.h"
#include "protocol.h"

namespace relay
{

namespace
{

class direct_outbound final : public outbound_handler
{
   public:
    explicit direct_outbound(std::string tag) : outbound_handler(std::move(tag), "direct") {}

    [[nodiscard]] std::shared_ptr<tcp_outbound_stream> create_tcp_upstream(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const override
    {
        return make_direct_tcp_outbound_stream(executor, conn_id, trace_id, cfg);
    }

    [[nodiscard]] boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_upstream(
        const boost::asio::any_io_executor&, uint32_t, uint64_t, const config&) const override
    {
        udp_proxy_outbound_connect_result result;
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
};

class block_outbound final : public outbound_handler
{
   public:
    explicit block_outbound(std::string tag) : outbound_handler(std::move(tag), "block") {}

    [[nodiscard]] std::shared_ptr<tcp_outbound_stream> create_tcp_upstream(
        const boost::asio::any_io_executor&, uint32_t, uint64_t, const config&) const override
    {
        return nullptr;
    }

    [[nodiscard]] boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_upstream(
        const boost::asio::any_io_executor&, uint32_t, uint64_t, const config&) const override
    {
        udp_proxy_outbound_connect_result result;
        result.ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
};

class proxy_outbound final : public outbound_handler
{
   public:
    proxy_outbound(std::string tag, std::string type) : outbound_handler(std::move(tag), std::move(type)) {}

    [[nodiscard]] std::shared_ptr<tcp_outbound_stream> create_tcp_upstream(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const override
    {
        return make_proxy_tcp_outbound_stream(executor, conn_id, trace_id, cfg, tag());
    }

    [[nodiscard]] boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_upstream(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const override
    {
        co_return co_await udp_proxy_outbound::connect(executor, conn_id, trace_id, cfg, tag());
    }
};

}    // namespace

outbound_handler::outbound_handler(std::string tag, std::string type) : tag_(std::move(tag)), type_(std::move(type)) {}

std::shared_ptr<outbound_handler> make_outbound_handler(const config& cfg, const std::string& outbound_tag)
{
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr)
    {
        return nullptr;
    }
    if (outbound->type == "direct")
    {
        return std::make_shared<direct_outbound>(outbound_tag);
    }
    if (outbound->type == "block")
    {
        return std::make_shared<block_outbound>(outbound_tag);
    }
    if (outbound->type == "reality" || outbound->type == "socks")
    {
        return std::make_shared<proxy_outbound>(outbound_tag, outbound->type);
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
    co_return co_await handler->connect_udp_upstream(executor, conn_id, trace_id, cfg);
}

}    // namespace relay
