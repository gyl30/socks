#include <memory>
#include <vector>
#include <thread>
#include <cstdint>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_type.hpp>

#include "log.h"
#include "constants.h"
#include "app_runtime.h"

namespace relay
{

namespace
{

[[nodiscard]] uint32_t resolve_worker_threads(const config& cfg)
{
    if (cfg.workers > 0)
    {
        return cfg.workers;
    }

    const auto threads_count = std::thread::hardware_concurrency();
    if (threads_count > 0)
    {
        return threads_count;
    }
    return 4;
}

}    // namespace

app_runtime::app_runtime(const config& cfg) : cfg_(cfg), pool_(resolve_worker_threads(cfg_)) {}

void app_runtime::start()
{
    for (const auto& inbound : cfg_.inbounds)
    {
        start_inbound(inbound);
    }
}

void app_runtime::start_inbound(const config::inbound_entry_t& inbound)
{
    if (inbound.type == "reality" && inbound.reality.has_value())
    {
        auto server = std::make_shared<reality_inbound>(pool_, cfg_, inbound.tag, *inbound.reality);
        reality_inbounds_.push_back(server);
        server->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }

    if (inbound.type == "socks" && inbound.socks.has_value())
    {
        auto client = std::make_shared<socks_inbound>(pool_, cfg_, inbound.tag, *inbound.socks);
        socks_inbounds_.push_back(client);
        client->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }

#if SOCKS_HAS_TPROXY
    if (inbound.type == "tproxy" && inbound.tproxy.has_value())
    {
        auto client = std::make_shared<tproxy_inbound>(pool_, cfg_, inbound.tag, *inbound.tproxy);
        tproxy_inbounds_.push_back(client);
        client->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }
#endif

#if SOCKS_HAS_TUN
    if (inbound.type == "tun" && inbound.tun.has_value())
    {
        auto client = std::make_shared<tun_inbound>(pool_, cfg_, inbound.tag, *inbound.tun);
        tun_inbounds_.push_back(client);
        client->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }
#endif

    LOG_ERROR("{} inbound_tag {} inbound_type {} stage start unsupported inbound settings missing",
              log_event::kConnInit,
              inbound.tag,
              inbound.type);
    std::exit(EXIT_FAILURE);
}

void app_runtime::stop()
{
    for (const auto& client : socks_inbounds_)
    {
        if (client != nullptr)
        {
            client->stop();
        }
    }
#if SOCKS_HAS_TPROXY
    for (const auto& client : tproxy_inbounds_)
    {
        if (client != nullptr)
        {
            client->stop();
        }
    }
#endif
#if SOCKS_HAS_TUN
    for (const auto& client : tun_inbounds_)
    {
        if (client != nullptr)
        {
            client->stop();
        }
    }
#endif
    for (const auto& server : reality_inbounds_)
    {
        if (server != nullptr)
        {
            server->stop();
        }
    }

    pool_.emit_all(boost::asio::cancellation_type::all);
}

boost::asio::awaitable<void> app_runtime::async_wait_stopped()
{
    co_await pool_.async_wait_all();
    pool_.shutdown();
}

}    // namespace relay
