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
    auto runtime_cfg = std::make_shared<config>(make_runtime_config(cfg_, inbound));
    runtime_configs_.push_back(runtime_cfg);

    LOG_INFO("{} inbound_tag {} inbound_type {} stage start create_runtime_config",
             log_event::kConnInit,
             inbound.tag,
             inbound.type);

    if (inbound.type == "reality")
    {
        auto server = std::make_shared<remote_server>(pool_, *runtime_cfg);
        reality_inbounds_.push_back(server);
        server->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }

    if (inbound.type == "socks")
    {
        auto client = std::make_shared<socks_inbound>(pool_, *runtime_cfg);
        socks_inbounds_.push_back(client);
        client->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }

#if SOCKS_HAS_TPROXY
    if (inbound.type == "tproxy")
    {
        auto client = std::make_shared<tproxy_inbound>(pool_, *runtime_cfg);
        tproxy_inbounds_.push_back(client);
        client->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
        return;
    }
#endif

#if SOCKS_HAS_TUN
    if (inbound.type == "tun")
    {
        auto client = std::make_shared<tun_inbound>(pool_, *runtime_cfg);
        tun_inbounds_.push_back(client);
        client->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound.tag, inbound.type);
    }
#endif
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
