#include <cstdint>
#include <cstdlib>
#include <memory>
#include <thread>
#include <utility>
#include <vector>
#include <exception>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_type.hpp>

#include "log.h"
#include "constants.h"
#include "app_runtime.h"
#include "config_type_facts.h"

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

template <typename TInbound, typename TSettings>
void start_inbound_instance(io_context_pool& pool,
                            const config& cfg,
                            const std::string& inbound_tag,
                            const std::string& inbound_type,
                            const TSettings& settings,
                            std::vector<std::shared_ptr<TInbound>>& inbounds)
{
    try
    {
        auto inbound_instance = std::make_shared<TInbound>(pool, cfg, inbound_tag, settings);
        inbounds.push_back(inbound_instance);
        inbound_instance->start();
        LOG_INFO("{} inbound_tag {} inbound_type {} stage start started", log_event::kConnInit, inbound_tag, inbound_type);
    }
    catch (const std::exception& ex)
    {
        LOG_ERROR("{} inbound_tag {} inbound_type {} stage start exception {}",
                  log_event::kConnInit,
                  inbound_tag,
                  inbound_type,
                  ex.what());
        std::exit(EXIT_FAILURE);
    }
    catch (...)
    {
        LOG_ERROR("{} inbound_tag {} inbound_type {} stage start exception unknown", log_event::kConnInit, inbound_tag, inbound_type);
        std::exit(EXIT_FAILURE);
    }
}

template <typename TInbound>
void stop_inbound_instances(const std::vector<std::shared_ptr<TInbound>>& inbounds)
{
    for (const auto& inbound_instance : inbounds)
    {
        if (inbound_instance != nullptr)
        {
            inbound_instance->stop();
        }
    }
}

}    // namespace

app_runtime::app_runtime(const config& cfg) : cfg_(cfg), pool_(resolve_worker_threads(cfg_)) {}

void app_runtime::start()
{
    start_outbounds();
    start_web_server();
    for (const auto& inbound : cfg_.inbounds)
    {
        start_inbound(inbound);
    }
}

void app_runtime::start_web_server()
{
    if (!cfg_.web.enabled)
    {
        return;
    }

    web_server_ = std::make_shared<trace_web_server>(pool_, cfg_);
    web_server_->start();
}

void app_runtime::start_outbounds()
{
    outbounds_.clear();
    outbounds_.reserve(cfg_.outbounds.size());
    for (const auto& outbound : cfg_.outbounds)
    {
        const auto handler = make_outbound_handler(cfg_, outbound.tag);
        if (handler == nullptr)
        {
            LOG_ERROR("{} outbound_tag {} outbound_type {} stage start unsupported outbound",
                      log_event::kConnInit,
                      outbound.tag,
                      outbound.type);
            std::exit(EXIT_FAILURE);
        }
        outbounds_.push_back(handler);
        LOG_INFO("{} outbound_tag {} outbound_type {} stage start loaded",
                 log_event::kConnInit,
                 outbound.tag,
                 outbound.type);
    }
}

void app_runtime::start_inbound(const config::inbound_entry_t& inbound)
{
    if (inbound.type == config_type::kInboundReality && inbound.reality.has_value())
    {
        start_inbound_instance(pool_, cfg_, inbound.tag, inbound.type, *inbound.reality, reality_inbounds_);
        return;
    }

    if (inbound.type == config_type::kInboundSocks && inbound.socks.has_value())
    {
        start_inbound_instance(pool_, cfg_, inbound.tag, inbound.type, *inbound.socks, socks_inbounds_);
        return;
    }

#if SOCKS_HAS_TPROXY
    if (inbound.type == config_type::kInboundTproxy && inbound.tproxy.has_value())
    {
        start_inbound_instance(pool_, cfg_, inbound.tag, inbound.type, *inbound.tproxy, tproxy_inbounds_);
        return;
    }
#endif

#if SOCKS_HAS_TUN
    if (inbound.type == config_type::kInboundTun && inbound.tun.has_value())
    {
        start_inbound_instance(pool_, cfg_, inbound.tag, inbound.type, *inbound.tun, tun_inbounds_);
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
    stop_inbound_instances(socks_inbounds_);
#if SOCKS_HAS_TPROXY
    stop_inbound_instances(tproxy_inbounds_);
#endif
#if SOCKS_HAS_TUN
    stop_inbound_instances(tun_inbounds_);
#endif
    stop_inbound_instances(reality_inbounds_);

    if (web_server_ != nullptr)
    {
        web_server_->stop();
    }

    pool_.emit_all(boost::asio::cancellation_type::all);
}

boost::asio::awaitable<void> app_runtime::async_wait_stopped()
{
    co_await pool_.async_wait_all();
    pool_.shutdown();
}

}    // namespace relay
