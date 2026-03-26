#include <chrono>
#include <string>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "log.h"
#include "config.h"
#include "timeout_io.h"
#include "cert_fetcher.h"
#include "cert_manager.h"
#include "reality/material/material_provider.h"

namespace reality
{

namespace
{

material_provider::fetch_reply format_fetch_reply(std::expected<fetch_result, fetch_error> fetch_result)
{
    material_provider::fetch_reply reply;
    if (fetch_result.has_value())
    {
        reply.material = std::move(fetch_result->material);
        return reply;
    }

    reply.error_stage = std::move(fetch_result.error().stage);
    reply.error_reason = std::move(fetch_result.error().reason);
    return reply;
}

std::string format_fetch_error(const material_provider::fetch_reply& reply)
{
    if (reply.error_stage.empty())
    {
        return reply.error_reason;
    }
    if (reply.error_reason.empty())
    {
        return reply.error_stage;
    }
    return reply.error_stage + ": " + reply.error_reason;
}

boost::asio::awaitable<material_provider::fetch_reply> default_fetch(boost::asio::io_context& io_context,
                                                                     material_provider::fetch_request request)
{
    auto fetch_result = co_await cert_fetcher::fetch(io_context,
                                                     std::move(request.host),
                                                     request.port,
                                                     std::move(request.sni),
                                                     request.trace_id,
                                                     request.connect_timeout_sec,
                                                     request.read_timeout_sec,
                                                     request.write_timeout_sec);
    co_return format_fetch_reply(std::move(fetch_result));
}

}    // namespace

material_provider::material_provider(dependencies deps)
    : cfg_(deps.cfg),
      options_(deps.opts),
      now_seconds_fn_(std::move(deps.now_seconds)),
      fetch_(std::move(deps.fetch)),
      manager_(options_.cache_capacity)
{
    if (!now_seconds_fn_)
    {
        now_seconds_fn_ = []() { return mux::timeout_io::now_second(); };
    }
    if (!fetch_)
    {
        fetch_ = default_fetch;
    }
}

material_provider::~material_provider() = default;

std::optional<site_material_snapshot> material_provider::get_server_material_snapshot()
{
    if (cfg_.reality.sni.empty())
    {
        return std::nullopt;
    }
    return manager_.get_material_snapshot(cfg_.reality.sni);
}

boost::asio::awaitable<material_provider::refresh_result> material_provider::refresh_once(boost::asio::io_context& io_context)
{
    refresh_result result;
    const auto target_host = cfg_.reality.sni;
    if (target_host.empty())
    {
        co_return result;
    }

    result.attempted = true;
    result.next_refresh_in_seconds = options_.fetch_failure_retry_sec;

    const std::string trace_id = "site-material:" + target_host;
    const auto attempt_at = now_seconds();
    manager_.mark_fetch_started(target_host, target_host, target_host, options_.fallback_port, attempt_at, trace_id);

    auto fetch_reply = co_await fetch_(io_context,
                                       {.host = target_host,
                                        .port = options_.fallback_port,
                                        .sni = target_host,
                                        .trace_id = trace_id,
                                        .connect_timeout_sec = cfg_.timeout.connect,
                                        .read_timeout_sec = cfg_.timeout.connect,
                                        .write_timeout_sec = cfg_.timeout.connect});

    if (fetch_reply.material.has_value())
    {
        result.success = true;
        result.next_refresh_in_seconds = options_.fetch_success_ttl_sec;
        const auto next_refresh_at = now_seconds() + options_.fetch_success_ttl_sec;
        manager_.set_material(
            target_host, target_host, target_host, options_.fallback_port, std::move(*fetch_reply.material), next_refresh_at, trace_id);
        co_return result;
    }

    const auto next_refresh_at = now_seconds() + options_.fetch_failure_retry_sec;
    manager_.set_fetch_failure(
        target_host, target_host, target_host, options_.fallback_port, format_fetch_error(fetch_reply), attempt_at, next_refresh_at, trace_id);
    co_return result;
}

boost::asio::awaitable<void> material_provider::refresh_loop(boost::asio::io_context& io_context)
{
    const auto target_host = cfg_.reality.sni;
    if (target_host.empty())
    {
        LOG_INFO("reality site material refresh disabled because reality.sni is empty");
        co_return;
    }

    boost::asio::steady_timer refresh_timer(io_context);
    for (;;)
    {
        const auto refresh_state = co_await refresh_once(io_context);

        boost::system::error_code timer_ec;
        refresh_timer.expires_after(std::chrono::seconds(refresh_state.next_refresh_in_seconds));
        co_await refresh_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec));
        if (timer_ec == boost::asio::error::operation_aborted)
        {
            co_return;
        }
        if (timer_ec)
        {
            LOG_WARN("reality site material refresh timer error {}", timer_ec.message());
        }
    }
}

std::uint64_t material_provider::now_seconds() const
{
    return now_seconds_fn_();
}

}    // namespace reality
