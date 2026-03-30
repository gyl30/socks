#include <chrono>
#include <random>
#include <string>
#include <utility>

#include <spdlog/fmt/bundled/format.h>

#include "connection_context.h"

namespace mux
{
std::string generate_trace_id()
{
    static thread_local std::mt19937_64 gen(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    return fmt::format("{:016x}", dist(gen));
}

std::string connection_context::prefix() const
{
    if (!trace_id_.empty())
    {
        if (stream_id_ > 0)
        {
            return fmt::format("t{} c{}_s{}", trace_id_, conn_id_, stream_id_);
        }
        return fmt::format("t{} c{}", trace_id_, conn_id_);
    }
    if (stream_id_ > 0)
    {
        return fmt::format("c{}_s{}", conn_id_, stream_id_);
    }
    return fmt::format("c{}", conn_id_);
}

std::string connection_context::connection_info() const { return fmt::format("{}_{}_{}_{}", local_.addr, local_.port, remote_.addr, remote_.port); }

double connection_context::duration_seconds() const
{
    const auto now = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - stats_.start_time);
    return static_cast<double>(duration.count()) / 1000.0;
}

std::string connection_context::stats_summary() const
{
    return fmt::format("tx {} rx {} duration {:.2f}s", stats_.tx_bytes, stats_.rx_bytes, duration_seconds());
}

connection_context connection_context::with_stream(const uint32_t sid) const
{
    connection_context ctx = *this;
    ctx.stream_id_ = sid;
    ctx.stats_ = {};
    return ctx;
}

void connection_context::set_local_endpoint(std::string addr, const uint16_t port)
{
    local_.addr = std::move(addr);
    local_.port = port;
}

void connection_context::set_remote_endpoint(std::string addr, const uint16_t port)
{
    remote_.addr = std::move(addr);
    remote_.port = port;
}

void connection_context::set_target(const std::string& host, const uint16_t port)
{
    target_.host = host;
    target_.port = port;
}

void connection_context::new_trace_id() { trace_id_ = generate_trace_id(); }

}    // namespace mux
