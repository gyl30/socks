#include <chrono>
#include <random>
#include <string>
#include <cstdint>
#include <iomanip>
#include <sstream>

#include "log_context.h"

namespace mux
{

std::string generate_trace_id()
{
    static thread_local std::mt19937_64 gen(std::random_device{}());
    std::uniform_int_distribution<std::uint64_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << dist(gen);
    return oss.str();
}

std::string connection_context::prefix() const
{
    std::ostringstream oss;
    if (!trace_id_.empty())
    {
        oss << "t" << trace_id_ << " ";
    }
    oss << "c" << conn_id_;
    if (stream_id_ > 0)
    {
        oss << "_s" << stream_id_;
    }
    return oss.str();
}

std::string connection_context::connection_info() const
{
    std::ostringstream oss;
    oss << local_addr_ << "_" << local_port_ << "_" << remote_addr_ << "_" << remote_port_;
    return oss.str();
}

std::string connection_context::target_info() const
{
    std::ostringstream oss;
    oss << target_host_ << "_" << target_port_;
    return oss.str();
}

double connection_context::duration_seconds() const
{
    const auto now = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_);
    return static_cast<double>(duration.count()) / 1000.0;
}

std::string connection_context::stats_summary() const
{
    std::ostringstream oss;
    oss << "tx " << tx_bytes_ << " rx " << rx_bytes_ << " duration " << std::fixed << std::setprecision(2) << duration_seconds() << "s";
    return oss.str();
}

connection_context connection_context::with_stream(const std::uint32_t sid) const
{
    connection_context ctx = *this;
    ctx.stream_id_ = sid;
    ctx.tx_bytes_ = 0;
    ctx.rx_bytes_ = 0;
    ctx.start_time_ = std::chrono::steady_clock::now();
    return ctx;
}

void connection_context::set_target(const std::string& host, const std::uint16_t port)
{
    target_host_ = host;
    target_port_ = port;
}

void connection_context::new_trace_id() { trace_id_ = generate_trace_id(); }

std::string format_bytes(std::uint64_t bytes)
{
    constexpr std::uint64_t k_kib = 1024ULL;
    constexpr std::uint64_t k_mib = k_kib * 1024ULL;
    constexpr std::uint64_t k_gib = k_mib * 1024ULL;
    const auto bytes_d = static_cast<double>(bytes);
    std::ostringstream oss;
    if (bytes >= k_gib)
    {
        oss << std::fixed << std::setprecision(2) << (bytes_d / static_cast<double>(k_gib)) << "GB";
    }
    else if (bytes >= k_mib)
    {
        oss << std::fixed << std::setprecision(2) << (bytes_d / static_cast<double>(k_mib)) << "MB";
    }
    else if (bytes >= k_kib)
    {
        oss << std::fixed << std::setprecision(2) << (bytes_d / static_cast<double>(k_kib)) << "KB";
    }
    else
    {
        oss << bytes << "B";
    }
    return oss.str();
}

std::string format_latency_ms(std::int64_t ms)
{
    std::ostringstream oss;
    oss << ms << "ms";
    return oss.str();
}

}    // namespace mux
