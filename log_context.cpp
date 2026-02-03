#include "log_context.h"
#include <sstream>
#include <iomanip>
#include <random>

std::string generate_trace_id()
{
    static thread_local std::mt19937_64 gen(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << dist(gen);
    return oss.str();
}

std::string connection_context::prefix() const
{
    std::ostringstream oss;
    if (!trace_id.empty())
    {
        oss << "t" << trace_id << " ";
    }
    oss << "c" << conn_id;
    if (stream_id > 0)
    {
        oss << "_s" << stream_id;
    }
    return oss.str();
}

std::string connection_context::connection_info() const
{
    std::ostringstream oss;
    oss << local_addr << "_" << local_port << "_" << remote_addr << "_" << remote_port;
    return oss.str();
}

std::string connection_context::target_info() const
{
    std::ostringstream oss;
    oss << target_host << "_" << target_port;
    return oss.str();
}

double connection_context::duration_seconds() const
{
    const auto now = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
    return static_cast<double>(duration.count()) / 1000.0;
}

std::string connection_context::stats_summary() const
{
    std::ostringstream oss;
    oss << "tx " << tx_bytes << " rx " << rx_bytes << " duration " << std::fixed << std::setprecision(2) << duration_seconds() << "s";
    return oss.str();
}

connection_context connection_context::with_stream(uint32_t sid) const
{
    connection_context ctx = *this;
    ctx.stream_id = sid;
    ctx.tx_bytes = 0;
    ctx.rx_bytes = 0;
    ctx.start_time = std::chrono::steady_clock::now();
    return ctx;
}

void connection_context::set_target(const std::string& host, uint16_t port)
{
    target_host = host;
    target_port = port;
}

void connection_context::new_trace_id() { trace_id = generate_trace_id(); }

std::string format_bytes(uint64_t bytes)
{
    constexpr uint64_t k_kib = 1024ULL;
    constexpr uint64_t k_mib = k_kib * 1024ULL;
    constexpr uint64_t k_gib = k_mib * 1024ULL;
    const double bytes_d = static_cast<double>(bytes);
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

std::string format_latency_ms(int64_t ms)
{
    std::ostringstream oss;
    oss << ms << "ms";
    return oss.str();
}
