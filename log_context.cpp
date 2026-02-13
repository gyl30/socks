#include <chrono>
#include <random>
#include <string>
#include <cstdint>
#include <cstdio>
#include <charconv>
#include <system_error>

#include "log_context.h"

namespace mux
{
namespace
{

template <typename IntT>
void append_int(std::string& out, const IntT value)
{
    char buf[32];
    const auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), value);
    if (ec == std::errc())
    {
        out.append(buf, ptr);
    }
}

std::string fixed_hex_16(std::uint64_t value)
{
    char buf[16];
    const auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), value, 16);
    if (ec != std::errc())
    {
        return "0000000000000000";
    }

    const auto len = static_cast<std::size_t>(ptr - buf);
    std::string out;
    out.reserve(16);
    out.append(16 - len, '0');
    out.append(buf, len);
    return out;
}

}    // namespace


std::string generate_trace_id()
{
    static thread_local std::mt19937_64 gen(std::random_device{}());
    std::uniform_int_distribution<std::uint64_t> dist;
    return fixed_hex_16(dist(gen));
}

std::string connection_context::prefix() const
{
    std::string out;
    out.reserve(trace_id_.size() + 32);
    if (!trace_id_.empty())
    {
        out.push_back('t');
        out += trace_id_;
        out.push_back(' ');
    }
    out.push_back('c');
    append_int(out, conn_id_);
    if (stream_id_ > 0)
    {
        out += "_s";
        append_int(out, stream_id_);
    }
    return out;
}

std::string connection_context::connection_info() const
{
    std::string out;
    out.reserve(local_addr_.size() + remote_addr_.size() + 32);
    out += local_addr_;
    out.push_back('_');
    append_int(out, local_port_);
    out.push_back('_');
    out += remote_addr_;
    out.push_back('_');
    append_int(out, remote_port_);
    return out;
}

std::string connection_context::target_info() const
{
    std::string out;
    out.reserve(target_host_.size() + 16);
    out += target_host_;
    out.push_back('_');
    append_int(out, target_port_);
    return out;
}

double connection_context::duration_seconds() const
{
    const auto now = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_);
    return static_cast<double>(duration.count()) / 1000.0;
}

std::string connection_context::stats_summary() const
{
    char duration_buf[32];
    std::snprintf(duration_buf, sizeof(duration_buf), "%.2f", duration_seconds());

    std::string out;
    out.reserve(96);
    out += "tx ";
    append_int(out, tx_bytes_);
    out += " rx ";
    append_int(out, rx_bytes_);
    out += " duration ";
    out += duration_buf;
    out.push_back('s');
    return out;
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
    constexpr std::uint64_t kKib = 1024ULL;
    constexpr std::uint64_t kMib = kKib * 1024ULL;
    constexpr std::uint64_t kGib = kMib * 1024ULL;
    const auto bytes_d = static_cast<double>(bytes);
    char number_buf[32];
    if (bytes >= kGib)
    {
        std::snprintf(number_buf, sizeof(number_buf), "%.2fGB", bytes_d / static_cast<double>(kGib));
        return std::string(number_buf);
    }
    if (bytes >= kMib)
    {
        std::snprintf(number_buf, sizeof(number_buf), "%.2fMB", bytes_d / static_cast<double>(kMib));
        return std::string(number_buf);
    }
    if (bytes >= kKib)
    {
        std::snprintf(number_buf, sizeof(number_buf), "%.2fKB", bytes_d / static_cast<double>(kKib));
        return std::string(number_buf);
    }
    std::string out;
    out.reserve(24);
    append_int(out, bytes);
    out.push_back('B');
    return out;
}

std::string format_latency_ms(std::int64_t ms)
{
    std::string out;
    out.reserve(24);
    append_int(out, ms);
    out += "ms";
    return out;
}

}    // namespace mux
