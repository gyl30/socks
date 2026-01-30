#ifndef LOG_CONTEXT_H
#define LOG_CONTEXT_H

#include <ios>
#include <string>
#include <cstdint>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>

namespace log_event
{
constexpr const char* CONN_INIT = "conn_init";
constexpr const char* CONN_ESTABLISHED = "conn_established";
constexpr const char* CONN_CLOSE = "conn_close";
constexpr const char* HANDSHAKE = "handshake";
constexpr const char* DATA_SEND = "data_send";
constexpr const char* DATA_RECV = "data_recv";
constexpr const char* STREAM_OPEN = "stream_open";
constexpr const char* STREAM_CLOSE = "stream_close";
constexpr const char* ROUTE = "route";
constexpr const char* FALLBACK = "fallback";
constexpr const char* AUTH = "auth";
constexpr const char* MUX = "mux";
constexpr const char* MUX_FRAME = "mux_frame";
constexpr const char* SOCKS = "socks";
constexpr const char* DNS = "dns";
constexpr const char* TIMEOUT = "timeout";
constexpr const char* CERT = "cert";
}    // namespace log_event

inline std::string generate_trace_id()
{
    static thread_local std::mt19937_64 gen(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << dist(gen);
    return oss.str();
}

struct connection_context
{
    std::string trace_id;
    uint32_t conn_id = 0;
    uint32_t stream_id = 0;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string target_host;
    uint16_t target_port = 0;
    std::string sni;

    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

    [[nodiscard]] std::string prefix() const
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

    [[nodiscard]] std::string connection_info() const
    {
        std::ostringstream oss;
        oss << local_addr << "_" << local_port << "_" << remote_addr << "_" << remote_port;
        return oss.str();
    }

    [[nodiscard]] std::string target_info() const
    {
        std::ostringstream oss;
        oss << target_host << "_" << target_port;
        return oss.str();
    }

    [[nodiscard]] double duration_seconds() const
    {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        return duration.count() / 1000.0;
    }

    [[nodiscard]] std::string stats_summary() const
    {
        std::ostringstream oss;
        oss << "tx " << tx_bytes << " rx " << rx_bytes << " duration " << std::fixed << std::setprecision(2) << duration_seconds() << "s";
        return oss.str();
    }

    [[nodiscard]] connection_context with_stream(uint32_t sid) const
    {
        connection_context ctx = *this;
        ctx.stream_id = sid;
        ctx.tx_bytes = 0;
        ctx.rx_bytes = 0;
        ctx.start_time = std::chrono::steady_clock::now();
        return ctx;
    }

    void set_target(const std::string& host, uint16_t port)
    {
        target_host = host;
        target_port = port;
    }

    void new_trace_id() { trace_id = generate_trace_id(); }
};

inline std::string format_bytes(uint64_t bytes)
{
    std::ostringstream oss;
    if (bytes >= 1024 * 1024 * 1024)
    {
        oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0 * 1024.0)) << "GB";
    }
    else if (bytes >= 1024 * 1024)
    {
        oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0)) << "MB";
    }
    else if (bytes >= 1024)
    {
        oss << std::fixed << std::setprecision(2) << (bytes / 1024.0) << "KB";
    }
    else
    {
        oss << bytes << "B";
    }
    return oss.str();
}

inline std::string format_latency_ms(int64_t ms)
{
    std::ostringstream oss;
    oss << ms << "ms";
    return oss.str();
}

#endif
