#ifndef LOG_CONTEXT_H
#define LOG_CONTEXT_H

#include <string>
#include <cstdint>
#include <chrono>

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

std::string generate_trace_id();

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

    [[nodiscard]] std::string prefix() const;

    [[nodiscard]] std::string connection_info() const;

    [[nodiscard]] std::string target_info() const;

    [[nodiscard]] double duration_seconds() const;

    [[nodiscard]] std::string stats_summary() const;

    [[nodiscard]] connection_context with_stream(uint32_t sid) const;

    void set_target(const std::string& host, uint16_t port);

    void new_trace_id();
};

std::string format_bytes(uint64_t bytes);

std::string format_latency_ms(int64_t ms);

#endif
