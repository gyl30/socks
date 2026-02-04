#ifndef LOG_CONTEXT_H
#define LOG_CONTEXT_H

#include <chrono>
#include <string>
#include <cstdint>

namespace mux
{

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

class connection_context
{
   public:
    [[nodiscard]] std::string trace_id() const { return trace_id_; }
    void trace_id(const std::string& val) { trace_id_ = val; }

    [[nodiscard]] uint32_t conn_id() const { return conn_id_; }
    void conn_id(const uint32_t val) { conn_id_ = val; }

    [[nodiscard]] uint32_t stream_id() const { return stream_id_; }
    void stream_id(const uint32_t val) { stream_id_ = val; }

    [[nodiscard]] std::string local_addr() const { return local_addr_; }
    void local_addr(const std::string& val) { local_addr_ = val; }

    [[nodiscard]] uint16_t local_port() const { return local_port_; }
    void local_port(const uint16_t val) { local_port_ = val; }

    [[nodiscard]] std::string remote_addr() const { return remote_addr_; }
    void remote_addr(const std::string& val) { remote_addr_ = val; }

    [[nodiscard]] uint16_t remote_port() const { return remote_port_; }
    void remote_port(const uint16_t val) { remote_port_ = val; }

    [[nodiscard]] std::string target_host() const { return target_host_; }
    void target_host(const std::string& val) { target_host_ = val; }

    [[nodiscard]] uint16_t target_port() const { return target_port_; }
    void target_port(const uint16_t val) { target_port_ = val; }

    [[nodiscard]] std::string sni() const { return sni_; }
    void sni(const std::string& val) { sni_ = val; }

    [[nodiscard]] uint64_t tx_bytes() const { return tx_bytes_; }
    void tx_bytes(const uint64_t val) { tx_bytes_ = val; }
    void add_tx_bytes(const uint64_t val) { tx_bytes_ += val; }

    [[nodiscard]] uint64_t rx_bytes() const { return rx_bytes_; }
    void rx_bytes(const uint64_t val) { rx_bytes_ = val; }
    void add_rx_bytes(const uint64_t val) { rx_bytes_ += val; }

    [[nodiscard]] std::chrono::steady_clock::time_point start_time() const { return start_time_; }

    [[nodiscard]] std::string prefix() const;

    [[nodiscard]] std::string connection_info() const;

    [[nodiscard]] std::string target_info() const;

    [[nodiscard]] double duration_seconds() const;

    [[nodiscard]] std::string stats_summary() const;

    [[nodiscard]] connection_context with_stream(const uint32_t sid) const;

    void set_target(const std::string& host, const uint16_t port);

    void new_trace_id();

   private:
    std::string trace_id_;
    uint32_t conn_id_ = 0;
    uint32_t stream_id_ = 0;
    std::string local_addr_;
    uint16_t local_port_ = 0;
    std::string remote_addr_;
    uint16_t remote_port_ = 0;
    std::string target_host_;
    uint16_t target_port_ = 0;
    std::string sni_;

    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
};

std::string format_bytes(uint64_t bytes);

std::string format_latency_ms(int64_t ms);

}    // namespace mux

#endif
