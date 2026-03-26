#ifndef CONNECTION_CONTEXT_H
#define CONNECTION_CONTEXT_H

#include <chrono>
#include <string>
#include <cstdint>

namespace mux
{

namespace log_event
{

constexpr const char* kConnInit = "conn_init";
constexpr const char* kConnEstablished = "conn_established";
constexpr const char* kConnClose = "conn_close";
constexpr const char* kHandshake = "handshake";
constexpr const char* kDataSend = "data_send";
constexpr const char* kDataRecv = "data_recv";
constexpr const char* kStreamOpen = "stream_open";
constexpr const char* kStreamClose = "stream_close";
constexpr const char* kRoute = "route";
constexpr const char* kFallback = "fallback";
constexpr const char* kAuth = "auth";
constexpr const char* kMux = "mux";
constexpr const char* kMuxFrame = "mux_frame";
constexpr const char* kSocks = "socks";
constexpr const char* kDns = "dns";
constexpr const char* kTimeout = "timeout";
constexpr const char* kCert = "cert";

}    // namespace log_event

std::string generate_trace_id();

class connection_context
{
   public:
    [[nodiscard]] std::string trace_id() const { return trace_id_; }
    void trace_id(const std::string& val) { trace_id_ = val; }

    [[nodiscard]] std::uint32_t conn_id() const { return conn_id_; }
    void conn_id(const std::uint32_t val) { conn_id_ = val; }

    [[nodiscard]] std::uint32_t stream_id() const { return stream_id_; }
    void stream_id(const std::uint32_t val) { stream_id_ = val; }

    [[nodiscard]] std::string local_addr() const { return local_.addr; }

    [[nodiscard]] std::uint16_t local_port() const { return local_.port; }

    [[nodiscard]] std::string remote_addr() const { return remote_.addr; }

    [[nodiscard]] std::uint16_t remote_port() const { return remote_.port; }

    [[nodiscard]] std::string sni() const { return target_.sni; }
    void sni(const std::string& val) { target_.sni = val; }

    [[nodiscard]] std::uint64_t tx_bytes() const { return stats_.tx_bytes; }
    void add_tx_bytes(const std::uint64_t val) { stats_.tx_bytes += val; }

    [[nodiscard]] std::uint64_t rx_bytes() const { return stats_.rx_bytes; }
    void add_rx_bytes(const std::uint64_t val) { stats_.rx_bytes += val; }

    [[nodiscard]] std::string prefix() const;

    [[nodiscard]] std::string connection_info() const;

    [[nodiscard]] double duration_seconds() const;

    [[nodiscard]] std::string stats_summary() const;

    [[nodiscard]] connection_context with_stream(std::uint32_t sid) const;

    void set_local_endpoint(std::string addr, std::uint16_t port);

    void set_remote_endpoint(std::string addr, std::uint16_t port);

    void set_target(const std::string& host, std::uint16_t port);

    void new_trace_id();

   private:
    struct endpoint_info
    {
        std::string addr;
        std::uint16_t port = 0;
    };

    struct target_info
    {
        std::string host;
        std::uint16_t port = 0;
        std::string sni;
    };

    struct traffic_stats
    {
        std::uint64_t tx_bytes = 0;
        std::uint64_t rx_bytes = 0;
        std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();
    };

    std::string trace_id_;
    std::uint32_t conn_id_ = 0;
    std::uint32_t stream_id_ = 0;
    endpoint_info local_;
    endpoint_info remote_;
    target_info target_;
    traffic_stats stats_;
};

}    // namespace mux

#endif
