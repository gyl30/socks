#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include <span>
#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace relay::proxy
{

// Covers framed TCP control/data messages and the largest supported UDP datagram.
constexpr uint32_t kMaxPacketSize = 1U + 1U + 1U + 255U + 2U + 65507U;
constexpr uint8_t kTcpFeatureVision = 0x01;
constexpr uint8_t kKnownTcpFeatureFlags = kTcpFeatureVision;

enum class message_type : uint8_t
{
    kTcpConnectRequest = 0x01,
    kTcpConnectReply = 0x02,
    kUdpAssociateRequest = 0x03,
    kUdpAssociateReply = 0x04,
    kUdpDatagram = 0x05,
    kTcpData = 0x06,
    kTcpShutdown = 0x07,
};

struct tcp_connect_request
{
    std::string target_host;
    uint16_t target_port = 0;
    uint64_t trace_id = 0;
    uint16_t timeout_sec = 0;
    uint8_t feature_flags = 0;
};

struct tcp_connect_reply
{
    uint8_t socks_rep = 0;
    std::string bind_host;
    uint16_t bind_port = 0;
    uint8_t feature_flags = 0;
};

struct udp_associate_request
{
    uint64_t trace_id = 0;
    uint16_t timeout_sec = 0;
};

struct udp_associate_reply
{
    uint8_t socks_rep = 0;
    std::string bind_host;
    uint16_t bind_port = 0;
};

struct udp_datagram
{
    std::string target_host;
    uint16_t target_port = 0;
    std::vector<uint8_t> payload;
};

enum class tcp_stream_frame_kind : uint8_t
{
    kInvalid = 0,
    kData,
    kShutdown,
};

struct tcp_stream_frame
{
    tcp_stream_frame_kind kind = tcp_stream_frame_kind::kInvalid;
    std::vector<uint8_t> payload;
};

class tcp_stream_send_state
{
   public:
    [[nodiscard]] bool can_send_data(std::span<const uint8_t> payload) const;
    [[nodiscard]] bool can_send_shutdown() const { return !shutdown_sent_; }
    void mark_shutdown_sent() { shutdown_sent_ = true; }
    void reset() { shutdown_sent_ = false; }
    [[nodiscard]] bool shutdown_sent() const { return shutdown_sent_; }

   private:
    bool shutdown_sent_ = false;
};

class tcp_stream_recv_state
{
   public:
    [[nodiscard]] bool accept(const tcp_stream_frame& frame);
    void reset() { shutdown_seen_ = false; }
    [[nodiscard]] bool shutdown_seen() const { return shutdown_seen_; }

   private:
    bool shutdown_seen_ = false;
};

[[nodiscard]] std::string_view message_name(message_type type);

[[nodiscard]] bool encode_tcp_connect_request(const tcp_connect_request& request, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_tcp_connect_request(const uint8_t* data, std::size_t len, tcp_connect_request& out);

[[nodiscard]] bool encode_tcp_connect_reply(const tcp_connect_reply& reply, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_tcp_connect_reply(const uint8_t* data, std::size_t len, tcp_connect_reply& out);

[[nodiscard]] bool encode_udp_associate_request(const udp_associate_request& request, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_udp_associate_request(const uint8_t* data, std::size_t len, udp_associate_request& out);

[[nodiscard]] bool encode_udp_associate_reply(const udp_associate_reply& reply, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_udp_associate_reply(const uint8_t* data, std::size_t len, udp_associate_reply& out);

[[nodiscard]] bool encode_udp_datagram(const udp_datagram& datagram, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_udp_datagram(const uint8_t* data, std::size_t len, udp_datagram& out);

[[nodiscard]] bool encode_tcp_stream_data(std::span<const uint8_t> payload, std::vector<uint8_t>& out);

[[nodiscard]] bool encode_tcp_stream_shutdown(std::vector<uint8_t>& out);

[[nodiscard]] bool decode_tcp_stream_frame(const uint8_t* data, std::size_t len, tcp_stream_frame& out);

}    // namespace relay::proxy

#endif
