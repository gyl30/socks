#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "proxy_protocol.h"

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

}    // namespace

int main()
{
    using relay::proxy::decode_tcp_stream_frame;
    using relay::proxy::encode_tcp_stream_data;
    using relay::proxy::encode_tcp_stream_shutdown;
    using relay::proxy::kMaxPacketSize;
    using relay::proxy::tcp_stream_frame;
    using relay::proxy::tcp_stream_frame_kind;
    using relay::proxy::tcp_stream_recv_state;
    using relay::proxy::tcp_stream_send_state;

    std::vector<uint8_t> packet;
    const std::vector<uint8_t> payload{'o', 'k'};
    tcp_stream_frame frame;

    const bool ok =
        require(encode_tcp_stream_data(std::span<const uint8_t>(payload.data(), payload.size()), packet), "failed to encode tcp data frame") &&
        require(packet.size() == payload.size() + 1U, "unexpected tcp data frame size") &&
        require(decode_tcp_stream_frame(packet.data(), packet.size(), frame), "failed to decode tcp data frame") &&
        require(frame.kind == tcp_stream_frame_kind::kData, "decoded frame kind should be data") &&
        require(frame.payload == payload, "decoded tcp data payload mismatch") &&
        require(encode_tcp_stream_shutdown(packet), "failed to encode tcp shutdown frame") &&
        require(packet.size() == 1U, "unexpected tcp shutdown frame size") &&
        require(decode_tcp_stream_frame(packet.data(), packet.size(), frame), "failed to decode tcp shutdown frame") &&
        require(frame.kind == tcp_stream_frame_kind::kShutdown, "decoded frame kind should be shutdown") &&
        require(frame.payload.empty(), "shutdown frame must not carry payload") &&
        require(!encode_tcp_stream_data({}, packet), "empty tcp data payload should be rejected") &&
        require(!decode_tcp_stream_frame(nullptr, 0, frame), "empty tcp frame should be rejected") &&
        require(!decode_tcp_stream_frame(reinterpret_cast<const uint8_t*>("\x06"), 1, frame), "tcp data frame without payload should be rejected") &&
        require(!decode_tcp_stream_frame(reinterpret_cast<const uint8_t*>("\x07\x00"), 2, frame), "tcp shutdown frame with payload should be rejected") &&
        require(!decode_tcp_stream_frame(reinterpret_cast<const uint8_t*>("\x08\x00"), 2, frame), "unknown tcp frame type should be rejected");

    if (!ok)
    {
        return 1;
    }

    std::vector<uint8_t> oversized(kMaxPacketSize, 0x42);
    if (!require(!encode_tcp_stream_data(std::span<const uint8_t>(oversized.data(), oversized.size()), packet),
                 "oversized tcp data payload should be rejected"))
    {
        return 1;
    }

    tcp_stream_send_state send_state;
    if (!require(send_state.can_send_data(std::span<const uint8_t>(payload.data(), payload.size())), "send state should allow data before shutdown") ||
        !require(send_state.can_send_shutdown(), "send state should allow shutdown before shutdown"))
    {
        return 1;
    }
    send_state.mark_shutdown_sent();
    if (!require(send_state.shutdown_sent(), "send state should remember shutdown") ||
        !require(!send_state.can_send_shutdown(), "send state should reject duplicate shutdown") ||
        !require(!send_state.can_send_data(std::span<const uint8_t>(payload.data(), payload.size())), "send state should reject data after shutdown"))
    {
        return 1;
    }

    tcp_stream_recv_state recv_state;
    tcp_stream_frame data_frame{.kind = tcp_stream_frame_kind::kData, .payload = payload};
    tcp_stream_frame shutdown_frame{.kind = tcp_stream_frame_kind::kShutdown, .payload = {}};
    if (!require(recv_state.accept(data_frame), "recv state should accept initial data") ||
        !require(recv_state.accept(shutdown_frame), "recv state should accept first shutdown") ||
        !require(recv_state.shutdown_seen(), "recv state should remember shutdown") ||
        !require(!recv_state.accept(shutdown_frame), "recv state should reject duplicate shutdown") ||
        !require(!recv_state.accept(data_frame), "recv state should reject data after shutdown"))
    {
        return 1;
    }

    return 0;
}
