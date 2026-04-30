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
    using relay::proxy::decode_tcp_connect_reply;
    using relay::proxy::decode_tcp_connect_request;
    using relay::proxy::decode_tcp_stream_frame;
    using relay::proxy::decode_udp_associate_reply;
    using relay::proxy::decode_udp_associate_request;
    using relay::proxy::decode_udp_datagram;
    using relay::proxy::encode_tcp_connect_reply;
    using relay::proxy::encode_tcp_connect_request;
    using relay::proxy::encode_tcp_stream_data;
    using relay::proxy::encode_tcp_stream_shutdown;
    using relay::proxy::encode_udp_associate_reply;
    using relay::proxy::encode_udp_associate_request;
    using relay::proxy::encode_udp_datagram;
    using relay::proxy::kMaxPacketSize;
    using relay::proxy::message_name;
    using relay::proxy::message_type;
    using relay::proxy::tcp_connect_reply;
    using relay::proxy::tcp_connect_request;
    using relay::proxy::tcp_stream_frame;
    using relay::proxy::tcp_stream_frame_kind;
    using relay::proxy::tcp_stream_recv_state;
    using relay::proxy::tcp_stream_send_state;
    using relay::proxy::udp_associate_reply;
    using relay::proxy::udp_associate_request;
    using relay::proxy::udp_datagram;

    std::vector<uint8_t> packet;
    const std::vector<uint8_t> payload{'o', 'k'};
    tcp_stream_frame frame;
    tcp_connect_request connect_request;
    tcp_connect_reply connect_reply;
    udp_associate_request associate_request;
    udp_associate_reply associate_reply;
    udp_datagram datagram;

    const tcp_connect_request domain_connect_request{
        .target_host = "example.com",
        .target_port = 443,
        .trace_id = 0x0102030405060708ULL,
    };
    const tcp_connect_request mapped_connect_request{
        .target_host = "::ffff:127.0.0.1",
        .target_port = 8443,
        .trace_id = 0x1112131415161718ULL,
    };
    const tcp_connect_reply success_connect_reply{
        .socks_rep = 0x00,
        .bind_host = "",
        .bind_port = 0,
    };
    const udp_associate_request outbound_associate_request{
        .trace_id = 0x2122232425262728ULL,
    };
    const udp_associate_reply success_associate_reply{
        .socks_rep = 0x00,
        .bind_host = "",
        .bind_port = 0,
    };
    const udp_datagram outbound_datagram{
        .target_host = "example.com",
        .target_port = 5353,
        .payload = std::vector<uint8_t>{'u', 'd', 'p'},
    };

    const bool ok =
        require(message_name(message_type::kTcpConnectRequest) == "tcp_connect_request", "unexpected tcp connect request message name") &&
        require(message_name(static_cast<message_type>(0xFF)) == "unknown", "unexpected unknown message name") &&
        require(encode_tcp_connect_request(domain_connect_request, packet), "failed to encode tcp connect request") &&
        require(decode_tcp_connect_request(packet.data(), packet.size(), connect_request), "failed to decode tcp connect request") &&
        require(connect_request.target_host == domain_connect_request.target_host, "decoded tcp connect request host mismatch") &&
        require(connect_request.target_port == domain_connect_request.target_port, "decoded tcp connect request port mismatch") &&
        require(connect_request.trace_id == domain_connect_request.trace_id, "decoded tcp connect request trace id mismatch") &&
        require(!decode_tcp_connect_request(packet.data(), packet.size() - 1U, connect_request),
                "truncated tcp connect request should be rejected") &&
        require(encode_tcp_connect_request(mapped_connect_request, packet), "failed to encode mapped tcp connect request") &&
        require(decode_tcp_connect_request(packet.data(), packet.size(), connect_request), "failed to decode mapped tcp connect request") &&
        require(connect_request.target_host == "127.0.0.1", "mapped tcp connect request host should normalize to ipv4") &&
        require(connect_request.target_port == mapped_connect_request.target_port, "mapped tcp connect request port mismatch") &&
        require(!encode_tcp_connect_request(tcp_connect_request{.target_host = "example.com", .target_port = 0, .trace_id = 1}, packet),
                "tcp connect request with zero port should be rejected") &&
        require(encode_tcp_connect_reply(success_connect_reply, packet), "failed to encode tcp connect reply") &&
        require(decode_tcp_connect_reply(packet.data(), packet.size(), connect_reply), "failed to decode tcp connect reply") &&
        require(connect_reply.socks_rep == success_connect_reply.socks_rep, "decoded tcp connect reply rep mismatch") &&
        require(connect_reply.bind_host == "0.0.0.0", "decoded tcp connect reply default bind host mismatch") &&
        require(connect_reply.bind_port == 0, "decoded tcp connect reply default bind port mismatch") &&
        require(encode_udp_associate_request(outbound_associate_request, packet), "failed to encode udp associate request") &&
        require(decode_udp_associate_request(packet.data(), packet.size(), associate_request), "failed to decode udp associate request") &&
        require(associate_request.trace_id == outbound_associate_request.trace_id, "decoded udp associate request trace id mismatch") &&
        require(!decode_udp_associate_request(packet.data(), packet.size() - 1U, associate_request),
                "truncated udp associate request should be rejected") &&
        require(encode_udp_associate_reply(success_associate_reply, packet), "failed to encode udp associate reply") &&
        require(decode_udp_associate_reply(packet.data(), packet.size(), associate_reply), "failed to decode udp associate reply") &&
        require(associate_reply.socks_rep == success_associate_reply.socks_rep, "decoded udp associate reply rep mismatch") &&
        require(associate_reply.bind_host == "0.0.0.0", "decoded udp associate reply default bind host mismatch") &&
        require(associate_reply.bind_port == 0, "decoded udp associate reply default bind port mismatch") &&
        require(!decode_udp_associate_reply(packet.data(), packet.size() - 1U, associate_reply),
                "truncated udp associate reply should be rejected") &&
        require(encode_udp_datagram(outbound_datagram, packet), "failed to encode udp datagram") &&
        require(decode_udp_datagram(packet.data(), packet.size(), datagram), "failed to decode udp datagram") &&
        require(datagram.target_host == outbound_datagram.target_host, "decoded udp datagram host mismatch") &&
        require(datagram.target_port == outbound_datagram.target_port, "decoded udp datagram port mismatch") &&
        require(datagram.payload == outbound_datagram.payload, "decoded udp datagram payload mismatch") &&
        require(!decode_udp_datagram(reinterpret_cast<const uint8_t*>("\x05\x01\x7f\x00\x00\x01\x00"), 7U, datagram),
                "truncated udp datagram endpoint should be rejected") &&
        require(!encode_udp_datagram(udp_datagram{.target_host = "example.com", .target_port = 0, .payload = {'b'}}, packet),
                "udp datagram with zero port should be rejected") &&
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
