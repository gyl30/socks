#ifndef MUX_SESSION_UTILS_H
#define MUX_SESSION_UTILS_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <utility>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
namespace mux::session_util
{

[[nodiscard]] inline bool is_normal_close_error(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor;
}

[[nodiscard]] inline const char* mux_command_name(uint8_t cmd)
{
    switch (cmd)
    {
        case mux::kCmdSyn:
            return "syn";
        case mux::kCmdAck:
            return "ack";
        case mux::kCmdDat:
            return "dat";
        case mux::kCmdFin:
            return "fin";
        case mux::kCmdRst:
            return "rst";
        default:
            return "unknown";
    }
}

inline void update_stream_close_command(std::atomic<uint8_t>& stream_close_command, uint8_t next_command)
{
    auto current = stream_close_command.load(std::memory_order_relaxed);
    for (;;)
    {
        uint8_t desired = current;
        if (next_command == mux::kCmdRst)
        {
            desired = mux::kCmdRst;
        }
        else if (next_command == mux::kNoStreamControl && current != mux::kCmdRst)
        {
            desired = mux::kNoStreamControl;
        }
        if (desired == current)
        {
            return;
        }
        if (stream_close_command.compare_exchange_weak(current, desired, std::memory_order_relaxed))
        {
            return;
        }
    }
}

[[nodiscard]] inline std::string udp_target_key(const std::string& host, uint16_t port) { return host + "|" + std::to_string(port); }

template <typename Cache>
inline void evict_expired(Cache& cache, uint64_t now_ms)
{
    cache.evict_while([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
}

inline boost::asio::awaitable<void> send_stream_reset(const std::shared_ptr<mux_stream>& stream,
                                                      const char* event,
                                                      uint32_t conn_id,
                                                      const char* stage)
{
    if (stream == nullptr)
    {
        co_return;
    }

    mux_frame rst_frame;
    rst_frame.h.stream_id = stream->id();
    rst_frame.h.command = mux::kCmdRst;

    boost::system::error_code rst_ec;
    co_await stream->async_write(std::move(rst_frame), rst_ec);
    if (rst_ec)
    {
        LOG_WARN("event {} conn_id {} stream_id {} stage {} send rst failed {}", event, conn_id, stream->id(), stage, rst_ec.message());
    }
}

inline boost::asio::awaitable<void> send_fail_ack(const std::shared_ptr<mux_stream>& stream, uint32_t stream_id, uint8_t rep)
{
    if (stream == nullptr)
    {
        co_return;
    }

    const ack_payload ack{.socks_rep = rep, .bnd_addr = "0.0.0.0", .bnd_port = 0};
    std::vector<uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        co_return;
    }

    mux_frame ack_frame;
    ack_frame.h.stream_id = stream_id;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload = std::move(ack_data);

    boost::system::error_code ack_ec;
    co_await stream->async_write(std::move(ack_frame), ack_ec);
}

template <typename Channel>
inline boost::asio::awaitable<void> forward_udp_packets_to_proxy_stream(Channel& packet_channel,
                                                                        const std::shared_ptr<mux_stream>& stream,
                                                                        uint64_t trace_id,
                                                                        uint32_t conn_id,
                                                                        const boost::asio::ip::udp::endpoint& client_endpoint,
                                                                        const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                        const char* udp_label,
                                                                        uint64_t& tx_bytes,
                                                                        uint64_t& last_activity_time_ms)
{
    boost::system::error_code ec;
    for (;;)
    {
        auto payload = co_await packet_channel.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        const socks_udp_header header{
            .frag = 0,
            .addr = target_endpoint.address().to_string(),
            .port = target_endpoint.port(),
        };
        const auto header_bytes = socks_codec::encode_udp_header(header);
        mux_frame data_frame;
        data_frame.h.stream_id = stream->id();
        data_frame.h.command = mux::kCmdDat;
        data_frame.payload.reserve(header_bytes.size() + payload.size());
        data_frame.payload.insert(data_frame.payload.end(), header_bytes.begin(), header_bytes.end());
        data_frame.payload.insert(data_frame.payload.end(), payload.begin(), payload.end());
        if (data_frame.payload.size() > mux::kMaxPayload)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} {} udp payload too large {} max {}",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label,
                     data_frame.payload.size(),
                     mux::kMaxPayload);
            continue;
        }

        co_await stream->async_write(std::move(data_frame), ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} send {} udp payload failed {}",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label,
                     ec.message());
            co_return;
        }
        tx_bytes += payload.size();
        last_activity_time_ms = net::now_ms();
    }
}

template <typename SendToClient>
inline boost::asio::awaitable<void> forward_proxy_udp_stream_to_client(const std::shared_ptr<mux_stream>& stream,
                                                                       const config& cfg,
                                                                       std::atomic<uint8_t>& stream_close_command,
                                                                       uint64_t trace_id,
                                                                       uint32_t conn_id,
                                                                       const boost::asio::ip::udp::endpoint& client_endpoint,
                                                                       const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                       const char* udp_label,
                                                                       uint64_t& last_activity_time_ms,
                                                                       SendToClient&& send_to_client)
{
    const auto read_timeout = (cfg.timeout.idle == 0) ? cfg.timeout.read : std::max(cfg.timeout.read, cfg.timeout.idle + 2);
    boost::system::error_code ec;
    for (;;)
    {
        const auto frame = co_await stream->async_read(read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            update_stream_close_command(stream_close_command, mux::kNoStreamControl);
            co_return;
        }
        if (frame.h.command == mux::kCmdFin || frame.h.command == mux::kCmdRst)
        {
            update_stream_close_command(stream_close_command, mux::kNoStreamControl);
            co_return;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} unexpected {} udp frame {}",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label,
                     frame.h.command);
            co_return;
        }

        socks_udp_header header;
        if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} decode {} udp header failed",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label);
            co_return;
        }
        if (header.header_len > frame.payload.size())
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} {} udp header length invalid {}",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label,
                     header.header_len);
            co_return;
        }
        if (header.frag != 0x00)
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} {} udp fragment unsupported {}",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label,
                     header.frag);
            co_return;
        }
        if (header.port == 0)
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} {} udp source port invalid",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label);
            co_return;
        }

        boost::system::error_code addr_ec;
        const auto source_addr = boost::asio::ip::make_address(header.addr, addr_ec);
        if (addr_ec)
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} parse {} udp source address failed {}",
                     log_event::kMux,
                     trace_id,
                     conn_id,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     stream->id(),
                     udp_label,
                     addr_ec.message());
            co_return;
        }

        const boost::asio::ip::udp::endpoint source_endpoint(net::normalize_address(source_addr), header.port);
        const auto* payload = frame.payload.data() + header.header_len;
        const auto payload_len = frame.payload.size() - header.header_len;
        if (!(co_await send_to_client(source_endpoint, payload, payload_len)))
        {
            update_stream_close_command(stream_close_command, mux::kCmdRst);
            co_return;
        }
        last_activity_time_ms = net::now_ms();
    }
}

}    // namespace mux::session_util

#endif
