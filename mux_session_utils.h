#ifndef MUX_SESSION_UTILS_H
#define MUX_SESSION_UTILS_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "log.h"
#include "mux_codec.h"
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

}    // namespace mux::session_util

#endif
