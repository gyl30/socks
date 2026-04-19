#ifndef SESSION_RESULT_H
#define SESSION_RESULT_H

#include <cstdint>
#include <memory>

#include <boost/system/error_code.hpp>

#include "router.h"
#include "tcp_outbound_stream.h"

namespace relay
{

struct stream_relay_result
{
    enum class close_reason : uint8_t
    {
        kUnknown = 0,
        kInboundEof,
        kOutboundEof,
        kInboundError,
        kOutboundError,
        kIdleTimeout,
        kStopped,
    };

    enum class close_action : uint8_t
    {
        kNone = 0,
        kShutdownSend,
        kClose,
        kAbort,
    };

    struct close_policy
    {
        close_action inbound_action = close_action::kNone;
        close_action outbound_action = close_action::kNone;
    };

    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    uint64_t duration_ms = 0;
    boost::system::error_code ec;
    close_reason reason = close_reason::kUnknown;
};

[[nodiscard]] inline const char* to_string(stream_relay_result::close_reason reason)
{
    switch (reason)
    {
        case stream_relay_result::close_reason::kUnknown:
            return "unknown";
        case stream_relay_result::close_reason::kInboundEof:
            return "inbound_eof";
        case stream_relay_result::close_reason::kOutboundEof:
            return "outbound_eof";
        case stream_relay_result::close_reason::kInboundError:
            return "inbound_error";
        case stream_relay_result::close_reason::kOutboundError:
            return "outbound_error";
        case stream_relay_result::close_reason::kIdleTimeout:
            return "idle_timeout";
        case stream_relay_result::close_reason::kStopped:
            return "stopped";
    }
    return "unknown";
}

[[nodiscard]] inline stream_relay_result::close_policy default_close_policy(stream_relay_result::close_reason reason)
{
    using close_action = stream_relay_result::close_action;
    using close_reason = stream_relay_result::close_reason;

    switch (reason)
    {
        case close_reason::kUnknown:
            return {};
        case close_reason::kInboundEof:
            return {.inbound_action = close_action::kNone, .outbound_action = close_action::kShutdownSend};
        case close_reason::kOutboundEof:
            return {.inbound_action = close_action::kShutdownSend, .outbound_action = close_action::kNone};
        case close_reason::kInboundError:
        case close_reason::kOutboundError:
        case close_reason::kIdleTimeout:
        case close_reason::kStopped:
            return {.inbound_action = close_action::kClose, .outbound_action = close_action::kClose};
    }
    return {};
}

struct tcp_flow_result
{
    route_decision decision;
    std::shared_ptr<tcp_outbound_stream> stream;
    tcp_outbound_connect_result connect_result;
};

enum class udp_flow_mode : uint8_t
{
    kBlock,
    kDirect,
    kProxy
};

struct udp_flow_result
{
    route_decision decision;
    udp_flow_mode mode = udp_flow_mode::kBlock;
};

}    // namespace relay

#endif
