#ifndef SESSION_RESULT_H
#define SESSION_RESULT_H

#include <map>
#include <string>
#include <cstdint>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include "router.h"

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

enum class session_close_reason : uint8_t
{
    kUnknown = 0,
    kCompleted,
    kRouteBlocked,
    kIdleTimeout,
    kStopped,
    kTransportError,
};

enum class udp_close_reason : uint8_t
{
    kUnknown = 0,
    kCompleted,
    kRouteBlocked,
    kIdleTimeout,
    kStopped,
    kTransportError,
};

[[nodiscard]] inline const char* to_string(udp_close_reason reason)
{
    switch (reason)
    {
        case udp_close_reason::kUnknown:
            return "unknown";
        case udp_close_reason::kCompleted:
            return "completed";
        case udp_close_reason::kRouteBlocked:
            return "route_blocked";
        case udp_close_reason::kIdleTimeout:
            return "idle_timeout";
        case udp_close_reason::kStopped:
            return "stopped";
        case udp_close_reason::kTransportError:
            return "transport_error";
    }
    return "unknown";
}

[[nodiscard]] inline udp_close_reason finalize_udp_close_reason(udp_close_reason current, const bool completed)
{
    if (current != udp_close_reason::kUnknown)
    {
        return current;
    }
    return completed ? udp_close_reason::kCompleted : udp_close_reason::kTransportError;
}

[[nodiscard]] inline udp_close_reason stop_udp_close_reason(udp_close_reason current)
{
    if (current != udp_close_reason::kUnknown)
    {
        return current;
    }
    return udp_close_reason::kStopped;
}

[[nodiscard]] inline bool is_stopped_io_error(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor;
}

[[nodiscard]] inline const char* to_string(session_close_reason reason)
{
    switch (reason)
    {
        case session_close_reason::kUnknown:
            return "unknown";
        case session_close_reason::kCompleted:
            return "completed";
        case session_close_reason::kRouteBlocked:
            return "route_blocked";
        case session_close_reason::kIdleTimeout:
            return "idle_timeout";
        case session_close_reason::kStopped:
            return "stopped";
        case session_close_reason::kTransportError:
            return "transport_error";
    }
    return "unknown";
}

[[nodiscard]] inline session_close_reason to_session_close_reason(stream_relay_result::close_reason reason)
{
    switch (reason)
    {
        case stream_relay_result::close_reason::kUnknown:
            return session_close_reason::kUnknown;
        case stream_relay_result::close_reason::kInboundEof:
        case stream_relay_result::close_reason::kOutboundEof:
            return session_close_reason::kCompleted;
        case stream_relay_result::close_reason::kInboundError:
        case stream_relay_result::close_reason::kOutboundError:
            return session_close_reason::kTransportError;
        case stream_relay_result::close_reason::kIdleTimeout:
            return session_close_reason::kIdleTimeout;
        case stream_relay_result::close_reason::kStopped:
            return session_close_reason::kStopped;
    }
    return session_close_reason::kUnknown;
}

[[nodiscard]] inline session_close_reason to_session_close_reason(udp_close_reason reason)
{
    switch (reason)
    {
        case udp_close_reason::kUnknown:
            return session_close_reason::kUnknown;
        case udp_close_reason::kCompleted:
            return session_close_reason::kCompleted;
        case udp_close_reason::kRouteBlocked:
            return session_close_reason::kRouteBlocked;
        case udp_close_reason::kIdleTimeout:
            return session_close_reason::kIdleTimeout;
        case udp_close_reason::kStopped:
            return session_close_reason::kStopped;
        case udp_close_reason::kTransportError:
            return session_close_reason::kTransportError;
    }
    return session_close_reason::kUnknown;
}

[[nodiscard]] inline std::map<std::string, std::string> make_session_close_extra(const uint64_t duration_ms,
                                                                                  const session_close_reason close_reason)
{
    return {{"duration_ms", std::to_string(duration_ms)}, {"close_reason", to_string(close_reason)}};
}

[[nodiscard]] inline std::map<std::string, std::string> make_session_error_extra(const session_close_reason close_reason)
{
    return {{"close_reason", to_string(close_reason)}};
}

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
