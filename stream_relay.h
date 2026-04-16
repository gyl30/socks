#ifndef STREAM_RELAY_H
#define STREAM_RELAY_H

#include <cstdint>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "session_result.h"
#include "stream_relay_transport.h"

namespace relay
{

struct stream_relay_context
{
    stream_relay_transport& inbound;
    stream_relay_transport& outbound;
    boost::asio::steady_timer& idle_timer;
    const config::timeout_t& timeout;
    uint64_t trace_id = 0;
    uint32_t conn_id = 0;
    std::string_view log_event_name;
    std::string_view inbound_to_outbound_stage = "client_to_outbound";
    std::string_view outbound_to_inbound_stage = "outbound_to_client";
    uint64_t& last_activity_time_ms;
    uint64_t& tx_bytes;
    uint64_t& rx_bytes;
};

[[nodiscard]] boost::asio::awaitable<stream_relay_result> relay_streams(stream_relay_context& context);

}    // namespace relay

#endif
