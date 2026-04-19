#ifndef UDP_SESSION_FLOW_H
#define UDP_SESSION_FLOW_H

#include <map>
#include <memory>
#include <string>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "request_context.h"
#include "router.h"
#include "session_result.h"
#include "trace_store.h"

namespace relay
{

boost::asio::awaitable<udp_flow_result> prepare_udp_route_flow(const request_context& request, const std::shared_ptr<router>& router);

boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_proxy_flow(const boost::asio::any_io_executor& executor,
                                                                                const request_context& request,
                                                                                const std::string& outbound_tag,
                                                                                const config& cfg);

template <typename RunFn, typename FinalizeFn>
boost::asio::awaitable<bool> finish_udp_session(RunFn run_session, udp_close_reason& close_reason, FinalizeFn finalize)
{
    const bool completed = co_await run_session();
    close_reason = finalize_udp_close_reason(close_reason, completed);
    co_await finalize(completed);
    co_return completed;
}

[[nodiscard]] inline std::map<std::string, std::string> make_udp_close_extra(const uint64_t duration_ms, const udp_close_reason close_reason)
{
    return {{"duration_ms", std::to_string(duration_ms)}, {"close_reason", to_string(close_reason)}};
}

inline void record_udp_session_close_trace(trace_event event,
                                           const uint64_t tx_bytes,
                                           const uint64_t rx_bytes,
                                           const uint64_t duration_ms,
                                           const udp_close_reason close_reason)
{
    event.stage = trace_stage::kSessionClose;
    event.result = trace_result::kOk;
    event.bytes_tx = tx_bytes;
    event.bytes_rx = rx_bytes;
    event.latency_ms = static_cast<uint32_t>(duration_ms);
    event.extra = make_udp_close_extra(duration_ms, close_reason);
    trace_store::instance().record_event(std::move(event));
}

inline void record_udp_session_error_trace(trace_event event,
                                           const udp_close_reason close_reason,
                                           const std::string& error_message = {})
{
    event.stage = trace_stage::kSessionError;
    event.result = trace_result::kFail;
    if (!error_message.empty())
    {
        event.error_message = error_message;
    }
    event.extra["close_reason"] = to_string(close_reason);
    trace_store::instance().record_event(std::move(event));
}

[[nodiscard]] inline trace_event make_transparent_udp_trace_event(const uint64_t trace_id,
                                                                  const uint32_t conn_id,
                                                                  const std::string& inbound_tag,
                                                                  const std::string& inbound_type,
                                                                  const std::string& outbound_tag,
                                                                  const std::string& outbound_type,
                                                                  const boost::asio::ip::udp::endpoint& client_endpoint,
                                                                  const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                  const std::string& route_type,
                                                                  const std::string& match_type,
                                                                  const std::string& match_value)
{
    return trace_event{
        .trace_id = trace_id,
        .conn_id = conn_id,
        .inbound_tag = inbound_tag,
        .inbound_type = inbound_type,
        .outbound_tag = outbound_tag,
        .outbound_type = outbound_type,
        .target_host = target_endpoint.address().to_string(),
        .target_port = target_endpoint.port(),
        .remote_host = client_endpoint.address().to_string(),
        .remote_port = client_endpoint.port(),
        .route_type = route_type,
        .match_type = match_type,
        .match_value = match_value,
    };
}

}    // namespace relay

#endif
