#include <iostream>
#include <optional>
#include <string>

#include <boost/asio/error.hpp>

#include "session_result.h"
#include "trace_store.h"

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

std::optional<relay::trace_session_summary> load_summary(const uint64_t trace_id)
{
    const auto snapshot = relay::trace_store::instance().get_trace(trace_id);
    if (!snapshot.has_value())
    {
        return std::nullopt;
    }
    return snapshot->summary;
}

relay::trace_event make_close_event(const uint64_t trace_id,
                                    const relay::stream_relay_result::close_reason close_reason,
                                    const boost::system::error_code& ec)
{
    const auto close_trace = relay::make_session_close_trace_info(close_reason, ec);
    return relay::trace_event{
        .trace_id = trace_id,
        .conn_id = static_cast<uint32_t>(trace_id),
        .stage = relay::trace_stage::kSessionClose,
        .result = close_trace.result,
        .inbound_tag = "test-in",
        .inbound_type = "test",
        .target_host = "example.com",
        .target_port = 443,
        .error_code = close_trace.error_code,
        .error_message = close_trace.error_message,
        .extra = relay::make_session_close_extra(123, close_trace.close_reason),
    };
}

bool test_transport_error_close()
{
    const uint64_t trace_id = 0x7100000000000001ULL;
    relay::trace_store::instance().record_event(make_close_event(
        trace_id, relay::stream_relay_result::close_reason::kOutboundError, boost::asio::error::connection_reset));
    const auto summary = load_summary(trace_id);
    if (!require(summary.has_value(), "transport_error_close missing trace summary"))
    {
        return false;
    }
    return require(summary->status == relay::trace_status::kFailed, "transport_error_close expected failed status") &&
           require(summary->final_error_code == make_error_code(boost::asio::error::connection_reset).value(),
                   "transport_error_close expected connection_reset error code") &&
           require(summary->final_error_message == make_error_code(boost::asio::error::connection_reset).message(),
                   "transport_error_close expected connection_reset error message");
}

bool test_idle_timeout_close()
{
    const uint64_t trace_id = 0x7100000000000002ULL;
    relay::trace_store::instance().record_event(
        make_close_event(trace_id, relay::stream_relay_result::close_reason::kIdleTimeout, boost::asio::error::timed_out));
    const auto summary = load_summary(trace_id);
    if (!require(summary.has_value(), "idle_timeout_close missing trace summary"))
    {
        return false;
    }
    return require(summary->status == relay::trace_status::kTimeout, "idle_timeout_close expected timeout status") &&
           require(summary->final_error_code == make_error_code(boost::asio::error::timed_out).value(),
                   "idle_timeout_close expected timed_out error code") &&
           require(summary->final_error_message == make_error_code(boost::asio::error::timed_out).message(),
                   "idle_timeout_close expected timed_out error message");
}

bool test_completed_close()
{
    const uint64_t trace_id = 0x7100000000000003ULL;
    relay::trace_store::instance().record_event(
        make_close_event(trace_id, relay::stream_relay_result::close_reason::kInboundEof, {}));
    const auto summary = load_summary(trace_id);
    if (!require(summary.has_value(), "completed_close missing trace summary"))
    {
        return false;
    }
    return require(summary->status == relay::trace_status::kSuccess, "completed_close expected success status") &&
           require(summary->final_error_code == 0, "completed_close expected zero error code") &&
           require(summary->final_error_message.empty(), "completed_close expected empty error message");
}

}    // namespace

int main()
{
    const bool ok = test_transport_error_close() && test_idle_timeout_close() && test_completed_close();
    return ok ? 0 : 1;
}
