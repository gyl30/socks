#include <chrono>
#include <limits>
#include <memory>
#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "trace_store.h"
#include "trace_id.h"
#include "constants.h"
#include "net_utils.h"
#include "request_context.h"
#include "stream_relay.h"
#include "tcp_connect_flow.h"
#include "tun_tcp_session.h"

namespace relay
{

namespace
{

void tcp_recved_all(tcp_pcb* pcb, std::size_t size)
{
    while (pcb != nullptr && size > 0)
    {
        const auto chunk = static_cast<u16_t>(std::min<std::size_t>(size, std::numeric_limits<u16_t>::max()));
        tcp_recved(pcb, chunk);
        size -= chunk;
    }
}

}    // namespace

class tun_stream_relay_transport final : public stream_relay_transport
{
   public:
    explicit tun_stream_relay_transport(tun_tcp_session& session) : session_(session) {}

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<uint8_t> buffer, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> close() override;
    void on_read_delivered(const std::size_t bytes) override;

   private:
    [[nodiscard]] boost::system::error_code make_client_io_error() const;
    [[nodiscard]] std::size_t consume_pending_read_data(std::span<uint8_t> buffer);
    void load_pending_read_data();
    void maybe_reset_pending_read_data();

   private:
    tun_tcp_session& session_;
    std::vector<uint8_t> pending_read_data_;
    std::size_t pending_read_offset_ = 0;
    std::size_t pending_read_acked_ = 0;
};

boost::system::error_code tun_stream_relay_transport::make_client_io_error() const
{
    if (session_.close_reason_ == stream_relay_result::close_reason::kInboundError)
    {
        return boost::asio::error::connection_reset;
    }
    if (session_.close_reason_ == stream_relay_result::close_reason::kInboundEof)
    {
        return boost::asio::error::eof;
    }
    return boost::asio::error::operation_aborted;
}

std::size_t tun_stream_relay_transport::consume_pending_read_data(const std::span<uint8_t> buffer)
{
    const auto remaining = pending_read_data_.size() - pending_read_offset_;
    const auto size = std::min(buffer.size(), remaining);
    std::copy_n(
        pending_read_data_.data() + static_cast<std::ptrdiff_t>(pending_read_offset_), static_cast<std::ptrdiff_t>(size), buffer.data());
    pending_read_offset_ += size;
    maybe_reset_pending_read_data();
    return size;
}

void tun_stream_relay_transport::load_pending_read_data()
{
    if (session_.queue_ == nullptr)
    {
        return;
    }

    auto* packet = session_.queue_;
    session_.queue_ = nullptr;
    pending_read_data_ = tun::pbuf_to_vector(packet);
    pbuf_free(packet);
    pending_read_offset_ = 0;
    pending_read_acked_ = 0;
}

void tun_stream_relay_transport::maybe_reset_pending_read_data()
{
    if (pending_read_offset_ == pending_read_data_.size() && pending_read_acked_ == pending_read_data_.size())
    {
        pending_read_data_.clear();
        pending_read_offset_ = 0;
        pending_read_acked_ = 0;
    }
}

boost::asio::awaitable<std::size_t> tun_stream_relay_transport::read(std::span<uint8_t> buffer, boost::system::error_code& ec)
{
    ec.clear();
    if (buffer.empty())
    {
        co_return 0;
    }

    for (;;)
    {
        if (pending_read_offset_ < pending_read_data_.size())
        {
            co_return consume_pending_read_data(buffer);
        }

        if (session_.queue_ != nullptr)
        {
            load_pending_read_data();
            continue;
        }

        if (session_.peer_eof_)
        {
            ec = boost::asio::error::eof;
            co_return 0;
        }

        if (session_.pcb_ == nullptr || session_.stopped_)
        {
            ec = make_client_io_error();
            co_return 0;
        }

        co_await session_.wait_client_event();
    }
}

boost::asio::awaitable<std::size_t> tun_stream_relay_transport::write(std::span<const uint8_t> data, boost::system::error_code& ec)
{
    ec.clear();
    if (data.empty())
    {
        co_return 0;
    }

    std::size_t offset = 0;
    while (offset < data.size())
    {
        if (session_.pcb_ == nullptr || session_.stopped_)
        {
            ec = make_client_io_error();
            co_return 0;
        }

        const auto writable = static_cast<std::size_t>(tcp_sndbuf(session_.pcb_));
        if (writable == 0)
        {
            co_await session_.wait_send_event();
            continue;
        }

        const auto chunk =
            std::min<std::size_t>({data.size() - offset, writable, static_cast<std::size_t>(std::numeric_limits<u16_t>::max())});
        const auto write_err = tcp_write(session_.pcb_,
                                         data.data() + static_cast<std::ptrdiff_t>(offset),
                                         static_cast<u16_t>(chunk),
                                         TCP_WRITE_FLAG_COPY);
        if (write_err == ERR_MEM)
        {
            co_await session_.wait_send_event();
            continue;
        }
        if (write_err != ERR_OK)
        {
            ec = boost::asio::error::connection_reset;
            co_return 0;
        }

        const auto output_err = tcp_output(session_.pcb_);
        if (output_err != ERR_OK && output_err != ERR_MEM)
        {
            ec = boost::asio::error::connection_reset;
            co_return 0;
        }

        offset += chunk;
    }

    co_return data.size();
}

boost::asio::awaitable<void> tun_stream_relay_transport::shutdown_send(boost::system::error_code& ec)
{
    ec.clear();
    if (session_.pcb_ == nullptr || session_.stopped_)
    {
        co_return;
    }

    session_.graceful_shutdown_to_client();
    co_return;
}

boost::asio::awaitable<void> tun_stream_relay_transport::close()
{
    session_.close_client_connection(true);
    co_return;
}

void tun_stream_relay_transport::on_read_delivered(const std::size_t bytes)
{
    if (bytes == 0)
    {
        return;
    }

    pending_read_acked_ += bytes;
    tcp_recved_all(session_.pcb_, bytes);
    maybe_reset_pending_read_data();
}

tun_tcp_session::tun_tcp_session(const boost::asio::any_io_executor& executor,
                                 std::shared_ptr<router> router,
                                 tcp_pcb* pcb,
                                 const uint32_t sid,
                                 std::string inbound_tag,
                                 const config& cfg,
                                 std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(sid),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      router_(std::move(router)),
      pcb_(pcb),
      on_close_(std::move(on_close)),
      idle_timer_(executor),
      client_wait_timer_(executor),
      send_wait_timer_(executor),
      client_addr_(tun::lwip_ip_to_string(pcb_->remote_ip)),
      client_port_(pcb_->remote_port),
      target_addr_(tun::lwip_ip_to_string(pcb_->local_ip)),
      target_port_(pcb_->local_port),
      last_activity_time_ms_(net::now_ms())
{
    attach_lwip_callbacks();
    tcp_nagle_disable(pcb_);
}

boost::asio::awaitable<void> tun_tcp_session::start()
{
    co_await run();
    notify_closed();
}

void tun_tcp_session::stop()
{
    if (stopped_)
    {
        return;
    }

    note_close_reason(stream_relay_result::close_reason::kStopped);
    stopped_ = true;
    close_client_connection(true);
    signal_all_events();
}

request_context tun_tcp_session::make_request_context() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kTcp,
        .command = request_command::kConnect,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .target_host = target_addr_,
        .target_port = target_port_,
        .target_ip = std::make_optional(target_addr_),
        .target_domain = std::nullopt,
        .client_host = client_addr_,
        .client_port = client_port_,
        .local_host = "",
        .local_port = 0,
    };
}

boost::asio::awaitable<bool> tun_tcp_session::connect_backend(const route_decision& decision,
                                                              const std::shared_ptr<tcp_outbound_stream>& backend)
{
    const auto route_name = decision.matched ? decision.outbound_tag : decision.outbound_type;
    const auto connect_start = std::chrono::steady_clock::now();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    const auto connect_result = co_await backend->connect(target_addr_, target_port_);
    const auto connect_latency_ms = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count());
    if (connect_result.ec)
    {
        trace_event event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tun",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = target_addr_,
            .target_port = target_port_,
            .local_host = "",
            .local_port = 0,
            .remote_host = client_addr_,
            .remote_port = client_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms = connect_latency_ms,
            .error_code = connect_result.ec.value(),
            .error_message = connect_result.ec.message(),
            .extra = {},
        };
        if (connect_result.has_resolved_target_endpoint)
        {
            event.resolved_target_host = connect_result.resolved_target_addr.to_string();
            event.resolved_target_port = connect_result.resolved_target_port;
        }
        if (connect_result.has_bind_endpoint)
        {
            event.extra["bind_host"] = connect_result.bind_addr.to_string();
            event.extra["bind_port"] = std::to_string(connect_result.bind_port);
        }
        event.extra["socks_rep"] = std::to_string(connect_result.socks_rep);
        auto session_error = event;
        session_error.stage = trace_stage::kSessionError;
        session_error.extra["close_reason"] = to_string(session_close_reason::kTransportError);
        trace_store::instance().record_event(std::move(event));
        trace_store::instance().record_event(std::move(session_error));
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} route {} connect failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_addr_,
                 client_port_,
                 target_addr_,
                 target_port_,
                 route_name,
                 connect_result.ec.message());
        co_await backend->close();
        close_client_connection(true);
        co_return false;
    }

    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {} connected",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_,
             route_name);

    trace_event connected_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = connect_latency_ms,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    };
    if (connect_result.has_resolved_target_endpoint)
    {
        connected_event.resolved_target_host = connect_result.resolved_target_addr.to_string();
        connected_event.resolved_target_port = connect_result.resolved_target_port;
    }
    trace_store::instance().record_event(std::move(connected_event));
    co_return true;
}

boost::asio::awaitable<void> tun_tcp_session::relay_backend(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    tun_stream_relay_transport inbound_transport(*this);
    stream_relay_context relay_context{
        .inbound = inbound_transport,
        .outbound = *backend,
        .idle_timer = idle_timer_,
        .timeout = cfg_.timeout,
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .log_event_name = log_event::kRoute,
        .last_activity_time_ms = last_activity_time_ms_,
        .tx_bytes = tx_bytes_,
        .rx_bytes = rx_bytes_,
    };
    const auto relay_result = co_await relay_streams(relay_context);
    close_reason_ = relay_result.reason;
}

boost::asio::awaitable<void> tun_tcp_session::finish_connected_session(
    const route_decision& decision, const std::shared_ptr<tcp_outbound_stream>& backend)
{
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRelayStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    co_await relay_backend(backend);
    co_await backend->close();
    close_client_connection(false);
    co_await wait_for_close_completion();

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    const auto session_reason = to_session_close_reason(close_reason_);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kSessionClose,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .latency_ms = static_cast<uint32_t>(duration_ms),
        .error_code = 0,
        .error_message = "",
        .extra = make_session_close_extra(duration_ms, session_reason),
    });
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} close_reason {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_,
             to_string(session_reason),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
    co_return;
}

boost::asio::awaitable<void> tun_tcp_session::run()
{
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} tun tcp accepted",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = "",
        .outbound_type = "",
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = "",
        .match_type = "",
        .match_value = "",
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = "",
        .outbound_type = "",
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = "",
        .match_type = "",
        .match_value = "",
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });

    const auto request = make_request_context();
    auto flow_result = prepare_tcp_connect_flow(request, router_, idle_timer_.get_executor(), cfg_);
    auto decision = std::move(flow_result.decision);
    const auto backend = flow_result.outbound;
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = (backend == nullptr && decision.route == route_type::kBlock) ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = "",
        .local_port = 0,
        .remote_host = client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    if (backend == nullptr)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tun",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = target_addr_,
            .target_port = target_port_,
            .local_host = "",
            .local_port = 0,
            .remote_host = client_addr_,
            .remote_port = client_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms = 0,
            .error_code = 0,
            .error_message = (decision.route == route_type::kBlock) ? "route blocked" : "outbound handler unavailable",
            .extra = make_session_error_extra((decision.route == route_type::kBlock) ? session_close_reason::kRouteBlocked
                                                                                    : session_close_reason::kTransportError),
        });
        boost::asio::steady_timer close_timer(idle_timer_.get_executor());
        close_timer.expires_after(std::chrono::milliseconds(50));
        const auto [close_wait_ec] = co_await close_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        (void)close_wait_ec;
        close_client_connection(false);
        co_await wait_for_close_completion();
        co_return;
    }

    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_,
             decision.matched ? decision.outbound_tag : decision.outbound_type);
    if (!(co_await connect_backend(decision, backend)))
    {
        co_return;
    }

    co_await finish_connected_session(decision, backend);
}

boost::asio::awaitable<void> tun_tcp_session::wait_for_close_completion()
{
    while (close_pending_ && pcb_ != nullptr && !stopped_)
    {
        co_await wait_send_event();
    }
}

boost::asio::awaitable<void> tun_tcp_session::wait_client_event()
{
    client_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    const auto [ec] = co_await client_wait_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)ec;
}

boost::asio::awaitable<void> tun_tcp_session::wait_send_event()
{
    send_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    const auto [ec] = co_await send_wait_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)ec;
}

void tun_tcp_session::signal_client_event() { client_wait_timer_.cancel(); }

void tun_tcp_session::signal_send_event() { send_wait_timer_.cancel(); }

void tun_tcp_session::signal_all_events()
{
    signal_client_event();
    signal_send_event();
    idle_timer_.cancel();
}

void tun_tcp_session::note_close_reason(const stream_relay_result::close_reason reason)
{
    if (close_reason_ == stream_relay_result::close_reason::kUnknown)
    {
        close_reason_ = reason;
    }
}

void tun_tcp_session::attach_lwip_callbacks()
{
    if (pcb_ == nullptr)
    {
        return;
    }

    tcp_arg(pcb_, this);
    tcp_recv(pcb_, &tun_tcp_session::on_recv);
    tcp_sent(pcb_, &tun_tcp_session::on_sent);
    tcp_err(pcb_, &tun_tcp_session::on_err);
    tcp_poll(pcb_, &tun_tcp_session::on_poll, 2);
}

void tun_tcp_session::detach_lwip_callbacks()
{
    if (pcb_ == nullptr)
    {
        return;
    }

    tcp_arg(pcb_, nullptr);
    tcp_recv(pcb_, nullptr);
    tcp_sent(pcb_, nullptr);
    tcp_err(pcb_, nullptr);
    tcp_poll(pcb_, nullptr, 0);
}

void tun_tcp_session::close_client_connection(const bool abort_connection)
{
    if (pcb_ == nullptr)
    {
        return;
    }

    if (abort_connection)
    {
        abort_client_connection();
        return;
    }

    if (close_pending_)
    {
        return;
    }

    detach_lwip_callbacks();
    const auto close_err = tcp_close(pcb_);
    if (close_err == ERR_OK || close_err == ERR_CLSD)
    {
        pcb_ = nullptr;
        close_pending_ = false;
        stopped_ = true;
        signal_all_events();
        return;
    }

    if (close_err == ERR_MEM)
    {
        attach_lwip_callbacks();
        close_pending_ = true;
        signal_send_event();
        return;
    }

    abort_client_connection();
}

void tun_tcp_session::abort_client_connection()
{
    if (pcb_ == nullptr)
    {
        return;
    }

    auto* pcb = pcb_;
    pcb_ = nullptr;
    close_pending_ = false;
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
    tcp_poll(pcb, nullptr, 0);
    tcp_abort(pcb);

    if (queue_ != nullptr)
    {
        pbuf_free(queue_);
        queue_ = nullptr;
    }

    stopped_ = true;
    signal_all_events();
}

void tun_tcp_session::try_finish_client_close()
{
    if (!close_pending_ || pcb_ == nullptr || stopped_)
    {
        return;
    }

    detach_lwip_callbacks();
    const auto close_err = tcp_close(pcb_);
    if (close_err == ERR_OK || close_err == ERR_CLSD)
    {
        pcb_ = nullptr;
        close_pending_ = false;
        stopped_ = true;
        signal_all_events();
        return;
    }

    if (close_err == ERR_MEM)
    {
        attach_lwip_callbacks();
        return;
    }

    if (close_err != ERR_MEM)
    {
        abort_client_connection();
    }
}

void tun_tcp_session::graceful_shutdown_to_client()
{
    if (pcb_ == nullptr)
    {
        return;
    }

    const auto shutdown_err = tcp_shutdown(pcb_, 0, 1);
    if (shutdown_err != ERR_OK && shutdown_err != ERR_CLSD)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} tcp shutdown failed {}",
                 log_event::kConnClose,
                 trace_id_,
                 conn_id_,
                 client_addr_,
                 client_port_,
                 target_addr_,
                 target_port_,
                 tun::lwip_error_message(shutdown_err));
    }
}

void tun_tcp_session::notify_closed()
{
    stop();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
}

err_t tun_tcp_session::on_recv(void* arg, tcp_pcb* pcb, pbuf* packet, const err_t err)
{
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self == nullptr)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        return ERR_OK;
    }

    if (err != ERR_OK)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        self->note_close_reason(stream_relay_result::close_reason::kInboundError);
        self->close_client_connection(true);
        return err;
    }

    if (packet == nullptr)
    {
        self->peer_eof_ = true;
        self->signal_client_event();
        return ERR_OK;
    }

    (void)pcb;
    if (self->queue_ == nullptr)
    {
        self->queue_ = packet;
    }
    else
    {
        if (self->pcb_ != nullptr && self->queue_->tot_len > TCP_WND_MAX(self->pcb_))
        {
            return ERR_WOULDBLOCK;
        }
        pbuf_cat(self->queue_, packet);
    }
    self->last_activity_time_ms_ = net::now_ms();
    self->signal_client_event();
    return ERR_OK;
}

err_t tun_tcp_session::on_sent(void* arg, tcp_pcb* pcb, const u16_t len)
{
    (void)pcb;
    (void)len;
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self != nullptr)
    {
        self->last_activity_time_ms_ = net::now_ms();
        self->try_finish_client_close();
        self->signal_send_event();
    }
    return ERR_OK;
}

void tun_tcp_session::on_err(void* arg, const err_t err)
{
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self == nullptr)
    {
        return;
    }

    self->pcb_ = nullptr;
    self->close_pending_ = false;
    self->peer_eof_ = true;
    self->stopped_ = true;
    self->note_close_reason(stream_relay_result::close_reason::kInboundError);
    self->signal_all_events();
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} lwip tcp error {}",
             log_event::kConnClose,
             self->trace_id_,
             self->conn_id_,
             self->client_addr_,
             self->client_port_,
             self->target_addr_,
             self->target_port_,
             tun::lwip_error_message(err));
}

err_t tun_tcp_session::on_poll(void* arg, tcp_pcb* pcb)
{
    (void)pcb;
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self != nullptr)
    {
        self->try_finish_client_close();
        self->signal_send_event();
    }
    return ERR_OK;
}

}    // namespace relay
