#include <algorithm>
#include <chrono>
#include <memory>
#include <vector>
#include <string>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "config.h"
#include "log.h"
#include "mux_codec.h"
#include "protocol.h"
#include "net_utils.h"
#include "scoped_exit.h"
#include "mux_connection.h"
#include "mux_protocol.h"
#include "mux_session_utils.h"
#include "remote_session.h"
namespace mux
{

namespace
{
boost::asio::awaitable<void> send_stream_control_frame(const std::shared_ptr<mux_stream>& stream,
                                                       uint8_t command,
                                                       boost::system::error_code& ec)
{
    ec.clear();
    if (stream == nullptr)
    {
        co_return;
    }

    mux_frame control_frame;
    control_frame.h.stream_id = stream->id();
    control_frame.h.command = command;
    co_await stream->async_write(control_frame, ec);
}
}    // namespace

remote_tcp_session::remote_tcp_session(boost::asio::io_context& io_context,
                                       const std::shared_ptr<mux_connection>& connection,
                                       uint32_t id,
                                       uint32_t conn_id,
                                       uint64_t trace_id,
                                       const config& cfg)
    : id_(id),
      trace_id_(trace_id),
      conn_id_(conn_id),
      cfg_(cfg),
      socket_(io_context),
      idle_timer_(io_context),
      stream_(connection != nullptr ? connection->create_incoming_stream(id) : nullptr),
      connection_(connection)
{
    last_activity_time_ms_ = net::now_ms();
}

bool remote_tcp_session::has_stream() const { return stream_ != nullptr; }

boost::asio::awaitable<void> remote_tcp_session::start(const syn_payload& syn)
{
    if (stream_ == nullptr)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} start tcp session without stream",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 syn.addr,
                 syn.port);
        co_return;
    }

    co_await run(syn);
}

void remote_tcp_session::close_from_fin()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} stage close_from_fin shutdown_send failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message());
    }
}

void remote_tcp_session::close_from_reset()
{
    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} stage close_from_reset close failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message());
    }
}

boost::asio::awaitable<void> remote_tcp_session::run(const syn_payload& syn)
{
    DEFER(if (auto connection = connection_.lock(); connection != nullptr && stream_ != nullptr) { connection->close_and_remove_stream(stream_); });
    DEFER(boost::system::error_code ignore; ignore = socket_.close(ignore); (void)ignore;);

    initialize_target(syn);
    log_connecting();

    boost::asio::ip::tcp::resolver resolver(socket_.get_executor());
    boost::asio::ip::tcp::resolver::results_type resolve_res;
    if (!(co_await resolve_target(resolver, resolve_res)))
    {
        co_return;
    }

    if (!(co_await connect_target(resolve_res)))
    {
        co_return;
    }

    if (!(co_await send_success_ack()))
    {
        co_return;
    }

    co_await relay_target();
    log_close_summary();
}

void remote_tcp_session::initialize_target(const syn_payload& syn)
{
    target_host_ = syn.addr;
    target_port_ = syn.port;
    bind_host_ = "unknown";
    bind_port_ = 0;
}

void remote_tcp_session::log_connecting() const
{
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} connecting",
             log_event::kMux,
             trace_id_,
             conn_id_,
             id_,
             target_host_,
             target_port_);
}

boost::asio::awaitable<bool> remote_tcp_session::resolve_target(boost::asio::ip::tcp::resolver& resolver,
                                                                boost::asio::ip::tcp::resolver::results_type& resolve_res)
{
    boost::system::error_code ec;
    resolve_res = co_await net::wait_resolve_with_timeout(resolver, target_host_, std::to_string(target_port_), cfg_.timeout.connect, ec);
    if (ec)
    {
        const auto rep = socks::map_connect_error_to_socks_rep(ec);
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} resolve failed target {}:{} error {} rep {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 ec.message(),
                 rep);
        co_await session_util::send_fail_ack(stream_, id_, rep);
        co_return false;
    }
    if (resolve_res.begin() == resolve_res.end())
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} resolve empty target {}:{} rep {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 socks::kRepHostUnreach);
        co_await session_util::send_fail_ack(stream_, id_, socks::kRepHostUnreach);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> remote_tcp_session::connect_target(const boost::asio::ip::tcp::resolver::results_type& resolve_res)
{
    boost::system::error_code connect_ec = boost::asio::error::host_unreachable;
    for (const auto& entry : resolve_res)
    {
        const auto endpoint = entry.endpoint();
        const auto endpoint_text = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
        if (socket_.is_open())
        {
            boost::system::error_code close_ec;
            close_ec = socket_.close(close_ec);
            (void)close_ec;
        }
        connect_ec = socket_.open(endpoint.protocol(), connect_ec);
        if (connect_ec)
        {
            LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} open endpoint {} failed {}",
                      log_event::kMux,
                      trace_id_,
                      conn_id_,
                      id_,
                      target_host_,
                      target_port_,
                      endpoint_text,
                      connect_ec.message());
            continue;
        }
        LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} connect try endpoint {}",
                  log_event::kMux,
                  trace_id_,
                  conn_id_,
                  id_,
                  target_host_,
                  target_port_,
                  endpoint_text);
        co_await net::wait_connect_with_timeout(socket_, endpoint, cfg_.timeout.connect, connect_ec);
        if (!connect_ec)
        {
            break;
        }

        boost::system::error_code local_ep_ec;
        const auto local_ep = socket_.local_endpoint(local_ep_ec);
        if (local_ep_ec)
        {
            LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} connect try endpoint {} failed {} local_ep_unavailable {}",
                      log_event::kMux,
                      trace_id_,
                      conn_id_,
                      id_,
                      target_host_,
                      target_port_,
                      endpoint_text,
                      connect_ec.message(),
                      local_ep_ec.message());
            continue;
        }

        LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} connect try endpoint {} failed {} local_ep {}",
                  log_event::kMux,
                  trace_id_,
                  conn_id_,
                  id_,
                  target_host_,
                  target_port_,
                  endpoint_text,
                  connect_ec.message(),
                  local_ep.address().to_string() + ":" + std::to_string(local_ep.port()));
    }
    if (connect_ec)
    {
        const auto rep = socks::map_connect_error_to_socks_rep(connect_ec);
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} connect failed target {}:{} error {} rep {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 connect_ec.message(),
                 rep);
        co_await session_util::send_fail_ack(stream_, id_, rep);
        co_return false;
    }

    connect_ec.clear();
    connect_ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), connect_ec);
    if (connect_ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} stage set_no_delay error {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 connect_ec.message());
    }
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} connected",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             id_,
             target_host_,
             target_port_);
    co_return true;
}

boost::asio::awaitable<bool> remote_tcp_session::send_success_ack()
{
    boost::system::error_code ec;
    const auto local_ep = socket_.local_endpoint(ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} stage query_bind_endpoint error {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 ec.message());
        co_await session_util::send_fail_ack(stream_, id_, socks::kRepGenFail);
        co_return false;
    }

    bind_host_ = local_ep.address().to_string();
    bind_port_ = local_ep.port();
    const ack_payload ack{.socks_rep = socks::kRepSuccess, .bnd_addr = bind_host_, .bnd_port = bind_port_};
    std::vector<uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} send ack encode failed",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_);
        co_return false;
    }

    mux_frame ack_frame;
    ack_frame.h.stream_id = id_;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload.swap(ack_data);
    co_await stream_->async_write(ack_frame, ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} send ack failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message());
        co_return false;
    }

    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} ack sent bind {}:{}",
             log_event::kMux,
             trace_id_,
             conn_id_,
             id_,
             target_host_,
             target_port_,
             bind_host_,
             bind_port_);
    co_return true;
}

boost::asio::awaitable<void> remote_tcp_session::relay_target()
{
    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;

    if (cfg_.timeout.idle == 0)
    {
        co_await (upstream() && downstream());
        co_return;
    }

    co_await ((upstream() && downstream()) || idle_watchdog());
}

void remote_tcp_session::log_close_summary() const
{
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             id_,
             target_host_,
             target_port_,
             bind_host_,
             bind_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<void> remote_tcp_session::upstream()
{
    boost::system::error_code ec;
    for (;;)
    {
        const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto frame = co_await stream_->async_read(read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream stream read finished {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     ec.message());
            break;
        }
        if (frame.h.command == mux::kCmdFin)
        {
            LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream recv control cmd {} cmd_name {} payload_size {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     frame.h.command,
                     session_util::mux_command_name(frame.h.command),
                     frame.payload.size());
            close_from_fin();
            break;
        }
        if (frame.h.command == mux::kCmdRst)
        {
            LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream recv control cmd {} cmd_name {} payload_size {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     frame.h.command,
                     session_util::mux_command_name(frame.h.command),
                     frame.payload.size());
            stream_->close();
            close_from_reset();
            break;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream unexpected cmd {} cmd_name {} payload_size {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     frame.h.command,
                     session_util::mux_command_name(frame.h.command),
                     frame.payload.size());
            boost::system::error_code rst_ec;
            co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream send rst failed {}",
                         log_event::kMux,
                         trace_id_,
                         conn_id_,
                         id_,
                         target_host_,
                         target_port_,
                         bind_host_,
                         bind_port_,
                         rst_ec.message());
            }
            stream_->close();
            close_from_reset();
            break;
        }
        co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(frame.payload), cfg_.timeout.write, ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream write to target failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     ec.message());
            boost::system::error_code rst_ec;
            co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} upstream send rst failed {}",
                         log_event::kMux,
                         trace_id_,
                         conn_id_,
                         id_,
                         target_host_,
                         target_port_,
                         bind_host_,
                         bind_port_,
                         rst_ec.message());
            }
            stream_->close();
            close_from_reset();
            break;
        }
        tx_bytes_ += frame.payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} mux to target finished tx_bytes {}",
             log_event::kDataSend,
             trace_id_,
             conn_id_,
             id_,
             target_host_,
             target_port_,
             bind_host_,
             bind_port_,
             tx_bytes_);
}

boost::asio::awaitable<void> remote_tcp_session::downstream()
{
    std::vector<uint8_t> buf(8192);
    for (;;)
    {
        boost::system::error_code ec;
        const std::size_t n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code fin_ec;
                co_await send_stream_control_frame(stream_, mux::kCmdFin, fin_ec);
                if (fin_ec)
                {
                    LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} downstream send fin failed {}",
                             log_event::kMux,
                             trace_id_,
                             conn_id_,
                             id_,
                             target_host_,
                             target_port_,
                             bind_host_,
                             bind_port_,
                             fin_ec.message());
                }
            }
            else
            {
                LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} downstream target read finished {}",
                         log_event::kMux,
                         trace_id_,
                         conn_id_,
                         id_,
                         target_host_,
                         target_port_,
                         bind_host_,
                         bind_port_,
                         ec.message());
                boost::system::error_code rst_ec;
                co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
                if (rst_ec)
                {
                    LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} downstream send rst failed {}",
                             log_event::kMux,
                             trace_id_,
                             conn_id_,
                             id_,
                             target_host_,
                             target_port_,
                             bind_host_,
                             bind_port_,
                             rst_ec.message());
                }
                stream_->close();
                close_from_reset();
            }
            break;
        }
        last_activity_time_ms_ = net::now_ms();
        mux_frame data_frame;
        data_frame.h.stream_id = stream_->id();
        data_frame.h.command = mux::kCmdDat;
        data_frame.payload.assign(buf.begin(), buf.begin() + static_cast<int>(n));
        co_await stream_->async_write(data_frame, ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} downstream write to mux failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     ec.message());
            stream_->close();
            close_from_reset();
            break;
        }
        rx_bytes_ += n;
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} target to mux finished rx_bytes {}",
             log_event::kDataRecv,
             trace_id_,
             conn_id_,
             id_,
             target_host_,
             target_port_,
             bind_host_,
             bind_port_,
             rx_bytes_);
}

boost::asio::awaitable<void> remote_tcp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }
    const auto idle_timeout_ms = static_cast<uint64_t>(cfg_.timeout.idle) * 1000ULL;

    while (true)
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto elapsed_ms = net::now_ms() - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} bind {}:{} idle timeout {}s",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     cfg_.timeout.idle);
            stream_->close();
            close_from_reset();
            break;
        }
    }
}

}    // namespace mux
