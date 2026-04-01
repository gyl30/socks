#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <cstring>
#include <algorithm>

#include <boost/asio.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_session_utils.h"
#include "scoped_exit.h"
#include "mux_protocol.h"
#include "mux_connection.h"
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
                                       const config& cfg)
    : id_(id),
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
        LOG_WARN("event {} conn_id {} stream_id {} start tcp session without stream", log_event::kMux, conn_id_, id_);
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
        LOG_WARN("event {} conn_id {} stream_id {} shutdown target send failed {}", log_event::kMux, conn_id_, id_, ec.message());
    }
}

void remote_tcp_session::close_from_reset()
{
    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("event {} conn_id {} stream_id {} close target failed {}", log_event::kMux, conn_id_, id_, ec.message());
    }
}

boost::asio::awaitable<void> remote_tcp_session::run(const syn_payload& syn)
{
    DEFER(if (auto connection = connection_.lock(); connection != nullptr && stream_ != nullptr) { connection->close_and_remove_stream(stream_); });
    DEFER(boost::system::error_code ignore; ignore = socket_.close(ignore); (void)ignore;);

    LOG_INFO("event {} conn_id {} stream_id {} target {}:{} connecting", log_event::kMux, conn_id_, id_, syn.addr, syn.port);
    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver resolver(socket_.get_executor());
    auto resolve_res = co_await net::wait_resolve_with_timeout(resolver, syn.addr, std::to_string(syn.port), cfg_.timeout.connect, ec);
    if (ec)
    {
        const auto rep = socks::map_connect_error_to_socks_rep(ec);
        LOG_WARN("event {} conn_id {} stream_id {} resolve failed target {}:{} error {} rep {}",
                 log_event::kMux,
                 conn_id_,
                 id_,
                 syn.addr,
                 syn.port,
                 ec.message(),
                 rep);
        co_await session_util::send_fail_ack(stream_, id_, rep);
        co_return;
    }
    if (resolve_res.begin() == resolve_res.end())
    {
        LOG_WARN("event {} conn_id {} stream_id {} resolve empty target {}:{} rep {}",
                 log_event::kMux,
                 conn_id_,
                 id_,
                 syn.addr,
                 syn.port,
                 socks::kRepHostUnreach);
        co_await session_util::send_fail_ack(stream_, id_, socks::kRepHostUnreach);
        co_return;
    }
    boost::system::error_code connect_ec = boost::asio::error::host_unreachable;
    for (const auto& entry : resolve_res)
    {
        if (socket_.is_open())
        {
            boost::system::error_code close_ec;
            close_ec = socket_.close(close_ec);
            (void)close_ec;
        }
        connect_ec = socket_.open(entry.endpoint().protocol(), connect_ec);
        if (connect_ec)
        {
            continue;
        }
        co_await net::wait_connect_with_timeout(socket_, entry.endpoint(), cfg_.timeout.connect, connect_ec);
        if (!connect_ec)
        {
            break;
        }
    }
    if (connect_ec)
    {
        const auto rep = socks::map_connect_error_to_socks_rep(connect_ec);
        LOG_WARN("event {} conn_id {} stream_id {} connect failed target {}:{} error {} rep {}",
                 log_event::kMux,
                 conn_id_,
                 id_,
                 syn.addr,
                 syn.port,
                 connect_ec.message(),
                 rep);
        co_await session_util::send_fail_ack(stream_, id_, rep);
        co_return;
    }
    ec.clear();

    ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} stream_id {} set_option no_delay failed {}", log_event::kMux, conn_id_, id_, ec.message());
    }
    LOG_INFO("event {} conn_id {} stream_id {} target {}:{} connected", log_event::kConnEstablished, conn_id_, id_, syn.addr, syn.port);

    boost::system::error_code local_ep_ec;
    const auto local_ep = socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_WARN("event {} conn_id {} stream_id {} local endpoint unavailable {}", log_event::kMux, conn_id_, id_, local_ep_ec.message());
        co_await session_util::send_fail_ack(stream_, id_, socks::kRepGenFail);
        co_return;
    }
    std::string bind_addr = local_ep.address().to_string();
    uint16_t bind_port = local_ep.port();

    const ack_payload ack{.socks_rep = socks::kRepSuccess, .bnd_addr = bind_addr, .bnd_port = bind_port};
    std::vector<uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        LOG_WARN("event {} conn_id {} stream_id {} send ack encode failed", log_event::kMux, conn_id_, id_);
        co_return;
    }
    mux_frame ack_frame;
    ack_frame.h.stream_id = id_;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload.swap(ack_data);
    co_await stream_->async_write(ack_frame, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} stream_id {} send ack failed {}", log_event::kMux, conn_id_, id_, ec.message());
        co_return;
    }
    LOG_INFO("event {} conn_id {} stream_id {} ack sent bind {}:{}", log_event::kMux, conn_id_, id_, bind_addr, bind_port);

    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (upstream() && downstream());
    }
    else
    {
        co_await ((upstream() && downstream()) || idle_watchdog());
    }

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} conn_id {} stream_id {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             conn_id_,
             id_,
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
            LOG_INFO("event {} conn_id {} stream_id {} upstream stream read finished {}", log_event::kMux, conn_id_, id_, ec.message());
            break;
        }
        if (frame.h.command == mux::kCmdFin)
        {
            LOG_INFO("event {} conn_id {} stream_id {} upstream recv control cmd {}({}) payload_size {}",
                     log_event::kMux,
                     conn_id_,
                     id_,
                     frame.h.command,
                     session_util::mux_command_name(frame.h.command),
                     frame.payload.size());
            close_from_fin();
            break;
        }
        if (frame.h.command == mux::kCmdRst)
        {
            LOG_INFO("event {} conn_id {} stream_id {} upstream recv control cmd {}({}) payload_size {}",
                     log_event::kMux,
                     conn_id_,
                     id_,
                     frame.h.command,
                     session_util::mux_command_name(frame.h.command),
                     frame.payload.size());
            stream_->close();
            close_from_reset();
            break;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            LOG_WARN("event {} conn_id {} stream_id {} upstream unexpected cmd {}({}) payload_size {}",
                     log_event::kMux,
                     conn_id_,
                     id_,
                     frame.h.command,
                     session_util::mux_command_name(frame.h.command),
                     frame.payload.size());
            boost::system::error_code rst_ec;
            co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("event {} conn_id {} stream_id {} upstream send rst failed {}", log_event::kMux, conn_id_, id_, rst_ec.message());
            }
            stream_->close();
            close_from_reset();
            break;
        }
        co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(frame.payload), cfg_.timeout.write, ec);
        if (ec)
        {
            LOG_WARN("event {} conn_id {} stream_id {} upstream write to target failed {}", log_event::kMux, conn_id_, id_, ec.message());
            boost::system::error_code rst_ec;
            co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("event {} conn_id {} stream_id {} upstream send rst failed {}", log_event::kMux, conn_id_, id_, rst_ec.message());
            }
            stream_->close();
            close_from_reset();
            break;
        }
        tx_bytes_ += frame.payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("event {} conn_id {} stream_id {} mux to target finished tx_bytes {}", log_event::kDataSend, conn_id_, id_, tx_bytes_);
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
                    LOG_WARN("event {} conn_id {} stream_id {} downstream send fin failed {}", log_event::kMux, conn_id_, id_, fin_ec.message());
                }
            }
            else
            {
                LOG_INFO("event {} conn_id {} stream_id {} downstream target read finished {}", log_event::kMux, conn_id_, id_, ec.message());
                boost::system::error_code rst_ec;
                co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
                if (rst_ec)
                {
                    LOG_WARN("event {} conn_id {} stream_id {} downstream send rst failed {}", log_event::kMux, conn_id_, id_, rst_ec.message());
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
            LOG_WARN("event {} conn_id {} stream_id {} downstream write to mux failed {}", log_event::kMux, conn_id_, id_, ec.message());
            stream_->close();
            close_from_reset();
            break;
        }
        rx_bytes_ += n;
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("event {} conn_id {} stream_id {} target to mux finished rx_bytes {}", log_event::kDataRecv, conn_id_, id_, rx_bytes_);
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
            LOG_WARN("event {} conn_id {} stream_id {} idle timeout {}s", log_event::kTimeout, conn_id_, id_, cfg_.timeout.idle);
            stream_->close();
            close_from_reset();
            break;
        }
    }
}

}    // namespace mux
