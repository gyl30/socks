#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "timeout_io.h"
#include "scoped_exit.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "remote_session.h"

namespace mux
{

namespace
{

[[nodiscard]] const char* mux_command_name(const std::uint8_t cmd)
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

[[nodiscard]] std::uint8_t map_connect_error_to_socks_rep(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::connection_refused)
    {
        return socks::kRepConnRefused;
    }
    if (ec == boost::asio::error::network_unreachable)
    {
        return socks::kRepNetUnreach;
    }
    if (ec == boost::asio::error::host_unreachable || ec == boost::asio::error::host_not_found || ec == boost::asio::error::host_not_found_try_again)
    {
        return socks::kRepHostUnreach;
    }
    if (ec == boost::asio::error::timed_out)
    {
        return socks::kRepTtlExpired;
    }
    return socks::kRepGenFail;
}

}    // namespace

boost::asio::awaitable<void> send_stream_control_frame(const std::shared_ptr<mux_stream>& stream,
                                                       const std::uint8_t command,
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

remote_tcp_session::remote_tcp_session(const std::shared_ptr<mux_connection>& connection,
                                       const std::uint32_t id,
                                       const connection_context& ctx,
                                       const config& cfg)
    : id_(id),
      cfg_(cfg),
      socket_(connection->io_context()),
      idle_timer_(connection->io_context()),
      stream_(std::make_shared<mux_stream>(id, cfg, connection->io_context(), connection)),
      connection_(connection)
{
    ctx_ = ctx;
    ctx_.stream_id(id);
    last_activity_time_ms_ = timeout_io::now_ms();
    if (connection != nullptr)
    {
        connection->register_stream(stream_);
    }
}

boost::asio::awaitable<void> remote_tcp_session::start(const syn_payload& syn)
{
    co_await run(syn);
}

void remote_tcp_session::close_from_fin()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_CTX_WARN(ctx_, "{} shutdown target send failed {}", log_event::kMux, ec.message());
    }
}

void remote_tcp_session::close_from_reset()
{
    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close target failed {}", log_event::kMux, ec.message());
    }
}

boost::asio::awaitable<void> remote_tcp_session::run(const syn_payload& syn)
{
    DEFER(if (auto connection = connection_.lock(); connection != nullptr && stream_ != nullptr) { connection->close_and_remove_stream(stream_); });
    DEFER(boost::system::error_code ignore; ignore = socket_.close(ignore); (void)ignore;);

    ctx_.set_target(syn.addr, syn.port);
    LOG_CTX_INFO(ctx_, "{} connecting {} {}", log_event::kMux, syn.addr, syn.port);
    boost::system::error_code ec;
    const auto send_fail_ack = [&](const std::uint8_t rep) -> boost::asio::awaitable<void>
    {
        ack_payload ack{.socks_rep = rep, .bnd_addr = "0.0.0.0", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        if (!mux_codec::encode_ack(ack, ack_data))
        {
            co_return;
        }

        mux_frame ack_frame;
        ack_frame.h.stream_id = id_;
        ack_frame.h.command = mux::kCmdAck;
        ack_frame.payload = std::move(ack_data);
        boost::system::error_code ack_ec;
        co_await stream_->async_write(ack_frame, ack_ec);
    };
    boost::asio::ip::tcp::resolver resolver_(socket_.get_executor());
    auto resolve_res = co_await timeout_io::wait_resolve_with_timeout(resolver_, syn.addr, std::to_string(syn.port), cfg_.timeout.connect, ec);
    if (ec)
    {
        const auto rep = map_connect_error_to_socks_rep(ec);
        LOG_CTX_WARN(ctx_, "{} resolve failed target {}:{} error {} rep {}", log_event::kMux, syn.addr, syn.port, ec.message(), rep);
        co_await send_fail_ack(rep);
        co_return;
    }
    if (resolve_res.begin() == resolve_res.end())
    {
        LOG_CTX_WARN(ctx_, "{} resolve empty target {}:{} rep {}", log_event::kMux, syn.addr, syn.port, socks::kRepHostUnreach);
        co_await send_fail_ack(socks::kRepHostUnreach);
        co_return;
    }
    boost::system::error_code connect_ec = boost::asio::error::host_unreachable;
    for (const auto& entry : resolve_res)
    {
        if (socket_.is_open())
        {
            boost::system::error_code close_ec;
            close_ec = socket_.close(close_ec);
        }
        connect_ec = socket_.open(entry.endpoint().protocol(), connect_ec);
        if (connect_ec)
        {
            continue;
        }
        co_await timeout_io::wait_connect_with_timeout(socket_, entry.endpoint(), cfg_.timeout.connect, connect_ec);
        if (!connect_ec)
        {
            break;
        }
    }
    if (connect_ec)
    {
        const auto rep = map_connect_error_to_socks_rep(connect_ec);
        LOG_CTX_WARN(ctx_, "{} connect failed target {}:{} error {} rep {}", log_event::kMux, syn.addr, syn.port, connect_ec.message(), rep);
        co_await send_fail_ack(rep);
        co_return;
    }
    ec.clear();

    ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "set_option no_delay failed {}", ec.message());
    }
    LOG_CTX_INFO(ctx_, "{} connected {} {}", log_event::kConnEstablished, syn.addr, syn.port);

    boost::system::error_code local_ep_ec;
    const auto local_ep = socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_CTX_WARN(ctx_, "{} local endpoint unavailable {}", log_event::kMux, local_ep_ec.message());
        co_await send_fail_ack(socks::kRepGenFail);
        co_return;
    }
    std::string bind_addr = local_ep.address().to_string();
    uint16_t bind_port = local_ep.port();

    const ack_payload ack{.socks_rep = socks::kRepSuccess, .bnd_addr = bind_addr, .bnd_port = bind_port};
    std::vector<std::uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        LOG_CTX_WARN(ctx_, "{} send ack encode failed", log_event::kMux);
        co_return;
    }
    mux_frame ack_frame;
    ack_frame.h.stream_id = id_;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload.swap(ack_data);
    co_await stream_->async_write(ack_frame, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ec.message());
        co_return;
    }
    LOG_CTX_INFO(ctx_, "{} ack sent stream {} bind {} {}", log_event::kMux, id_, bind_addr, bind_port);

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

    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
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
            LOG_CTX_INFO(ctx_, "{} upstream stream read finished {}", log_event::kMux, ec.message());
            break;
        }
        if (frame.h.command == mux::kCmdFin)
        {
            LOG_CTX_INFO(ctx_,
                         "{} upstream recv control cmd {}({}) payload_size {}",
                         log_event::kMux,
                         frame.h.command,
                         mux_command_name(frame.h.command),
                         frame.payload.size());
            close_from_fin();
            break;
        }
        if (frame.h.command == mux::kCmdRst)
        {
            LOG_CTX_INFO(ctx_,
                         "{} upstream recv control cmd {}({}) payload_size {}",
                         log_event::kMux,
                         frame.h.command,
                         mux_command_name(frame.h.command),
                         frame.payload.size());
            stream_->close();
            close_from_reset();
            break;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            LOG_CTX_WARN(ctx_,
                         "{} upstream unexpected cmd {}({}) payload_size {}",
                         log_event::kMux,
                         frame.h.command,
                         mux_command_name(frame.h.command),
                         frame.payload.size());
            boost::system::error_code rst_ec;
            co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
            if (rst_ec)
            {
                LOG_CTX_WARN(ctx_, "{} upstream send rst failed {}", log_event::kMux, rst_ec.message());
            }
            stream_->close();
            close_from_reset();
            break;
        }
        co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(frame.payload), cfg_.timeout.write, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} upstream write to target failed {}", log_event::kMux, ec.message());
            boost::system::error_code rst_ec;
            co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
            if (rst_ec)
            {
                LOG_CTX_WARN(ctx_, "{} upstream send rst failed {}", log_event::kMux, rst_ec.message());
            }
            stream_->close();
            close_from_reset();
            break;
        }
        last_activity_time_ms_ = timeout_io::now_ms();
    }
    LOG_CTX_INFO(ctx_, "{} mux to target finished", log_event::kDataSend);
}

boost::asio::awaitable<void> remote_tcp_session::downstream()
{
    std::vector<std::uint8_t> buf(8192);
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
                    LOG_CTX_WARN(ctx_, "{} downstream send fin failed {}", log_event::kMux, fin_ec.message());
                }
            }
            else
            {
                LOG_CTX_INFO(ctx_, "{} downstream target read finished {}", log_event::kMux, ec.message());
                boost::system::error_code rst_ec;
                co_await send_stream_control_frame(stream_, mux::kCmdRst, rst_ec);
                if (rst_ec)
                {
                    LOG_CTX_WARN(ctx_, "{} downstream send rst failed {}", log_event::kMux, rst_ec.message());
                }
                stream_->close();
                close_from_reset();
            }
            break;
        }
        last_activity_time_ms_ = timeout_io::now_ms();
        mux_frame data_frame;
        data_frame.h.stream_id = stream_->id();
        data_frame.h.command = mux::kCmdDat;
        data_frame.payload.assign(buf.begin(), buf.begin() + static_cast<int>(n));
        co_await stream_->async_write(data_frame, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} downstream write to mux failed {}", log_event::kMux, ec.message());
            stream_->close();
            close_from_reset();
            break;
        }
        last_activity_time_ms_ = timeout_io::now_ms();
    }
    LOG_CTX_INFO(ctx_, "{} target to mux finished", log_event::kDataRecv);
}

boost::asio::awaitable<void> remote_tcp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }
    const auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;

    while (true)
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto elapsed_ms = timeout_io::now_ms() - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} idle timeout {}s", log_event::kTimeout, cfg_.timeout.idle);
            stream_->close();
            close_from_reset();
            break;
        }
    }
}

}    // namespace mux
