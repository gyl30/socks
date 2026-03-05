#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <utility>
#include <expected>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/errc.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/detail/errc.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "timeout_io.h"
#include "log_context.h"
#include "mux_protocol.h"

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

}    // namespace

boost::asio::awaitable<void> direct_upstream::connect(const std::string& host, const std::uint16_t port, boost::system::error_code& ec)
{
    auto endpoints = co_await timeout_io::wait_resolve_with_timeout(resolver_, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        auto& stats = statistics::instance();
        stats.inc_direct_upstream_resolve_errors();
        LOG_CTX_WARN(ctx_, "{} stage=resolve target={}:{} error={}", log_event::kRoute, host, port, ec.message());
        co_return;
    }

    boost::system::error_code last_ec = boost::asio::error::host_unreachable;
    for (const auto& entry : endpoints)
    {
        if (socket_.is_open())
        {
            boost::system::error_code close_ec;
            close_ec = socket_.close(close_ec);
        }
        boost::system::error_code op_ec;
        op_ec = socket_.open(entry.endpoint().protocol(), op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }
        const auto connect_mark = cfg_.tproxy.enabled ? cfg_.tproxy.mark : 0U;
        if (connect_mark != 0)
        {
            if (auto r = net::set_socket_mark(socket_.native_handle(), connect_mark); !r)
            {
                last_ec = r.error();
                continue;
            }
        }

        co_await timeout_io::wait_connect_with_timeout(socket_, entry.endpoint(), cfg_.timeout.connect, op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }
        op_ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), op_ec);
        if (op_ec)
        {
            LOG_WARN("direct upstream set no delay failed error {}", op_ec.message());
        }
        ec.clear();
        co_return;
    }
    ec = last_ec;
}

boost::asio::awaitable<std::size_t> direct_upstream::read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec)
{
    auto n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    co_return n;
}

bool direct_upstream::get_bind_endpoint(boost::asio::ip::address& addr, std::uint16_t& port, boost::system::error_code& ec) const
{
    const auto local_ep = socket_.local_endpoint(ec);
    if (ec)
    {
        return false;
    }
    addr = socks_codec::normalize_ip_address(local_ep.address());
    port = local_ep.port();
    return true;
}

boost::asio::awaitable<void> direct_upstream::write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec)
{
    co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(data), cfg_.timeout.write, ec);
}

boost::asio::awaitable<void> direct_upstream::close()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec)
    {
        LOG_WARN("direct upstream shutdown failed error {}", ec.message());
    }
    ec = socket_.close(ec);
    if (ec)
    {
        LOG_WARN("direct upstream close failed error {}", ec.message());
    }
    co_return;
}

proxy_upstream::proxy_upstream(std::shared_ptr<mux_tunnel_impl> tunnel, connection_context ctx)
    : ctx_(std::move(ctx)), tunnel_(std::move(tunnel))
{
}

boost::asio::awaitable<void> proxy_upstream::send_syn_request(const std::shared_ptr<mux_stream>& stream,
                                                              const std::string& host,
                                                              const std::uint16_t port,
                                                              boost::system::error_code& ec)
{
    const auto stream_ctx = ctx_.with_stream(stream->id());
    const syn_payload syn{.socks_cmd = socks::kCmdConnect, .addr = host, .port = port, .trace_id = ctx_.trace_id()};
    std::vector<std::uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        LOG_CTX_ERROR(stream_ctx, "{} stage=send_syn target={}:{} encode failed", log_event::kRoute, host, port);
        co_return;
    }
    mux_frame syn_frame;
    syn_frame.h.stream_id = stream->id();
    syn_frame.h.command = kCmdSyn;
    syn_frame.payload = std::move(syn_data);
    LOG_CTX_DEBUG(stream_ctx,
                  "{} stage=send_syn stream={} target={}:{} payload_size={}",
                  log_event::kRoute,
                  stream->id(),
                  host,
                  port,
                  syn_frame.payload.size());
    co_await stream->async_write(syn_frame, ec);
    if (ec)
    {
        LOG_CTX_ERROR(stream_ctx, "{} stage=send_syn target={}:{} error={}", log_event::kRoute, host, port, ec.message());
        co_return;
    }
}

boost::asio::awaitable<bool> proxy_upstream::wait_connect_ack(const std::shared_ptr<mux_stream>& stream,
                                                              const std::string& host,
                                                              const std::uint16_t port)
{
    const auto stream_ctx = ctx_.with_stream(stream->id());
    boost::system::error_code ack_ec;
    auto ack_frame = co_await stream->async_read(ack_ec);
    if (ack_ec)
    {
        LOG_CTX_ERROR(stream_ctx, "{} stage=wait_ack target={}:{} error={}", log_event::kRoute, host, port, ack_ec.message());
        co_return false;
    }
    if (ack_frame.h.command != kCmdAck)
    {
        LOG_CTX_WARN(stream_ctx,
                     "{} stage=wait_ack target={}:{} unexpected_cmd={}({}) payload_size={}",
                     log_event::kRoute,
                     host,
                     port,
                     ack_frame.h.command,
                     mux_command_name(ack_frame.h.command),
                     ack_frame.payload.size());
        co_return false;
    }

    ack_payload ack{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack))
    {
        LOG_CTX_WARN(stream_ctx, "{} stage=decode_ack target={}:{} error=invalid_ack_payload", log_event::kRoute, host, port);
        co_return false;
    }
    if (ack.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(stream_ctx, "{} stage=wait_ack target={}:{} remote_rep={}", log_event::kRoute, host, port, ack.socks_rep);
        co_return false;
    }

    boost::system::error_code bind_ec;
    const auto bind_addr = boost::asio::ip::make_address(ack.bnd_addr, bind_ec);
    if (bind_ec)
    {
        LOG_CTX_WARN(stream_ctx, "{} stage=wait_ack target={}:{} invalid_bind_addr={}", log_event::kRoute, host, port, ack.bnd_addr);
    }
    else
    {
        bind_addr_ = socks_codec::normalize_ip_address(bind_addr);
        bind_port_ = ack.bnd_port;
        has_bind_endpoint_ = true;
    }

    LOG_CTX_INFO(stream_ctx,
                 "{} stage=wait_ack target={}:{} bind={}:{}",
                 log_event::kRoute,
                 host,
                 port,
                 ack.bnd_addr,
                 ack.bnd_port);
    co_return true;
}

boost::asio::awaitable<void> proxy_upstream::connect(const std::string& host, const std::uint16_t port, boost::system::error_code& ec)
{
    if (tunnel_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_CTX_ERROR(ctx_, "{} create stream failed no tunnel", log_event::kRoute);
        co_return;
    }

    auto stream = tunnel_->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::connection_aborted;
        LOG_CTX_ERROR(ctx_, "{} create stream failed", log_event::kRoute);
        co_return;
    }
    has_bind_endpoint_ = false;
    bind_port_ = 0;
    co_await send_syn_request(stream, host, port, ec);
    if (ec)
    {
        tunnel_->remove_stream(stream);
        co_return;
    }

    if (!(co_await wait_connect_ack(stream, host, port)))
    {
        ec = boost::asio::error::connection_refused;
        tunnel_->remove_stream(stream);
        co_return;
    }

    stream_ = std::move(stream);
}

boost::asio::awaitable<std::size_t> proxy_upstream::read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec)
{
    if (stream_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return 0;
    }

    auto data_frame = co_await stream_->async_read(ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_.with_stream(stream_->id()), "{} stage=read_frame error={}", log_event::kRoute, ec.message());
        co_return 0;
    }
    if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
    {
        LOG_CTX_INFO(ctx_.with_stream(stream_->id()),
                     "{} stage=read_frame recv_control cmd={}({}) payload_size={}",
                     log_event::kRoute,
                     data_frame.h.command,
                     mux_command_name(data_frame.h.command),
                     data_frame.payload.size());
        ec = boost::asio::error::eof;
        co_return 0;
    }
    if (data_frame.h.command != mux::kCmdDat)
    {
        LOG_CTX_WARN(ctx_.with_stream(stream_->id()),
                     "{} stage=read_frame unexpected_cmd={}({}) payload_size={}",
                     log_event::kRoute,
                     data_frame.h.command,
                     mux_command_name(data_frame.h.command),
                     data_frame.payload.size());
        ec = boost::asio::error::invalid_argument;
        co_return 0;
    }

    if (buf.size() < data_frame.payload.size())
    {
        buf.resize(data_frame.payload.size());
    }
    std::copy(data_frame.payload.begin(), data_frame.payload.end(), buf.begin());
    co_return data_frame.payload.size();
}

boost::asio::awaitable<void> proxy_upstream::write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec)
{
    mux_frame data_frame;
    data_frame.h.stream_id = stream_->id();
    data_frame.h.command = mux::kCmdDat;
    data_frame.payload = data;
    co_return co_await stream_->async_write(data_frame, ec);
}

bool proxy_upstream::get_bind_endpoint(boost::asio::ip::address& addr, std::uint16_t& port, boost::system::error_code& ec) const
{
    if (!has_bind_endpoint_)
    {
        ec = boost::asio::error::not_connected;
        return false;
    }
    ec.clear();
    addr = bind_addr_;
    port = bind_port_;
    return true;
}

boost::asio::awaitable<void> proxy_upstream::close()
{
    if (stream_ != nullptr && tunnel_ != nullptr)
    {
        boost::system::error_code fin_ec;
        mux_frame fin_frame;
        fin_frame.h.stream_id = stream_->id();
        fin_frame.h.command = mux::kCmdFin;
        co_await stream_->async_write(fin_frame, fin_ec);
        if (fin_ec)
        {
            LOG_CTX_WARN(ctx_.with_stream(stream_->id()), "{} stage=send_fin error={}", log_event::kRoute, fin_ec.message());
        }
        tunnel_->remove_stream(stream_);
    }
    stream_.reset();
    co_return;
}

}    // namespace mux
