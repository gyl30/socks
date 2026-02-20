// NOLINTBEGIN(misc-include-cleaner)
#include <boost/system/error_code.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <boost/system/errc.hpp>
#include <boost/system/detail/errc.hpp>
#include <string>
#include <vector>
#include <cstring>
#include <memory>
#include <expected>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "mux_tunnel.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "statistics.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "timeout_io.h"

namespace mux
{

std::expected<void, boost::system::error_code> direct_upstream::open_socket_for_endpoint(const boost::asio::ip::tcp::endpoint& endpoint)
{
    if (socket_.is_open())
    {
        boost::system::error_code close_ec;
        close_ec = socket_.close(close_ec);
    }
    boost::system::error_code ec;
    ec = socket_.open(endpoint.protocol(), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    return {};
}

void direct_upstream::apply_socket_mark()
{
    if (mark_ == 0)
    {
        return;
    }

    if (auto r = net::set_socket_mark(socket_.native_handle(), mark_); !r)
    {
        LOG_WARN("direct upstream set mark failed {}", r.error().message());
    }
}

void direct_upstream::apply_no_delay()
{
    boost::system::error_code ec;
    ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("direct upstream set no delay failed error {}", ec.message());
    }
}

boost::asio::awaitable<bool> direct_upstream::connect(const std::string& host, const std::uint16_t port)
{
    const auto timeout_sec = timeout_sec_;
    const auto resolve_res = co_await timeout_io::async_resolve_with_timeout(resolver_, host, std::to_string(port), timeout_sec);
    if (!resolve_res.ok)
    {
        auto& stats = statistics::instance();
        if (resolve_res.timed_out)
        {
            stats.inc_direct_upstream_resolve_timeouts();
            LOG_CTX_WARN(
                ctx_, "{} stage=resolve target={}:{} timeout={}s", log_event::kRoute, host, port, timeout_sec);
        }
        else
        {
            stats.inc_direct_upstream_resolve_errors();
            LOG_CTX_WARN(
                ctx_, "{} stage=resolve target={}:{} error={}", log_event::kRoute, host, port, resolve_res.ec.message());
        }
        co_return false;
    }

    boost::system::error_code last_ec;
    for (const auto& entry : resolve_res.endpoints)
    {
        if (auto open_result = open_socket_for_endpoint(entry.endpoint()); !open_result)
        {
            last_ec = open_result.error();
            continue;
        }

        apply_socket_mark();

        const auto connect_res = co_await timeout_io::async_connect_with_timeout(socket_, entry.endpoint(), timeout_sec, "direct upstream");
        if (!connect_res.ok)
        {
            if (connect_res.timed_out)
            {
                last_ec = boost::asio::error::timed_out;
                continue;
            }
            last_ec = connect_res.ec;
            continue;
        }

        apply_no_delay();
        co_return true;
    }

    const auto err = last_ec ? last_ec : boost::system::errc::make_error_code(boost::system::errc::host_unreachable);
    auto& stats = statistics::instance();
    if (err == boost::asio::error::timed_out)
    {
        stats.inc_direct_upstream_connect_timeouts();
        LOG_CTX_WARN(
            ctx_, "{} stage=connect target={}:{} timeout={}s", log_event::kRoute, host, port, timeout_sec);
    }
    else
    {
        stats.inc_direct_upstream_connect_errors();
        LOG_CTX_WARN(ctx_, "{} stage=connect target={}:{} error={}", log_event::kRoute, host, port, err.message());
    }
    co_return false;
}

boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> direct_upstream::read(std::vector<std::uint8_t>& buf)
{
    auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
    co_return std::make_pair(ec, n);
}

boost::asio::awaitable<std::size_t> direct_upstream::write(const std::vector<std::uint8_t>& data)
{
    co_return co_await write(data.data(), data.size());
}

boost::asio::awaitable<std::size_t> direct_upstream::write(const std::uint8_t* data, const std::size_t len)
{
    if (data == nullptr || len == 0)
    {
        co_return 0;
    }

    auto [ec, n] = co_await boost::asio::async_write(socket_, boost::asio::buffer(data, len), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write error {}", log_event::kRoute, ec.message());
        co_return 0;
    }
    co_return n;
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

proxy_upstream::proxy_upstream(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel, connection_context ctx)
    : ctx_(std::move(ctx)), tunnel_(std::move(tunnel))
{
}

bool proxy_upstream::is_tunnel_ready() const
{
    return tunnel_ != nullptr && tunnel_->connection() != nullptr && tunnel_->connection()->is_open();
}

boost::asio::awaitable<bool> proxy_upstream::send_syn_request(const std::shared_ptr<mux_stream>& stream,
                                                       const std::string& host,
                                                       const std::uint16_t port)
{
    const auto stream_ctx = ctx_.with_stream(stream->id());
    const syn_payload syn{.socks_cmd = socks::kCmdConnect, .addr = host, .port = port, .trace_id = ctx_.trace_id()};
    std::vector<std::uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    const auto ec = co_await tunnel_->connection()->send_async(stream->id(), kCmdSyn, std::move(syn_data));
    if (ec)
    {
        LOG_CTX_ERROR(stream_ctx, "{} stage=send_syn target={}:{} error={}", log_event::kRoute, host, port, ec.message());
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> proxy_upstream::wait_connect_ack(const std::shared_ptr<mux_stream>& stream,
                                                       const std::string& host,
                                                       const std::uint16_t port)
{
    const auto stream_ctx = ctx_.with_stream(stream->id());
    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_ERROR(stream_ctx, "{} stage=wait_ack target={}:{} error={}", log_event::kRoute, host, port, ack_ec.message());
        co_return false;
    }

    ack_payload ack{};
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack))
    {
        LOG_CTX_WARN(stream_ctx, "{} stage=decode_ack target={}:{} error=invalid_ack_payload", log_event::kRoute, host, port);
        co_return false;
    }
    if (ack.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(
            stream_ctx, "{} stage=wait_ack target={}:{} remote_rep={}", log_event::kRoute, host, port, ack.socks_rep);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<void> proxy_upstream::cleanup_stream(const std::shared_ptr<mux_stream>& stream)
{
    if (stream == nullptr)
    {
        co_return;
    }

    co_await stream->close();
    if (tunnel_ != nullptr)
    {
        tunnel_->remove_stream(stream->id());
    }
}

boost::asio::awaitable<bool> proxy_upstream::connect(const std::string& host, const std::uint16_t port)
{
    if (!is_tunnel_ready())
    {
        LOG_CTX_WARN(ctx_, "{} proxy tunnel unavailable", log_event::kRoute);
        co_return false;
    }

    auto stream = tunnel_->create_stream(ctx_.trace_id());
    if (stream == nullptr)
    {
        LOG_CTX_ERROR(ctx_, "{} create stream failed", log_event::kRoute);
        co_return false;
    }

    if (!(co_await send_syn_request(stream, host, port)))
    {
        co_await cleanup_stream(stream);
        co_return false;
    }

    if (!(co_await wait_connect_ack(stream, host, port)))
    {
        co_await cleanup_stream(stream);
        co_return false;
    }

    stream_ = std::move(stream);

    co_return true;
}

boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> proxy_upstream::read(std::vector<std::uint8_t>& buf)
{
    auto stream = stream_;
    if (stream == nullptr)
    {
        co_return std::make_pair(boost::asio::error::operation_aborted, 0);
    }

    auto [ec, data] = co_await stream->async_read_some();
    if (!ec && !data.empty())
    {
        if (buf.size() < data.size())
        {
            buf.resize(data.size());
        }
        std::memcpy(buf.data(), data.data(), data.size());
        co_return std::make_pair(ec, data.size());
    }
    co_return std::make_pair(ec, 0);
}

boost::asio::awaitable<std::size_t> proxy_upstream::write(const std::vector<std::uint8_t>& data)
{
    co_return co_await write(data.data(), data.size());
}

boost::asio::awaitable<std::size_t> proxy_upstream::write(const std::uint8_t* data, const std::size_t len)
{
    auto stream = stream_;
    if (stream == nullptr)
    {
        co_return 0;
    }
    if (data == nullptr || len == 0)
    {
        co_return 0;
    }

    auto ec = co_await stream->async_write_some(data, len);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write error {}", log_event::kRoute, ec.message());
        co_return 0;
    }
    co_return len;
}

boost::asio::awaitable<void> proxy_upstream::close()
{
    auto stream = stream_;
    stream_.reset();

    if (stream != nullptr)
    {
        co_await stream->close();
        if (tunnel_ != nullptr)
        {
            tunnel_->remove_stream(stream->id());
        }
    }
}

}    // namespace mux
// NOLINTEND(misc-include-cleaner)
