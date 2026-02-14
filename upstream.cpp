#include <string>
#include <vector>
#include <cstring>
#include <expected>
#include <utility>
#include <system_error>

#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/connect.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "log_context.h"
#include "mux_protocol.h"

namespace mux
{

std::expected<void, std::error_code> direct_upstream::open_socket_for_endpoint(const asio::ip::tcp::endpoint& endpoint)
{
    if (socket_.is_open())
    {
        std::error_code close_ec;
        socket_.close(close_ec);
    }
    std::error_code ec;
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
    std::error_code ec;
    ec = socket_.set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("direct upstream set no delay failed error {}", ec.message());
    }
}

asio::awaitable<bool> direct_upstream::connect(const std::string& host, const std::uint16_t port)
{
    auto [res_ec, eps] = co_await resolver_.async_resolve(host, std::to_string(port), asio::as_tuple(asio::use_awaitable));
    if (res_ec)
    {
        LOG_CTX_WARN(ctx_, "{} resolve failed {}", log_event::kRoute, res_ec.message());
        co_return false;
    }

    std::error_code last_ec;
    for (const auto& entry : eps)
    {
        if (auto open_result = open_socket_for_endpoint(entry.endpoint()); !open_result)
        {
            last_ec = open_result.error();
            continue;
        }

        apply_socket_mark();

        auto [conn_ec] = co_await socket_.async_connect(entry.endpoint(), asio::as_tuple(asio::use_awaitable));
        if (conn_ec)
        {
            last_ec = conn_ec;
            continue;
        }

        apply_no_delay();
        co_return true;
    }

    const auto err = last_ec ? last_ec : std::make_error_code(std::errc::host_unreachable);
    LOG_CTX_WARN(ctx_, "{} connect failed {}", log_event::kRoute, err.message());
    co_return false;
}

asio::awaitable<std::pair<std::error_code, std::size_t>> direct_upstream::read(std::vector<std::uint8_t>& buf)
{
    auto [ec, n] = co_await socket_.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
    co_return std::make_pair(ec, n);
}

asio::awaitable<std::size_t> direct_upstream::write(const std::vector<std::uint8_t>& data)
{
    auto [ec, n] = co_await asio::async_write(socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write error {}", log_event::kRoute, ec.message());
        co_return 0;
    }
    co_return n;
}

asio::awaitable<void> direct_upstream::close()
{
    std::error_code ec;
    ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
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

proxy_upstream::proxy_upstream(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel, connection_context ctx)
    : ctx_(std::move(ctx)), tunnel_(std::move(tunnel))
{
}

bool proxy_upstream::is_tunnel_ready() const
{
    return tunnel_ != nullptr && tunnel_->connection() != nullptr && tunnel_->connection()->is_open();
}

asio::awaitable<bool> proxy_upstream::send_syn_request(const std::shared_ptr<mux_stream>& stream,
                                                       const std::string& host,
                                                       const std::uint16_t port)
{
    const syn_payload syn{.socks_cmd = socks::kCmdConnect, .addr = host, .port = port, .trace_id = ctx_.trace_id()};
    std::vector<std::uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    const auto ec = co_await tunnel_->connection()->send_async(stream->id(), kCmdSyn, std::move(syn_data));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} send syn failed {}", log_event::kRoute, ec.message());
        co_return false;
    }
    co_return true;
}

asio::awaitable<bool> proxy_upstream::wait_connect_ack(const std::shared_ptr<mux_stream>& stream)
{
    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} wait ack failed {}", log_event::kRoute, ack_ec.message());
        co_return false;
    }

    ack_payload ack;
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack) || ack.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(ctx_, "{} remote rejected {}", log_event::kRoute, ack.socks_rep);
        co_return false;
    }
    co_return true;
}

asio::awaitable<void> proxy_upstream::cleanup_stream(const std::shared_ptr<mux_stream>& stream)
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

asio::awaitable<bool> proxy_upstream::connect(const std::string& host, const std::uint16_t port)
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

    if (!(co_await wait_connect_ack(stream)))
    {
        co_await cleanup_stream(stream);
        co_return false;
    }

    stream_ = std::move(stream);

    co_return true;
}

asio::awaitable<std::pair<std::error_code, std::size_t>> proxy_upstream::read(std::vector<std::uint8_t>& buf)
{
    auto stream = stream_;
    if (stream == nullptr)
    {
        co_return std::make_pair(asio::error::operation_aborted, 0);
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

asio::awaitable<std::size_t> proxy_upstream::write(const std::vector<std::uint8_t>& data)
{
    auto stream = stream_;
    if (stream == nullptr)
    {
        co_return 0;
    }

    auto ec = co_await stream->async_write_some(data.data(), data.size());
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write error {}", log_event::kRoute, ec.message());
        co_return 0;
    }
    co_return data.size();
}

asio::awaitable<void> proxy_upstream::close()
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
