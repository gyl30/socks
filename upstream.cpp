#include "upstream.h"
#include <cstring>
#include "mux_codec.h"

namespace mux
{

// direct_upstream implementation

asio::awaitable<bool> direct_upstream::connect(const std::string& host, uint16_t port)
{
    auto [res_ec, eps] = co_await resolver_.async_resolve(host, std::to_string(port), asio::as_tuple(asio::use_awaitable));
    if (res_ec)
    {
        LOG_CTX_WARN(ctx_, "{} resolve failed {}", log_event::ROUTE, res_ec.message());
        co_return false;
    }

    auto [conn_ec, ep] = co_await asio::async_connect(socket_, eps, asio::as_tuple(asio::use_awaitable));
    if (conn_ec)
    {
        LOG_CTX_WARN(ctx_, "{} connect failed {}", log_event::ROUTE, conn_ec.message());
        co_return false;
    }

    std::error_code ec;
    ec = socket_.set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("direct upstream set no delay failed error {}", ec.message());
    }
    co_return true;
}

asio::awaitable<std::pair<std::error_code, size_t>> direct_upstream::read(std::vector<uint8_t>& buf)
{
    auto [ec, n] = co_await socket_.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
    co_return std::make_pair(ec, n);
}

asio::awaitable<size_t> direct_upstream::write(const std::vector<uint8_t>& data)
{
    auto [ec, n] = co_await asio::async_write(socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write error {}", log_event::ROUTE, ec.message());
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

// proxy_upstream implementation

proxy_upstream::proxy_upstream(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel, connection_context ctx)
    : ctx_(std::move(ctx)), tunnel_(std::move(tunnel))
{
}

asio::awaitable<bool> proxy_upstream::connect(const std::string& host, uint16_t port)
{
    stream_ = tunnel_->create_stream(ctx_.trace_id);
    if (!stream_)
    {
        LOG_CTX_ERROR(ctx_, "{} create stream failed", log_event::ROUTE);
        co_return false;
    }

    const syn_payload syn{.socks_cmd = socks::CMD_CONNECT, .addr = host, .port = port, .trace_id = ctx_.trace_id};
    std::vector<uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    auto ec = co_await tunnel_->connection()->send_async(stream_->id(), CMD_SYN, std::move(syn_data));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} send syn failed {}", log_event::ROUTE, ec.message());
        co_return false;
    }

    auto [ack_ec, ack_data] = co_await stream_->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} wait ack failed {}", log_event::ROUTE, ack_ec.message());
        co_return false;
    }

    ack_payload ack_pl;
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep != socks::REP_SUCCESS)
    {
        LOG_CTX_WARN(ctx_, "{} remote rejected {}", log_event::ROUTE, ack_pl.socks_rep);
        co_return false;
    }

    co_return true;
}

asio::awaitable<std::pair<std::error_code, size_t>> proxy_upstream::read(std::vector<uint8_t>& buf)
{
    auto [ec, data] = co_await stream_->async_read_some();
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

asio::awaitable<size_t> proxy_upstream::write(const std::vector<uint8_t>& data)
{
    auto ec = co_await stream_->async_write_some(data.data(), data.size());
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write error {}", log_event::ROUTE, ec.message());
        co_return 0;
    }
    co_return data.size();
}

asio::awaitable<void> proxy_upstream::close()
{
    if (stream_)
    {
        co_await stream_->close();
    }
}

}    // namespace mux
