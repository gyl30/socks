#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <vector>
#include <memory>
#include <asio.hpp>
#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "mux_protocol.h"

namespace mux
{

class upstream
{
   public:
    virtual ~upstream() = default;

    [[nodiscard]] virtual asio::awaitable<bool> connect(const std::string& host, uint16_t port) = 0;

    [[nodiscard]] virtual asio::awaitable<std::pair<std::error_code, size_t>> read(std::vector<uint8_t>& buf) = 0;

    [[nodiscard]] virtual asio::awaitable<size_t> write(const std::vector<uint8_t>& data) = 0;

    virtual asio::awaitable<void> close() = 0;
};

class direct_upstream : public upstream
{
   public:
    explicit direct_upstream(const asio::any_io_executor& ex) : socket_(ex), resolver_(ex) {}

    asio::awaitable<bool> connect(const std::string& host, uint16_t port) override
    {
        auto [res_ec, eps] = co_await resolver_.async_resolve(host, std::to_string(port), asio::as_tuple(asio::use_awaitable));
        if (res_ec)
        {
            LOG_WARN("direct upstream resolve failed error {}", res_ec.message());
            co_return false;
        }

        auto [conn_ec, ep] = co_await asio::async_connect(socket_, eps, asio::as_tuple(asio::use_awaitable));
        if (conn_ec)
        {
            LOG_WARN("direct upstream connect failed error {}", conn_ec.message());
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

    asio::awaitable<std::pair<std::error_code, size_t>> read(std::vector<uint8_t>& buf) override
    {
        auto [ec, n] = co_await socket_.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        co_return std::make_pair(ec, n);
    }

    asio::awaitable<size_t> write(const std::vector<uint8_t>& data) override
    {
        auto [ec, n] = co_await asio::async_write(socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("direct upstream write error {}", ec.message());
            co_return 0;
        }
        co_return n;
    }

    asio::awaitable<void> close() override
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

   private:
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
};

class proxy_upstream : public upstream
{
   public:
    explicit proxy_upstream(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel) : tunnel_(std::move(tunnel)) {}

    asio::awaitable<bool> connect(const std::string& host, uint16_t port) override
    {
        stream_ = tunnel_->create_stream();
        if (!stream_)
        {
            LOG_ERROR("proxy upstream failed to create stream");
            co_return false;
        }

        const syn_payload syn{.socks_cmd = socks::CMD_CONNECT, .addr = host, .port = port};
        auto ec = co_await tunnel_->get_connection()->send_async(stream_->id(), CMD_SYN, mux_codec::encode_syn(syn));
        if (ec)
        {
            LOG_ERROR("proxy upstream send syn failed error {}", ec.message());
            co_return false;
        }

        auto [ack_ec, ack_data] = co_await stream_->async_read_some();
        if (ack_ec)
        {
            LOG_ERROR("proxy upstream wait ack failed error {}", ack_ec.message());
            co_return false;
        }

        ack_payload ack_pl;
        if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep != socks::REP_SUCCESS)
        {
            LOG_WARN("proxy upstream remote rejected rep {}", ack_pl.socks_rep);
            co_return false;
        }

        co_return true;
    }

    asio::awaitable<std::pair<std::error_code, size_t>> read(std::vector<uint8_t>& buf) override
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

    asio::awaitable<size_t> write(const std::vector<uint8_t>& data) override
    {
        auto ec = co_await stream_->async_write_some(data.data(), data.size());
        if (ec)
        {
            LOG_ERROR("proxy upstream write error {}", ec.message());
            co_return 0;
        }
        co_return data.size();
    }

    asio::awaitable<void> close() override
    {
        if (stream_)
        {
            co_await stream_->close();
        }
    }

   private:
    std::shared_ptr<mux_stream> stream_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_;
};

}    // namespace mux

#endif
