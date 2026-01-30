#ifndef REMOTE_SESSION_H
#define REMOTE_SESSION_H

#include <vector>
#include "protocol.h"
#include "mux_tunnel.h"
#include "log.h"
#include "log_context.h"

namespace mux
{

class remote_session : public mux_stream_interface, public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_connection> connection, uint32_t id, const asio::any_io_executor &ex, const connection_context &ctx)
        : connection_(std::move(connection)), id_(id), resolver_(ex), target_socket_(ex), recv_channel_(ex, 128)
    {
        ctx_ = ctx;
        ctx_.stream_id = id;
    }

    asio::awaitable<void> start(std::vector<uint8_t> syn_data)
    {
        syn_payload syn;
        if (!mux_codec::decode_syn(syn_data.data(), syn_data.size(), syn))
        {
            LOG_CTX_WARN(ctx_, "{} decode syn failed", log_event::MUX);
            co_await connection_->send_async(id_, CMD_RST, {});
            co_return;
        }

        LOG_CTX_INFO(ctx_, "{} connecting {} {}", log_event::MUX, syn.addr, syn.port);
        auto [er, eps] = co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), asio::as_tuple(asio::use_awaitable));
        if (er)
        {
            LOG_CTX_ERROR(ctx_, "{} resolve failed {}", log_event::MUX, er.message());
            const ack_payload ack{.socks_rep = socks::REP_HOST_UNREACH, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }

        auto [ec_conn, ep_conn] = co_await asio::async_connect(target_socket_, eps, asio::as_tuple(asio::use_awaitable));
        if (ec_conn)
        {
            LOG_CTX_ERROR(ctx_, "{} connect failed {}", log_event::MUX, ec_conn.message());
            const ack_payload ack{.socks_rep = socks::REP_CONN_REFUSED, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }

        std::error_code ec_sock;
        ec_sock = target_socket_.set_option(asio::ip::tcp::no_delay(true), ec_sock);
        (void)ec_sock;
        LOG_CTX_DEBUG(ctx_, "{} established local {} remote {}",
                  log_event::MUX,
                  target_socket_.local_endpoint().address().to_string(),
                  ep_conn.address().to_string());

        const ack_payload ack_pl{.socks_rep = socks::REP_SUCCESS, .bnd_addr = ep_conn.address().to_string(), .bnd_port = ep_conn.port()};
        co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack_pl));

        using asio::experimental::awaitable_operators::operator&&;
        co_await (upstream() && downstream());

        std::error_code ignore;
        ignore = target_socket_.close(ignore);
        (void)ignore;
        if (manager_)
        {
            manager_->remove_stream(id_);
        }
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(std::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        std::error_code ec;
        ec = target_socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        (void)ec;
    }
    void on_reset() override
    {
        recv_channel_.close();
        target_socket_.close();
    }
    void set_manager(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> &m) { manager_ = m; }

   private:
    asio::awaitable<void> upstream()
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec || data.empty())
            {
                std::error_code ignore;
                ignore = target_socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
                (void)ignore;
                break;
            }
            auto [we, wn] =
                co_await asio::async_write(target_socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
    }

    asio::awaitable<void> downstream()
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            std::error_code re;
            const uint32_t n =
                co_await target_socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, re));
            if (re || n == 0)
            {
                break;
            }
            if (co_await connection_->send_async(id_, CMD_DAT, std::vector<uint8_t>(buf.begin(), buf.begin() + n)))
            {
                break;
            }
        }
        co_await connection_->send_async(id_, CMD_FIN, {});
    }

   private:
    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    connection_context ctx_;
    asio::ip::tcp::resolver resolver_;
    asio::ip::tcp::socket target_socket_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager_;
};

}    // namespace mux

#endif
