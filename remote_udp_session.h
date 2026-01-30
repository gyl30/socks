#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <vector>
#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection, uint32_t id, const asio::any_io_executor &ex, const connection_context &ctx)
        : id_(id), timer_(ex), udp_socket_(ex), udp_resolver_(ex), connection_(std::move(connection)), recv_channel_(ex, 128)
    {
        ctx_ = ctx;
        ctx_.stream_id = id;
        last_read_time_ = std::chrono::steady_clock::now();
        last_write_time_ = std::chrono::steady_clock::now();
    }

    asio::awaitable<void> start()
    {
        std::error_code ec;
        ec = udp_socket_.open(asio::ip::udp::v6(), ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} udp open failed {}", log_event::MUX, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            std::vector<uint8_t> ack_data;
            mux_codec::encode_ack(ack, ack_data);
            co_await connection_->send_async(id_, CMD_ACK, std::move(ack_data));
            co_return;
        }
        ec = udp_socket_.set_option(asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} udp v4 and v6 failed {}", log_event::MUX, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            std::vector<uint8_t> ack_data;
            mux_codec::encode_ack(ack, ack_data);
            co_await connection_->send_async(id_, CMD_ACK, std::move(ack_data));
            co_return;
        }
        ec = udp_socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), 0), ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} udp bind failed {}", log_event::MUX, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            std::vector<uint8_t> ack_data;
            mux_codec::encode_ack(ack, ack_data);
            co_await connection_->send_async(id_, CMD_ACK, std::move(ack_data));
            co_return;
        }

        auto local_ep = udp_socket_.local_endpoint(ec);
        LOG_CTX_INFO(ctx_, "{} udp session started bound at {}", log_event::MUX, local_ep.address().to_string());

        const ack_payload ack_pl{.socks_rep = socks::REP_SUCCESS, .bnd_addr = "0.0.0.0", .bnd_port = 0};
        std::vector<uint8_t> ack_pl_data;
        mux_codec::encode_ack(ack_pl, ack_pl_data);
        co_await connection_->send_async(id_, CMD_ACK, std::move(ack_pl_data));

        using asio::experimental::awaitable_operators::operator&&;
        co_await (mux_to_udp() && udp_to_mux() && watchdog());

        if (manager_)
        {
            manager_->remove_stream(id_);
        }
        LOG_CTX_INFO(ctx_, "{} finished {}", log_event::CONN_CLOSE, ctx_.stats_summary());
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(std::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        std::error_code ignore;
        ignore = udp_socket_.close(ignore);
        (void)ignore;
    }
    void on_reset() override { on_close(); }
    void set_manager(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> &m) { manager_ = m; }

   private:
    asio::awaitable<void> watchdog()
    {
        while (udp_socket_.is_open())
        {
            timer_.expires_after(std::chrono::seconds(1));
            auto [ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                LOG_CTX_WARN(ctx_, "{} watchdog error {}", log_event::TIMEOUT, ec.message());
                break;
            }
            auto now = std::chrono::steady_clock::now();
            auto read_elapsed = now - last_read_time_;
            auto write_elapsed = now - last_write_time_;
            if (read_elapsed > std::chrono::seconds(60))
            {
                LOG_CTX_WARN(ctx_, "{} read idle {}s", log_event::TIMEOUT, std::chrono::duration_cast<std::chrono::seconds>(read_elapsed).count());
            }
            if (write_elapsed > std::chrono::seconds(60))
            {
                LOG_CTX_WARN(ctx_, "{} write idle {}s", log_event::TIMEOUT, std::chrono::duration_cast<std::chrono::seconds>(write_elapsed).count());
            }
        }
        LOG_CTX_DEBUG(ctx_, "{} watchdog finished", log_event::MUX);
    }
    asio::awaitable<void> mux_to_udp()
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec || data.empty())
            {
                break;
            }
            socks_udp_header h;
            if (!socks_codec::decode_udp_header(data.data(), data.size(), h))
            {
                LOG_CTX_WARN(ctx_, "{} udp failed to decode header", log_event::MUX);
                continue;
            }

            auto [er, eps] = co_await udp_resolver_.async_resolve(h.addr, std::to_string(h.port), asio::as_tuple(asio::use_awaitable));
            if (!er)
            {
                auto target_ep = *eps.begin();
                LOG_CTX_DEBUG(
                    ctx_, "{} udp forwarding {} bytes to {}", log_event::MUX, data.size() - h.header_len, target_ep.endpoint().address().to_string());

                auto [se, sn] = co_await udp_socket_.async_send_to(
                    asio::buffer(data.data() + h.header_len, data.size() - h.header_len), target_ep, asio::as_tuple(asio::use_awaitable));
                if (se)
                {
                    LOG_CTX_WARN(ctx_, "{} udp send error {}", log_event::MUX, se.message());
                }
                else
                {
                    last_write_time_ = std::chrono::steady_clock::now();
                    ctx_.tx_bytes += sn;
                }
            }
            else
            {
                LOG_CTX_WARN(ctx_, "{} udp resolve error for {}", log_event::MUX, h.addr);
            }
        }
    }

    asio::awaitable<void> udp_to_mux()
    {
        std::vector<uint8_t> buf(65535);
        asio::ip::udp::endpoint ep;
        for (;;)
        {
            auto [re, n] = co_await udp_socket_.async_receive_from(asio::buffer(buf), ep, asio::as_tuple(asio::use_awaitable));
            if (re)
            {
                if (re != asio::error::operation_aborted)
                {
                    LOG_CTX_WARN(ctx_, "{} udp receive error {}", log_event::MUX, re.message());
                }
                break;
            }

            LOG_CTX_DEBUG(ctx_, "{} udp recv {} bytes from {}", log_event::MUX, n, ep.address().to_string());
            last_read_time_ = std::chrono::steady_clock::now();
            ctx_.rx_bytes += n;

            socks_udp_header h;
            h.addr = ep.address().to_string();
            h.port = ep.port();
            std::vector<uint8_t> pkt = socks_codec::encode_udp_header(h);
            pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<uint32_t>(n));
            if (co_await connection_->send_async(id_, CMD_DAT, std::move(pkt)))
            {
                break;
            }
        }
    }

   private:
    uint32_t id_;
    connection_context ctx_;
    asio::steady_timer timer_;
    asio::ip::udp::socket udp_socket_;
    asio::ip::udp::resolver udp_resolver_;
    std::shared_ptr<mux_connection> connection_;
    std::chrono::steady_clock::time_point last_read_time_;
    std::chrono::steady_clock::time_point last_write_time_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
