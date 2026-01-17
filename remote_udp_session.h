#ifndef REMOTE_UDP_SESSION_H
#define REMOTE_UDP_SESSION_H

#include <vector>
#include "protocol.h"
#include "mux_tunnel.h"

namespace mux
{

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection, uint32_t id, const asio::any_io_executor &ex)
        : id_(id), connection_(std::move(connection)), udp_socket_(ex), udp_resolver_(ex), timer_(ex), recv_channel_(ex, 128)
    {
        last_activity_ = std::chrono::steady_clock::now();
    }

    asio::awaitable<void> start()
    {
        uint32_t cid = connection_->id();
        std::error_code ec;
        ec = udp_socket_.open(asio::ip::udp::v6(), ec);
        if (ec)
        {
            LOG_ERROR("srv {} stream {} udp open failed {}", cid, id_, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }
        ec = udp_socket_.set_option(asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR("srv {} stream {} udp v4 and v6 failed {}", cid, id_, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }
        ec = udp_socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), 0), ec);
        if (ec)
        {
            LOG_ERROR("srv {} stream {} udp bind failed {}", cid, id_, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }

        auto local_ep = udp_socket_.local_endpoint(ec);
        LOG_INFO("srv {} stream {} udp session started, bound at {}", cid, id_, local_ep.address().to_string());

        const ack_payload ack_pl{.socks_rep = socks::REP_SUCCESS, .bnd_addr = "0.0.0.0", .bnd_port = 0};
        co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack_pl));

        using asio::experimental::awaitable_operators::operator&&;
        co_await (mux_to_udp() && udp_to_mux() && watchdog());

        if (manager_)
        {
            manager_->remove_stream(id_);
        }
        LOG_INFO("srv {} stream {} udp session finished", cid, id_);
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
    void update_activity() { last_activity_ = std::chrono::steady_clock::now(); }

    asio::awaitable<void> watchdog()
    {
        const std::chrono::seconds idle_timeout(60);
        const std::chrono::seconds check_interval(10);

        while (udp_socket_.is_open())
        {
            timer_.expires_after(check_interval);
            auto [ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                LOG_ERROR("srv {} stream {} udp session watchdog failed {}", connection_->id(), id_, ec.message());
                break;
            }
            auto now = std::chrono::steady_clock::now();
            if (now - last_activity_ > idle_timeout)
            {
                LOG_INFO("srv {} stream {} udp session timed out after {}s idle", connection_->id(), id_, idle_timeout.count());
                on_close();
                break;
            }
        }
    }
    asio::awaitable<void> mux_to_udp()
    {
        uint32_t cid = connection_->id();
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
                LOG_WARN("srv {} stream {} udp failed to decode header", cid, id_);
                continue;
            }

            auto [er, eps] = co_await udp_resolver_.async_resolve(h.addr, std::to_string(h.port), asio::as_tuple(asio::use_awaitable));
            if (!er)
            {
                auto target_ep = *eps.begin();
                LOG_DEBUG("srv {} stream {} udp forwarding {} bytes -> {}",
                          cid,
                          id_,
                          data.size() - h.header_len,
                          target_ep.endpoint().address().to_string());

                auto [se, sn] = co_await udp_socket_.async_send_to(asio::buffer(data.data() + h.header_len, data.size() - h.header_len),
                                                                   target_ep,
                                                                   asio::as_tuple(asio::use_awaitable));
                if (se)
                {
                    LOG_WARN("srv {} stream {} udp send error {}", cid, id_, se.message());
                }
            }
            else
            {
                LOG_WARN("srv {} stream {} udp resolve error for {}", cid, id_, h.addr);
            }
        }
    }

    asio::awaitable<void> udp_to_mux()
    {
        uint32_t cid = connection_->id();
        std::vector<uint8_t> buf(65535);
        asio::ip::udp::endpoint ep;
        for (;;)
        {
            auto [re, n] = co_await udp_socket_.async_receive_from(asio::buffer(buf), ep, asio::as_tuple(asio::use_awaitable));
            if (re)
            {
                if (re != asio::error::operation_aborted)
                {
                    LOG_WARN("srv {} stream {} udp receive error {}", cid, id_, re.message());
                }
                break;
            }

            LOG_DEBUG("srv {} stream {} udp recv {} bytes from {}", cid, id_, n, ep.address().to_string());

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
    std::shared_ptr<mux_connection> connection_;
    asio::ip::udp::socket udp_socket_;
    asio::ip::udp::resolver udp_resolver_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::time_point last_activity_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
