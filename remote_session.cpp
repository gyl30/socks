#include "remote_session.h"
#include "mux_codec.h"

namespace mux
{

remote_session::remote_session(std::shared_ptr<mux_connection> connection,
                               uint32_t id,
                               const asio::any_io_executor& ex,
                               const connection_context& ctx)
    : id_(id), resolver_(ex), target_socket_(ex), connection_(std::move(connection)), recv_channel_(ex, 128)
{
    ctx_ = ctx;
    ctx_.stream_id = id;
}

asio::awaitable<void> remote_session::start(const syn_payload& syn)
{
    ctx_.set_target(syn.addr, syn.port);
    LOG_CTX_INFO(ctx_, "{} connecting {} {}", log_event::MUX, syn.addr, syn.port);
    auto [er, eps] = co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), asio::as_tuple(asio::use_awaitable));
    if (er)
    {
        LOG_CTX_ERROR(ctx_, "{} resolve failed {}", log_event::MUX, er.message());
        const ack_payload ack{.socks_rep = socks::REP_HOST_UNREACH, .bnd_addr = "", .bnd_port = 0};
        std::vector<uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        co_await connection_->send_async(id_, CMD_ACK, std::move(ack_data));
        co_return;
    }

    auto [ec_conn, ep_conn] = co_await asio::async_connect(target_socket_, eps, asio::as_tuple(asio::use_awaitable));
    if (ec_conn)
    {
        LOG_CTX_ERROR(ctx_, "{} connect failed {}", log_event::MUX, ec_conn.message());
        const ack_payload ack{.socks_rep = socks::REP_CONN_REFUSED, .bnd_addr = "", .bnd_port = 0};
        std::vector<uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        co_await connection_->send_async(id_, CMD_ACK, std::move(ack_data));
        co_return;
    }

    std::error_code ec_sock;
    ec_sock = target_socket_.set_option(asio::ip::tcp::no_delay(true), ec_sock);
    if (ec_sock)
    {
        LOG_CTX_WARN(ctx_, "set_option no_delay failed {}", ec_sock.message());
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {}", log_event::CONN_ESTABLISHED, syn.addr, syn.port);

    const ack_payload ack_pl{.socks_rep = socks::REP_SUCCESS, .bnd_addr = ep_conn.address().to_string(), .bnd_port = ep_conn.port()};
    std::vector<uint8_t> ack_data;
    mux_codec::encode_ack(ack_pl, ack_data);
    co_await connection_->send_async(id_, CMD_ACK, std::move(ack_data));

    using asio::experimental::awaitable_operators::operator&&;
    co_await (upstream() && downstream());

    std::error_code ignore;
    ignore = target_socket_.close(ignore);
    (void)ignore;
    if (manager_)
    {
        manager_->remove_stream(id_);
    }
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::CONN_CLOSE, ctx_.stats_summary());
}

void remote_session::on_data(std::vector<uint8_t> data)
{
    recv_channel_.try_send(std::error_code(), std::move(data));
}

void remote_session::on_close()
{
    LOG_CTX_DEBUG(ctx_, "{} received FIN from client", log_event::MUX);
    recv_channel_.close();
    std::error_code ec;
    ec = target_socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    (void)ec;
}

void remote_session::on_reset()
{
    recv_channel_.close();
    target_socket_.close();
}

asio::awaitable<void> remote_session::upstream()
{
    for (;;)
    {
        auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec || data.empty())
        {
            if (ec)
            {
                LOG_CTX_DEBUG(ctx_, "{} mux channel closed {}", log_event::DATA_RECV, ec.message());
            }
            std::error_code ignore;
            ignore = target_socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
            (void)ignore;
            break;
        }
        auto [we, wn] = co_await asio::async_write(target_socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to target {}", log_event::DATA_SEND, we.message());
            break;
        }
        ctx_.rx_bytes += wn;
    }
    LOG_CTX_INFO(ctx_, "{} mux to target finished", log_event::DATA_SEND);
}

asio::awaitable<void> remote_session::downstream()
{
    std::vector<uint8_t> buf(8192);
    for (;;)
    {
        std::error_code re;
        const uint32_t n = co_await target_socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, re));
        if (re || n == 0)
        {
            if (re && re != asio::error::eof && re != asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} failed to read from target {}", log_event::DATA_RECV, re.message());
            }
            break;
        }
        if (co_await connection_->send_async(id_, CMD_DAT, std::vector<uint8_t>(buf.begin(), buf.begin() + n)))
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to mux", log_event::DATA_SEND);
            break;
        }
        ctx_.tx_bytes += n;
    }
    LOG_CTX_INFO(ctx_, "{} target to mux finished", log_event::DATA_RECV);
    co_await connection_->send_async(id_, CMD_FIN, {});
}

}    // namespace mux
