#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/channel_error.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "timeout_io.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "connection_context.h"
#include "client_tunnel_pool.h"

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

[[nodiscard]] bool is_expected_proxy_stream_read_shutdown(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor ||
           ec == boost::asio::experimental::error::channel_errors::channel_closed ||
           ec == boost::asio::experimental::error::channel_errors::channel_cancelled;
}

}    // namespace

class direct_upstream final : public upstream
{
   public:
    explicit direct_upstream(const boost::asio::any_io_executor& executor, connection_context ctx, const config& cfg)
        : cfg_(cfg), ctx_(std::move(ctx)), socket_(executor), resolver_(executor)
    {
    }

    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect(const std::string& host, std::uint16_t port) override;
    boost::asio::awaitable<void> write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec) override;

   private:
    const config& cfg_;
    connection_context ctx_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
};

class proxy_upstream final : public upstream
{
   public:
    explicit proxy_upstream(std::shared_ptr<mux_connection> tunnel, connection_context ctx, const config& cfg);
    explicit proxy_upstream(std::shared_ptr<client_tunnel_pool> tunnel_pool, connection_context ctx, const config& cfg);

    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect(const std::string& host, std::uint16_t port) override;
    boost::asio::awaitable<void> write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec) override;

   private:
    boost::asio::awaitable<void> send_syn_request(const std::shared_ptr<mux_stream>& stream,
                                                  const std::string& host,
                                                  std::uint16_t port,
                                                  boost::system::error_code& ec) const;
    boost::asio::awaitable<void> wait_connect_ack(const std::shared_ptr<mux_stream>& stream,
                                                  const std::string& host,
                                                  std::uint16_t port,
                                                  upstream_connect_result& result) const;
    [[nodiscard]] std::uint32_t connect_ack_timeout() const;

   private:
    const config& cfg_;
    connection_context ctx_;
    std::shared_ptr<mux_stream> stream_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<mux_connection> tunnel_;
    bool fin_sent_ = false;
    bool reset_received_ = false;
    bool protocol_error_ = false;
};

[[nodiscard]] static std::uint8_t map_connect_error_to_socks_rep(const boost::system::error_code& ec)
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

[[nodiscard]] static boost::system::error_code map_socks_rep_to_connect_error(const std::uint8_t rep)
{
    switch (rep)
    {
        case socks::kRepSuccess:
            return {};
        case socks::kRepNotAllowed:
            return boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        case socks::kRepNetUnreach:
            return boost::asio::error::network_unreachable;
        case socks::kRepHostUnreach:
            return boost::asio::error::host_unreachable;
        case socks::kRepConnRefused:
            return boost::asio::error::connection_refused;
        case socks::kRepTtlExpired:
            return boost::asio::error::timed_out;
        case socks::kRepCmdNotSupported:
            return boost::asio::error::operation_not_supported;
        case socks::kRepAddrTypeNotSupported:
            return boost::asio::error::address_family_not_supported;
        default:
            return boost::asio::error::connection_aborted;
    }
}

boost::asio::awaitable<upstream_connect_result> direct_upstream::connect(const std::string& host, const std::uint16_t port)
{
    upstream_connect_result result;
    result.socks_rep = socks::kRepSuccess;
    boost::system::error_code ec;
    auto endpoints = co_await timeout_io::wait_resolve_with_timeout(resolver_, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} stage resolve target {}:{} error {}", log_event::kRoute, host, port, ec.message());
        result.ec = ec;
        result.socks_rep = map_connect_error_to_socks_rep(ec);
        co_return result;
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
            net::set_socket_mark(socket_.native_handle(), connect_mark, op_ec);
            if (op_ec)
            {
                last_ec = op_ec;
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
        const auto local_ep = socket_.local_endpoint(op_ec);
        if (op_ec)
        {
            LOG_CTX_WARN(ctx_, "{} stage query_bind_endpoint failed {}", log_event::kRoute, op_ec.message());
        }
        else
        {
            result.bind_addr = socks_codec::normalize_ip_address(local_ep.address());
            result.bind_port = local_ep.port();
            result.has_bind_endpoint = true;
        }
        co_return result;
    }
    result.ec = last_ec;
    result.socks_rep = map_connect_error_to_socks_rep(last_ec);
    co_return result;
}

boost::asio::awaitable<std::size_t> direct_upstream::read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec)
{
    auto n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    co_return n;
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

boost::asio::awaitable<void> direct_upstream::shutdown_send(boost::system::error_code& ec)
{
    ec.clear();
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec.clear();
    }
    co_return;
}

std::shared_ptr<upstream> make_direct_upstream(const boost::asio::any_io_executor& executor, connection_context ctx, const config& cfg)
{
    return std::make_shared<direct_upstream>(executor, std::move(ctx), cfg);
}

proxy_upstream::proxy_upstream(std::shared_ptr<mux_connection> tunnel, connection_context ctx, const config& cfg)
    : cfg_(cfg), ctx_(std::move(ctx)), tunnel_(std::move(tunnel))
{
}

proxy_upstream::proxy_upstream(std::shared_ptr<client_tunnel_pool> tunnel_pool, connection_context ctx, const config& cfg)
    : cfg_(cfg), ctx_(std::move(ctx)), tunnel_pool_(std::move(tunnel_pool))
{
}

std::shared_ptr<upstream> make_proxy_upstream(std::shared_ptr<mux_connection> tunnel, connection_context ctx, const config& cfg)
{
    return std::make_shared<proxy_upstream>(std::move(tunnel), std::move(ctx), cfg);
}

std::shared_ptr<upstream> make_proxy_upstream(std::shared_ptr<client_tunnel_pool> tunnel_pool, connection_context ctx, const config& cfg)
{
    return std::make_shared<proxy_upstream>(std::move(tunnel_pool), std::move(ctx), cfg);
}

std::uint32_t proxy_upstream::connect_ack_timeout() const
{
    if (cfg_.timeout.connect == 0)
    {
        return cfg_.timeout.read;
    }

    return std::max(cfg_.timeout.read, cfg_.timeout.connect + 1);
}

boost::asio::awaitable<void> proxy_upstream::send_syn_request(const std::shared_ptr<mux_stream>& stream,
                                                              const std::string& host,
                                                              const std::uint16_t port,
                                                              boost::system::error_code& ec) const
{
    const auto stream_ctx = ctx_.with_stream(stream->id());
    const syn_payload syn{.socks_cmd = socks::kCmdConnect, .addr = host, .port = port, .trace_id = ctx_.trace_id()};
    std::vector<std::uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        LOG_CTX_ERROR(stream_ctx, "{} stage send_syn target {}:{} encode failed", log_event::kRoute, host, port);
        co_return;
    }
    mux_frame syn_frame;
    syn_frame.h.stream_id = stream->id();
    syn_frame.h.command = kCmdSyn;
    syn_frame.payload = std::move(syn_data);
    LOG_CTX_DEBUG(stream_ctx,
                  "{} stage send_syn stream {} target {}:{} payload_size {}",
                  log_event::kRoute,
                  stream->id(),
                  host,
                  port,
                  syn_frame.payload.size());
    co_await stream->async_write(syn_frame, ec);
    if (ec)
    {
        LOG_CTX_ERROR(stream_ctx, "{} stage send_syn target {}:{} error {}", log_event::kRoute, host, port, ec.message());
        co_return;
    }
}

boost::asio::awaitable<void> proxy_upstream::wait_connect_ack(const std::shared_ptr<mux_stream>& stream,
                                                              const std::string& host,
                                                              const std::uint16_t port,
                                                              upstream_connect_result& result) const
{
    const auto stream_ctx = ctx_.with_stream(stream->id());
    boost::system::error_code ack_ec;
    auto ack_frame = co_await stream->async_read(connect_ack_timeout(), ack_ec);
    if (ack_ec)
    {
        LOG_CTX_ERROR(stream_ctx, "{} stage wait_ack target {}:{} error {}", log_event::kRoute, host, port, ack_ec.message());
        result.ec = ack_ec;
        result.socks_rep = map_connect_error_to_socks_rep(ack_ec);
        co_return;
    }
    if (ack_frame.h.command != kCmdAck)
    {
        LOG_CTX_WARN(stream_ctx,
                     "{} stage wait_ack target {}:{} unexpected_cmd {}({}) payload_size {}",
                     log_event::kRoute,
                     host,
                     port,
                     ack_frame.h.command,
                     mux_command_name(ack_frame.h.command),
                     ack_frame.payload.size());
        result.ec = boost::asio::error::connection_aborted;
        result.socks_rep = map_connect_error_to_socks_rep(result.ec);
        co_return;
    }

    ack_payload ack{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack))
    {
        LOG_CTX_WARN(stream_ctx, "{} stage decode_ack target {}:{} error invalid_ack_payload", log_event::kRoute, host, port);
        result.ec = boost::asio::error::invalid_argument;
        result.socks_rep = map_connect_error_to_socks_rep(result.ec);
        co_return;
    }
    result.socks_rep = ack.socks_rep;
    if (ack.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(stream_ctx, "{} stage wait_ack target {}:{} remote_rep {}", log_event::kRoute, host, port, ack.socks_rep);
        result.ec = map_socks_rep_to_connect_error(ack.socks_rep);
        co_return;
    }

    boost::system::error_code bind_ec;
    const auto bind_addr = boost::asio::ip::make_address(ack.bnd_addr, bind_ec);
    if (bind_ec)
    {
        LOG_CTX_WARN(stream_ctx, "{} stage wait_ack target {}:{} invalid_bind_addr {}", log_event::kRoute, host, port, ack.bnd_addr);
    }
    else
    {
        result.bind_addr = socks_codec::normalize_ip_address(bind_addr);
        result.bind_port = ack.bnd_port;
        result.has_bind_endpoint = true;
    }

    LOG_CTX_INFO(stream_ctx, "{} stage wait_ack target {}:{} bind {}:{}", log_event::kRoute, host, port, ack.bnd_addr, ack.bnd_port);
}

boost::asio::awaitable<upstream_connect_result> proxy_upstream::connect(const std::string& host, const std::uint16_t port)
{
    upstream_connect_result result;
    result.socks_rep = socks::kRepSuccess;
    fin_sent_ = false;
    reset_received_ = false;
    protocol_error_ = false;
    boost::system::error_code ec;
    if (tunnel_pool_ != nullptr)
    {
        tunnel_.reset();
        tunnel_ = co_await tunnel_pool_->wait_for_tunnel(cfg_.timeout.connect, ec);
        if (ec || tunnel_ == nullptr)
        {
            if (!ec)
            {
                ec = boost::asio::error::not_connected;
            }
            LOG_CTX_ERROR(ctx_, "{} wait tunnel failed {}", log_event::kRoute, ec.message());
            result.ec = ec;
            result.socks_rep = map_connect_error_to_socks_rep(ec);
            co_return result;
        }
    }
    else if (tunnel_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_CTX_ERROR(ctx_, "{} create stream failed no tunnel", log_event::kRoute);
        result.ec = ec;
        result.socks_rep = map_connect_error_to_socks_rep(ec);
        co_return result;
    }

    auto stream = tunnel_->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::connection_aborted;
        LOG_CTX_ERROR(ctx_, "{} create stream failed", log_event::kRoute);
        result.ec = ec;
        result.socks_rep = map_connect_error_to_socks_rep(ec);
        co_return result;
    }
    co_await send_syn_request(stream, host, port, ec);
    if (ec)
    {
        result.ec = ec;
        result.socks_rep = map_connect_error_to_socks_rep(ec);
        tunnel_->close_and_remove_stream(stream);
        co_return result;
    }

    co_await wait_connect_ack(stream, host, port, result);
    if (result.ec)
    {
        tunnel_->close_and_remove_stream(stream);
        co_return result;
    }

    stream_ = std::move(stream);
    co_return result;
}

boost::asio::awaitable<std::size_t> proxy_upstream::read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec)
{
    const auto stream = stream_;
    if (stream == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return 0;
    }

    // 数据面读取不设超时，交由 idle watchdog 统一判定
    auto data_frame = co_await stream->async_read(0, ec);
    if (ec)
    {
        if (is_expected_proxy_stream_read_shutdown(ec))
        {
            LOG_CTX_INFO(ctx_.with_stream(stream->id()), "{} stage read_frame stopped {}", log_event::kRoute, ec.message());
        }
        else
        {
            LOG_CTX_WARN(ctx_.with_stream(stream->id()), "{} stage read_frame error {}", log_event::kRoute, ec.message());
        }
        co_return 0;
    }
    if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
    {
        LOG_CTX_INFO(ctx_.with_stream(stream->id()),
                     "{} stage read_frame recv_control cmd {}({}) payload_size {}",
                     log_event::kRoute,
                     data_frame.h.command,
                     mux_command_name(data_frame.h.command),
                     data_frame.payload.size());
        reset_received_ = data_frame.h.command == mux::kCmdRst;
        if (data_frame.h.command == mux::kCmdFin)
        {
            ec = boost::asio::error::eof;
        }
        else
        {
            ec = boost::asio::error::connection_reset;
        }
        co_return 0;
    }
    if (data_frame.h.command != mux::kCmdDat)
    {
        LOG_CTX_WARN(ctx_.with_stream(stream->id()),
                     "{} stage read_frame unexpected_cmd {}({}) payload_size {}",
                     log_event::kRoute,
                     data_frame.h.command,
                     mux_command_name(data_frame.h.command),
                     data_frame.payload.size());
        protocol_error_ = true;
        ec = boost::asio::error::invalid_argument;
        co_return 0;
    }

    if (buf.size() < data_frame.payload.size())
    {
        buf.resize(data_frame.payload.size());
    }
    std::ranges::copy(data_frame.payload, buf.begin());
    co_return data_frame.payload.size();
}

boost::asio::awaitable<void> proxy_upstream::write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec)
{
    const auto stream = stream_;
    if (stream == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }

    mux_frame data_frame;
    data_frame.h.stream_id = stream->id();
    data_frame.h.command = mux::kCmdDat;
    data_frame.payload = data;
    co_return co_await stream->async_write(data_frame, ec);
}

boost::asio::awaitable<void> proxy_upstream::shutdown_send(boost::system::error_code& ec)
{
    ec.clear();
    const auto stream = stream_;
    if (stream == nullptr || fin_sent_)
    {
        co_return;
    }

    mux_frame fin_frame;
    fin_frame.h.stream_id = stream->id();
    fin_frame.h.command = mux::kCmdFin;
    co_await stream->async_write(fin_frame, ec);
    if (!ec)
    {
        fin_sent_ = true;
    }
}

boost::asio::awaitable<void> proxy_upstream::close()
{
    const auto stream = stream_;
    const auto tunnel = tunnel_;
    if (stream != nullptr && tunnel != nullptr)
    {
        if (protocol_error_)
        {
            mux_frame rst_frame;
            rst_frame.h.stream_id = stream->id();
            rst_frame.h.command = mux::kCmdRst;
            boost::system::error_code rst_ec;
            co_await stream->async_write(std::move(rst_frame), rst_ec);
            if (rst_ec)
            {
                LOG_CTX_WARN(ctx_.with_stream(stream->id()), "{} stage send_rst error {}", log_event::kRoute, rst_ec.message());
            }
        }
        else if (!fin_sent_ && !reset_received_)
        {
            boost::system::error_code fin_ec;
            co_await shutdown_send(fin_ec);
            if (fin_ec)
            {
                LOG_CTX_WARN(ctx_.with_stream(stream->id()), "{} stage send_fin error {}", log_event::kRoute, fin_ec.message());
            }
        }
        tunnel->close_and_remove_stream(stream);
    }
    fin_sent_ = false;
    reset_received_ = false;
    protocol_error_ = false;
    stream_.reset();
    co_return;
}

}    // namespace mux
