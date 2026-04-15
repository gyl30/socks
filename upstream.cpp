#include <span>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
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
#include "constants.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"

namespace relay
{

class direct_upstream final : public upstream
{
   public:
    explicit direct_upstream(const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg)
        : cfg_(cfg), conn_id_(conn_id), trace_id_(trace_id), socket_(executor), resolver_(executor)
    {
    }

    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect(const std::string& host, uint16_t port) override;
    boost::asio::awaitable<void> write(const std::vector<uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buf, boost::system::error_code& ec) override;

   private:
    const config& cfg_;
    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
};

class proxy_upstream final : public upstream
{
   public:
    explicit proxy_upstream(const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg);

    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect(const std::string& host, uint16_t port) override;
    boost::asio::awaitable<void> write(const std::vector<uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buf, boost::system::error_code& ec) override;

   private:
    boost::asio::awaitable<void> send_connect_request(const std::string& host, uint16_t port, boost::system::error_code& ec) const;
    boost::asio::awaitable<void> wait_connect_reply(const std::string& host, uint16_t port, upstream_connect_result& result) const;
    [[nodiscard]] uint32_t connect_ack_timeout() const;

   private:
    const config& cfg_;
    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    boost::asio::any_io_executor executor_;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    std::shared_ptr<proxy_reality_connection> connection_;
    bool send_shutdown_ = false;
};

[[nodiscard]] static boost::system::error_code map_socks_rep_to_connect_error(uint8_t rep)
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

boost::asio::awaitable<upstream_connect_result> direct_upstream::connect(const std::string& host, uint16_t port)
{
    upstream_connect_result result;
    result.socks_rep = socks::kRepSuccess;
    target_host_ = host;
    target_port_ = port;
    bind_host_ = "unknown";
    bind_port_ = 0;
    boost::system::error_code ec;
    auto endpoints = co_await net::wait_resolve_with_timeout(resolver_, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN(
            "{} trace {:016x} conn {} stage resolve target {}:{} error {}", log_event::kRoute, trace_id_, conn_id_, host, port, ec.message());
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
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

        co_await net::wait_connect_with_timeout(socket_, entry.endpoint(), cfg_.timeout.connect, op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }
        op_ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), op_ec);
        if (op_ec)
        {
            LOG_WARN("{} trace {:016x} conn {} stage set_no_delay target {}:{} error {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     host,
                     port,
                     op_ec.message());
        }
        const auto local_ep = socket_.local_endpoint(op_ec);
        if (op_ec)
        {
            LOG_WARN("{} trace {:016x} conn {} stage query_bind_endpoint target {}:{} error {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     host,
                     port,
                     op_ec.message());
        }
        else
        {
            result.bind_addr = socks_codec::normalize_ip_address(local_ep.address());
            result.bind_port = local_ep.port();
            result.has_bind_endpoint = true;
            bind_host_ = result.bind_addr.to_string();
            bind_port_ = result.bind_port;
        }
        LOG_INFO("{} trace {:016x} conn {} route direct connected target {}:{} bind {}:{}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 host,
                 port,
                 bind_host_,
                 bind_port_);
        co_return result;
    }
    result.ec = last_ec;
    result.socks_rep = socks::map_connect_error_to_socks_rep(last_ec);
    co_return result;
}

boost::asio::awaitable<std::size_t> direct_upstream::read(std::vector<uint8_t>& buf, boost::system::error_code& ec)
{
    auto n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    co_return n;
}

boost::asio::awaitable<void> direct_upstream::write(const std::vector<uint8_t>& data, boost::system::error_code& ec)
{
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(data), cfg_.timeout.write, ec);
}

boost::asio::awaitable<void> direct_upstream::close()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && !net::is_socket_shutdown_error(ec))
    {
        LOG_WARN("{} trace {:016x} conn {} stage close target {}:{} bind {}:{} shutdown failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message());
    }
    ec = socket_.close(ec);
    if (ec && !net::is_socket_shutdown_error(ec))
    {
        LOG_WARN("{} trace {:016x} conn {} stage close target {}:{} bind {}:{} socket failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message());
    }
    co_return;
}

boost::asio::awaitable<void> direct_upstream::shutdown_send(boost::system::error_code& ec)
{
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec.clear();
    }
    co_return;
}

std::shared_ptr<upstream> make_direct_upstream(const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg)
{
    return std::make_shared<direct_upstream>(executor, conn_id, trace_id, cfg);
}

proxy_upstream::proxy_upstream(const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg)
    : cfg_(cfg), conn_id_(conn_id), trace_id_(trace_id), executor_(executor)
{
}

std::shared_ptr<upstream> make_proxy_upstream(const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg)
{
    return std::make_shared<proxy_upstream>(executor, conn_id, trace_id, cfg);
}

uint32_t proxy_upstream::connect_ack_timeout() const
{
    if (cfg_.timeout.connect == 0)
    {
        return cfg_.timeout.read;
    }

    return std::max(cfg_.timeout.read, cfg_.timeout.connect + 1);
}

boost::asio::awaitable<void> proxy_upstream::send_connect_request(const std::string& host, const uint16_t port, boost::system::error_code& ec) const
{
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }

    proxy::tcp_connect_request request;
    request.target_host = host;
    request.target_port = port;
    request.trace_id = trace_id_;

    std::vector<uint8_t> packet;
    if (!proxy::encode_tcp_connect_request(request, packet))
    {
        ec = boost::asio::error::message_size;
        LOG_ERROR("{} trace {:016x} conn {} stage send_connect_request target {}:{} encode failed",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  host,
                  port);
        co_return;
    }

    LOG_INFO("{} trace {:016x} conn {} stage send_connect_request target {}:{} payload_size {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             host,
             port,
             packet.size());
    co_await connection_->write_packet(packet, ec);
    if (ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} stage send_connect_request target {}:{} error {}",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  host,
                  port,
                  ec.message());
        co_return;
    }
}

boost::asio::awaitable<void> proxy_upstream::wait_connect_reply(const std::string& host, const uint16_t port, upstream_connect_result& result) const
{
    if (connection_ == nullptr)
    {
        result.ec = boost::asio::error::not_connected;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return;
    }

    boost::system::error_code reply_ec;
    const auto packet = co_await connection_->read_packet(connect_ack_timeout(), reply_ec);
    if (reply_ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} stage wait_connect_reply target {}:{} error {}",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  host,
                  port,
                  reply_ec.message());
        result.ec = reply_ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(reply_ec);
        co_return;
    }

    proxy::tcp_connect_reply reply;
    if (!proxy::decode_tcp_connect_reply(packet.data(), packet.size(), reply))
    {
        LOG_WARN("{} trace {:016x} conn {} stage decode_connect_reply target {}:{} invalid_reply_payload payload_size {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 host,
                 port,
                 packet.size());
        result.ec = boost::asio::error::invalid_argument;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return;
    }
    result.socks_rep = reply.socks_rep;
    if (reply.socks_rep != socks::kRepSuccess)
    {
        LOG_WARN("{} trace {:016x} conn {} stage wait_connect_reply target {}:{} remote_rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 host,
                 port,
                 reply.socks_rep);
        result.ec = map_socks_rep_to_connect_error(reply.socks_rep);
        co_return;
    }

    boost::system::error_code bind_ec;
    const auto bind_addr = boost::asio::ip::make_address(reply.bind_host, bind_ec);
    if (bind_ec)
    {
        LOG_WARN("{} trace {:016x} conn {} stage wait_connect_reply target {}:{} invalid_bind_addr {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 host,
                 port,
                 reply.bind_host);
    }
    else
    {
        result.bind_addr = socks_codec::normalize_ip_address(bind_addr);
        result.bind_port = reply.bind_port;
        result.has_bind_endpoint = true;
    }

    LOG_INFO("{} trace {:016x} conn {} stage wait_connect_reply target {}:{} bind {}:{}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             host,
             port,
             reply.bind_host,
             reply.bind_port);
}

boost::asio::awaitable<upstream_connect_result> proxy_upstream::connect(const std::string& host, uint16_t port)
{
    upstream_connect_result result;
    result.socks_rep = socks::kRepSuccess;
    target_host_ = host;
    target_port_ = port;
    bind_host_ = "unknown";
    bind_port_ = 0;
    send_shutdown_ = false;
    boost::system::error_code ec;
    connection_.reset();
    connection_ = co_await proxy_reality_connection::connect(executor_, cfg_, conn_id_, ec);
    if (connection_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::not_connected;
        }
        LOG_ERROR("{} trace {:016x} conn {} target {}:{} route proxy connect reality failed {}",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  host,
                  port,
                  ec.message());
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
        co_return result;
    }

    LOG_INFO("{} trace {:016x} conn {} target {}:{} route proxy connected reality local {}:{} remote {}:{}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             host,
             port,
             connection_->local_host(),
             connection_->local_port(),
             connection_->remote_host(),
             connection_->remote_port());
    co_await send_connect_request(host, port, ec);
    if (ec)
    {
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
        boost::system::error_code close_ec;
        connection_->close(close_ec);
        connection_.reset();
        co_return result;
    }

    co_await wait_connect_reply(host, port, result);
    if (result.ec)
    {
        boost::system::error_code close_ec;
        connection_->close(close_ec);
        connection_.reset();
        co_return result;
    }

    if (result.has_bind_endpoint)
    {
        bind_host_ = result.bind_addr.to_string();
        bind_port_ = result.bind_port;
    }

    co_return result;
}

boost::asio::awaitable<std::size_t> proxy_upstream::read(std::vector<uint8_t>& buf, boost::system::error_code& ec)
{
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return 0;
    }
    const auto bytes_read = co_await connection_->read_some(buf, 0, ec);
    if (ec && !net::is_socket_close_error(ec))
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} bind {}:{} stage read_proxy_data error {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message());
    }
    co_return bytes_read;
}

boost::asio::awaitable<void> proxy_upstream::write(const std::vector<uint8_t>& data, boost::system::error_code& ec)
{
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }
    co_return co_await connection_->write(std::span<const uint8_t>(data.data(), data.size()), ec);
}

boost::asio::awaitable<void> proxy_upstream::shutdown_send(boost::system::error_code& ec)
{
    if (connection_ == nullptr || send_shutdown_)
    {
        co_return;
    }
    co_await connection_->shutdown_send(ec);
    if (net::is_socket_close_error(ec))
    {
        ec.clear();
    }
    if (!ec)
    {
        send_shutdown_ = true;
    }
}

boost::asio::awaitable<void> proxy_upstream::close()
{
    if (connection_ != nullptr)
    {
        boost::system::error_code ec;
        connection_->close(ec);
    }
    connection_.reset();
    send_shutdown_ = false;
    co_return;
}

}    // namespace relay
