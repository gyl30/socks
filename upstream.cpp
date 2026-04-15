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
    explicit proxy_upstream(const boost::asio::any_io_executor& executor,
                            uint32_t conn_id,
                            uint64_t trace_id,
                            const config& cfg,
                            std::string outbound_tag);

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
    std::string outbound_tag_;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    std::shared_ptr<proxy_reality_connection> connection_;
    bool send_shutdown_ = false;
};

class socks_upstream final : public upstream
{
   public:
    explicit socks_upstream(const boost::asio::any_io_executor& executor,
                            uint32_t conn_id,
                            uint64_t trace_id,
                            const config& cfg,
                            std::string outbound_tag)
        : cfg_(cfg), conn_id_(conn_id), trace_id_(trace_id), outbound_tag_(std::move(outbound_tag)), socket_(executor), resolver_(executor)
    {
    }

    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect(const std::string& host, uint16_t port) override;
    boost::asio::awaitable<void> write(const std::vector<uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buf, boost::system::error_code& ec) override;

   private:
    [[nodiscard]] const config::socks_t* settings() const;
    [[nodiscard]] boost::asio::awaitable<bool> connect_server(const config::socks_t& settings, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> negotiate_method(const config::socks_t& settings, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> do_password_auth(const config::socks_t& settings, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> send_connect_request(const std::string& host, uint16_t port, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> read_connect_reply(upstream_connect_result& result, boost::system::error_code& ec);

   private:
    const config& cfg_;
    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    std::string outbound_tag_;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
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

[[nodiscard]] const config::socks_t* find_socks_outbound_settings(const config& cfg, const std::string& outbound_tag)
{
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr || outbound->type != "socks" || !outbound->socks.has_value())
    {
        return nullptr;
    }
    return &*outbound->socks;
}

bool append_socks_target_address(std::vector<uint8_t>& packet, const std::string& host)
{
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(host, ec);
    if (!ec)
    {
        const auto normalized = socks_codec::normalize_ip_address(address);
        if (normalized.is_v4())
        {
            packet.push_back(socks::kAtypIpv4);
            const auto bytes = normalized.to_v4().to_bytes();
            packet.insert(packet.end(), bytes.begin(), bytes.end());
            return true;
        }
        if (normalized.is_v6())
        {
            packet.push_back(socks::kAtypIpv6);
            const auto bytes = normalized.to_v6().to_bytes();
            packet.insert(packet.end(), bytes.begin(), bytes.end());
            return true;
        }
    }

    if (host.empty() || host.size() > socks::kMaxDomainLen || !socks::is_valid_domain(host))
    {
        return false;
    }
    packet.push_back(socks::kAtypDomain);
    packet.push_back(static_cast<uint8_t>(host.size()));
    packet.insert(packet.end(), host.begin(), host.end());
    return true;
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
        const auto connect_mark = resolve_socket_mark(cfg_);
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

const config::socks_t* socks_upstream::settings() const { return find_socks_outbound_settings(cfg_, outbound_tag_); }

boost::asio::awaitable<bool> socks_upstream::connect_server(const config::socks_t& settings, boost::system::error_code& ec)
{
    auto endpoints = co_await net::wait_resolve_with_timeout(resolver_, settings.host, std::to_string(settings.port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} out_tag {} stage resolve socks server {}:{} error {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 outbound_tag_,
                 settings.host,
                 settings.port,
                 ec.message());
        co_return false;
    }

    for (const auto& entry : endpoints)
    {
        if (socket_.is_open())
        {
            boost::system::error_code close_ec;
            close_ec = socket_.close(close_ec);
        }

        ec = socket_.open(entry.endpoint().protocol(), ec);
        if (ec)
        {
            continue;
        }
        const auto connect_mark = resolve_socket_mark(cfg_);
        if (connect_mark != 0)
        {
            net::set_socket_mark(socket_.native_handle(), connect_mark, ec);
            if (ec)
            {
                continue;
            }
        }

        co_await net::wait_connect_with_timeout(socket_, entry.endpoint(), cfg_.timeout.connect, ec);
        if (ec)
        {
            continue;
        }
        ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} out_tag {} stage set_no_delay socks server {}:{} error {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     outbound_tag_,
                     settings.host,
                     settings.port,
                     ec.message());
            ec.clear();
        }
        co_return true;
    }
    co_return false;
}

boost::asio::awaitable<bool> socks_upstream::do_password_auth(const config::socks_t& settings, boost::system::error_code& ec)
{
    if (settings.username.size() > 255 || settings.password.size() > 255)
    {
        ec = boost::asio::error::invalid_argument;
        co_return false;
    }

    std::vector<uint8_t> request;
    request.reserve(3 + settings.username.size() + settings.password.size());
    request.push_back(socks::kAuthVer);
    request.push_back(static_cast<uint8_t>(settings.username.size()));
    request.insert(request.end(), settings.username.begin(), settings.username.end());
    request.push_back(static_cast<uint8_t>(settings.password.size()));
    request.insert(request.end(), settings.password.begin(), settings.password.end());
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(request), cfg_.timeout.write, ec);
    if (ec)
    {
        co_return false;
    }

    uint8_t reply[2] = {0};
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(reply), cfg_.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }
    if (reply[0] != socks::kAuthVer || reply[1] != 0x00)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_upstream::negotiate_method(const config::socks_t& settings, boost::system::error_code& ec)
{
    const uint8_t method = settings.auth ? socks::kMethodPassword : socks::kMethodNoAuth;
    const uint8_t request[] = {socks::kVer, 0x01, method};
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(request), cfg_.timeout.write, ec);
    if (ec)
    {
        co_return false;
    }

    uint8_t reply[2] = {0};
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(reply), cfg_.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }
    if (reply[0] != socks::kVer || reply[1] == socks::kMethodNoAcceptable)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        co_return false;
    }
    if (reply[1] == socks::kMethodPassword)
    {
        co_return co_await do_password_auth(settings, ec);
    }
    if (reply[1] != socks::kMethodNoAuth)
    {
        ec = boost::asio::error::operation_not_supported;
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_upstream::send_connect_request(const std::string& host, const uint16_t port, boost::system::error_code& ec)
{
    std::vector<uint8_t> request = {socks::kVer, socks::kCmdConnect, 0x00};
    if (!append_socks_target_address(request, host))
    {
        ec = boost::asio::error::invalid_argument;
        co_return false;
    }
    request.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    request.push_back(static_cast<uint8_t>(port & 0xFF));
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(request), cfg_.timeout.write, ec);
    co_return !ec;
}

boost::asio::awaitable<bool> socks_upstream::read_connect_reply(upstream_connect_result& result, boost::system::error_code& ec)
{
    uint8_t header[4] = {0};
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(header), cfg_.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }
    if (header[0] != socks::kVer)
    {
        ec = boost::asio::error::invalid_argument;
        co_return false;
    }

    result.socks_rep = header[1];
    if (result.socks_rep != socks::kRepSuccess)
    {
        result.ec = map_socks_rep_to_connect_error(result.socks_rep);
        co_return false;
    }

    std::vector<uint8_t> address_bytes;
    if (header[3] == socks::kAtypIpv4)
    {
        address_bytes.resize(6);
    }
    else if (header[3] == socks::kAtypIpv6)
    {
        address_bytes.resize(18);
    }
    else if (header[3] == socks::kAtypDomain)
    {
        uint8_t domain_len = 0;
        co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&domain_len, 1), cfg_.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        address_bytes.resize(static_cast<std::size_t>(domain_len) + 2U);
        co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(address_bytes), cfg_.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        const std::string bind_host(address_bytes.begin(), address_bytes.end() - 2);
        bind_host_ = bind_host;
        bind_port_ = static_cast<uint16_t>((address_bytes[address_bytes.size() - 2] << 8) | address_bytes[address_bytes.size() - 1]);
        co_return true;
    }
    else
    {
        ec = boost::asio::error::address_family_not_supported;
        co_return false;
    }

    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(address_bytes), cfg_.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }

    if (header[3] == socks::kAtypIpv4)
    {
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy_n(address_bytes.begin(), 4, bytes.begin());
        result.bind_addr = boost::asio::ip::address_v4(bytes);
        result.bind_port = static_cast<uint16_t>((address_bytes[4] << 8) | address_bytes[5]);
    }
    else
    {
        boost::asio::ip::address_v6::bytes_type bytes{};
        std::copy_n(address_bytes.begin(), 16, bytes.begin());
        result.bind_addr = boost::asio::ip::address_v6(bytes);
        result.bind_port = static_cast<uint16_t>((address_bytes[16] << 8) | address_bytes[17]);
    }
    result.bind_addr = socks_codec::normalize_ip_address(result.bind_addr);
    result.has_bind_endpoint = true;
    bind_host_ = result.bind_addr.to_string();
    bind_port_ = result.bind_port;
    co_return true;
}

boost::asio::awaitable<upstream_connect_result> socks_upstream::connect(const std::string& host, uint16_t port)
{
    upstream_connect_result result;
    result.socks_rep = socks::kRepSuccess;
    target_host_ = host;
    target_port_ = port;
    bind_host_ = "unknown";
    bind_port_ = 0;

    const auto* outbound_settings = settings();
    if (outbound_settings == nullptr)
    {
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }

    boost::system::error_code ec;
    if (!(co_await connect_server(*outbound_settings, ec)))
    {
        result.ec = ec ? ec : boost::asio::error::host_unreachable;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    if (!(co_await negotiate_method(*outbound_settings, ec)))
    {
        result.ec = ec ? ec : boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    if (!(co_await send_connect_request(host, port, ec)))
    {
        result.ec = ec ? ec : boost::asio::error::operation_aborted;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    if (!(co_await read_connect_reply(result, ec)))
    {
        if (!result.ec)
        {
            result.ec = ec ? ec : boost::asio::error::operation_aborted;
        }
        if (result.socks_rep == socks::kRepSuccess)
        {
            result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        }
        co_return result;
    }

    LOG_INFO("{} trace {:016x} conn {} route proxy out_tag {} connected socks target {}:{} bind {}:{}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             outbound_tag_,
             host,
             port,
             bind_host_,
             bind_port_);
    co_return result;
}

boost::asio::awaitable<std::size_t> socks_upstream::read(std::vector<uint8_t>& buf, boost::system::error_code& ec)
{
    const auto bytes = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    co_return bytes;
}

boost::asio::awaitable<void> socks_upstream::write(const std::vector<uint8_t>& data, boost::system::error_code& ec)
{
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(data), cfg_.timeout.write, ec);
}

boost::asio::awaitable<void> socks_upstream::close()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = socket_.close(ec);
    co_return;
}

boost::asio::awaitable<void> socks_upstream::shutdown_send(boost::system::error_code& ec)
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

proxy_upstream::proxy_upstream(const boost::asio::any_io_executor& executor,
                               uint32_t conn_id,
                               uint64_t trace_id,
                               const config& cfg,
                               std::string outbound_tag)
    : cfg_(cfg), conn_id_(conn_id), trace_id_(trace_id), executor_(executor), outbound_tag_(std::move(outbound_tag))
{
}

std::shared_ptr<upstream> make_proxy_upstream(const boost::asio::any_io_executor& executor,
                                              uint32_t conn_id,
                                              uint64_t trace_id,
                                              const config& cfg,
                                              const std::string& outbound_tag)
{
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr)
    {
        return nullptr;
    }
    if (outbound->type == "reality")
    {
        return std::make_shared<proxy_upstream>(executor, conn_id, trace_id, cfg, outbound_tag);
    }
    if (outbound->type == "socks")
    {
        return std::make_shared<socks_upstream>(executor, conn_id, trace_id, cfg, outbound_tag);
    }
    return nullptr;
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
    connection_ = co_await proxy_reality_connection::connect(executor_, cfg_, outbound_tag_, conn_id_, ec);
    if (connection_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::not_connected;
        }
        LOG_ERROR("{} trace {:016x} conn {} target {}:{} route proxy out_tag {} connect reality failed {}",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  host,
                  port,
                  outbound_tag_,
                  ec.message());
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
        co_return result;
    }

    LOG_INFO("{} trace {:016x} conn {} target {}:{} route proxy out_tag {} connected reality local {}:{} remote {}:{}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             host,
             port,
             outbound_tag_,
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
