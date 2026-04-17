#include <vector>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/errc.hpp>

#include "config.h"
#include "net_utils.h"
#include "protocol.h"
#include "socks_client_flow.h"

namespace relay::socks_client
{

boost::asio::awaitable<bool> do_password_auth(
    boost::asio::ip::tcp::socket& socket, const config::socks_t& settings, const config& cfg, boost::system::error_code& ec)
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
    co_await net::wait_write_with_timeout(socket, boost::asio::buffer(request), cfg.timeout.write, ec);
    if (ec)
    {
        co_return false;
    }

    uint8_t reply[2] = {0};
    co_await net::wait_read_with_timeout(socket, boost::asio::buffer(reply), cfg.timeout.read, ec);
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

boost::asio::awaitable<bool> negotiate_method(
    boost::asio::ip::tcp::socket& socket, const config::socks_t& settings, const config& cfg, boost::system::error_code& ec)
{
    const uint8_t method = settings.auth ? socks::kMethodPassword : socks::kMethodNoAuth;
    const uint8_t request[] = {socks::kVer, 0x01, method};
    co_await net::wait_write_with_timeout(socket, boost::asio::buffer(request), cfg.timeout.write, ec);
    if (ec)
    {
        co_return false;
    }

    uint8_t reply[2] = {0};
    co_await net::wait_read_with_timeout(socket, boost::asio::buffer(reply), cfg.timeout.read, ec);
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
        co_return co_await do_password_auth(socket, settings, cfg, ec);
    }
    if (reply[1] != socks::kMethodNoAuth)
    {
        ec = boost::asio::error::operation_not_supported;
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> read_reply_address(
    boost::asio::ip::tcp::socket& socket, const uint8_t atyp, const config& cfg, std::string& host, uint16_t& port, boost::system::error_code& ec)
{
    std::vector<uint8_t> payload;
    if (atyp == socks::kAtypIpv4)
    {
        payload.resize(6);
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(payload), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy_n(payload.begin(), 4, bytes.begin());
        host = boost::asio::ip::address_v4(bytes).to_string();
        port = static_cast<uint16_t>((payload[4] << 8) | payload[5]);
        co_return true;
    }

    if (atyp == socks::kAtypIpv6)
    {
        payload.resize(18);
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(payload), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        boost::asio::ip::address_v6::bytes_type bytes{};
        std::copy_n(payload.begin(), 16, bytes.begin());
        host = boost::asio::ip::address_v6(bytes).to_string();
        port = static_cast<uint16_t>((payload[16] << 8) | payload[17]);
        co_return true;
    }

    if (atyp == socks::kAtypDomain)
    {
        uint8_t length = 0;
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(&length, 1), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        payload.resize(static_cast<std::size_t>(length) + 2U);
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(payload), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        host.assign(payload.begin(), payload.end() - 2);
        port = static_cast<uint16_t>((payload[payload.size() - 2] << 8) | payload[payload.size() - 1]);
        co_return true;
    }

    ec = boost::asio::error::address_family_not_supported;
    co_return false;
}

}    // namespace relay::socks_client
