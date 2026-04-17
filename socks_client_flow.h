#ifndef SOCKS_CLIENT_FLOW_H
#define SOCKS_CLIENT_FLOW_H

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"

namespace relay::socks_client
{

[[nodiscard]] boost::asio::awaitable<bool> do_password_auth(
    boost::asio::ip::tcp::socket& socket, const config::socks_t& settings, const config& cfg, boost::system::error_code& ec);

[[nodiscard]] boost::asio::awaitable<bool> negotiate_method(
    boost::asio::ip::tcp::socket& socket, const config::socks_t& settings, const config& cfg, boost::system::error_code& ec);

[[nodiscard]] boost::asio::awaitable<bool> read_reply_address(
    boost::asio::ip::tcp::socket& socket, uint8_t atyp, const config& cfg, std::string& host, uint16_t& port, boost::system::error_code& ec);

}    // namespace relay::socks_client

#endif
