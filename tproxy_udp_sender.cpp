#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#include <asio/buffer.hpp>
#include <asio/strand.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "tproxy_udp_sender.h"

namespace mux
{

tproxy_udp_sender::tproxy_udp_sender(const asio::any_io_executor& ex, const std::uint32_t mark) : ex_(ex), mark_(mark) {}

std::size_t tproxy_udp_sender::endpoint_hash::operator()(const endpoint_key& key) const
{
    const auto addr_text = key.addr.to_string();
    const std::size_t h1 = std::hash<std::string>()(addr_text);
    const std::size_t h2 = std::hash<std::uint16_t>()(key.port);
    return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
}

std::shared_ptr<asio::ip::udp::socket> tproxy_udp_sender::get_socket(const asio::ip::udp::endpoint& src_ep)
{
    const endpoint_key key{src_ep.address(), src_ep.port()};
    const std::lock_guard<std::mutex> lock(socket_mutex_);
    auto it = sockets_.find(key);
    if (it != sockets_.end())
    {
        return it->second;
    }

    auto socket = std::make_shared<asio::ip::udp::socket>(asio::make_strand(ex_));
    std::error_code ec;
    const bool ipv6 = src_ep.address().is_v6();
    socket->open(ipv6 ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp open failed {}", ec.message());
        return nullptr;
    }

    if (ipv6)
    {
        ec = socket->set_option(asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_WARN("tproxy udp v6 only failed {}", ec.message());
        }
    }

    ec = socket->set_option(asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp reuse addr failed {}", ec.message());
    }

    std::error_code trans_ec;
    if (!net::set_socket_transparent(socket->native_handle(), ipv6, trans_ec))
    {
        LOG_WARN("tproxy udp transparent failed {}", trans_ec.message());
        return nullptr;
    }

    if (mark_ != 0)
    {
        std::error_code mark_ec;
        if (!net::set_socket_mark(socket->native_handle(), mark_, mark_ec))
        {
            LOG_WARN("tproxy udp set mark failed {}", mark_ec.message());
        }
    }

    ec = socket->bind(src_ep, ec);
    if (ec)
    {
        LOG_WARN("tproxy udp bind failed {}", ec.message());
        return nullptr;
    }

    sockets_[key] = socket;
    return socket;
}

asio::awaitable<void> tproxy_udp_sender::send_to_client(const asio::ip::udp::endpoint& client_ep,
                                                        const asio::ip::udp::endpoint& src_ep,
                                                        const std::vector<std::uint8_t>& payload)
{
    const auto norm_src = net::normalize_endpoint(src_ep);
    const auto norm_client = net::normalize_endpoint(client_ep);
    auto socket = get_socket(norm_src);
    if (socket == nullptr)
    {
        co_return;
    }

    const auto [ec, n] = co_await socket->async_send_to(asio::buffer(payload), norm_client, asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_WARN("tproxy udp send to client failed {}", ec.message());
    }
}

}    // namespace mux
