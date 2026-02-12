#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <iterator>
#include <system_error>

#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "tproxy_udp_sender.h"

namespace mux
{

namespace
{

constexpr std::size_t kMaxCachedSockets = 1024;
constexpr std::uint64_t kSocketIdleTimeoutMs = 300000;

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

}    // namespace

tproxy_udp_sender::tproxy_udp_sender(asio::io_context& io_context, const std::uint32_t mark) : io_context_(io_context), mark_(mark) {}

std::size_t tproxy_udp_sender::endpoint_hash::operator()(const endpoint_key& key) const
{
    const auto addr_text = key.addr.to_string();
    const std::size_t h1 = std::hash<std::string>()(addr_text);
    const std::size_t h2 = std::hash<std::uint16_t>()(key.port);
    return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
}

std::shared_ptr<asio::ip::udp::socket> tproxy_udp_sender::get_socket(const asio::ip::udp::endpoint& src_ep)
{
    const auto now = now_ms();
    const endpoint_key key{src_ep.address(), src_ep.port()};
    prune_sockets(now);
    if (const auto cached = get_cached_socket(key, now); cached != nullptr)
    {
        return cached;
    }

    if (sockets_.size() >= kMaxCachedSockets)
    {
        evict_oldest_socket();
    }

    const bool ipv6 = src_ep.address().is_v6();
    const auto socket = create_bound_socket(src_ep, ipv6);
    if (socket == nullptr)
    {
        return nullptr;
    }
    update_cached_socket(key, socket, now);
    return socket;
}

std::shared_ptr<asio::ip::udp::socket> tproxy_udp_sender::get_cached_socket(const endpoint_key& key, const std::uint64_t now_ms)
{
    auto it = sockets_.find(key);
    if (it == sockets_.end())
    {
        return nullptr;
    }
    it->second.last_used_ms = now_ms;
    return it->second.socket;
}

std::shared_ptr<asio::ip::udp::socket> tproxy_udp_sender::create_bound_socket(const asio::ip::udp::endpoint& src_ep, const bool ipv6)
{
    auto socket = std::make_shared<asio::ip::udp::socket>(io_context_);
    std::error_code ec;
    socket->open(ipv6 ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp open failed {}", ec.message());
        return nullptr;
    }

    if (!prepare_socket_options(socket, ipv6))
    {
        return nullptr;
    }

    if (!bind_socket_to_source(socket, src_ep))
    {
        return nullptr;
    }

    return socket;
}

bool tproxy_udp_sender::prepare_socket_options(const std::shared_ptr<asio::ip::udp::socket>& socket, const bool ipv6)
{
    std::error_code ec;
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
        return false;
    }

    if (mark_ != 0)
    {
        std::error_code mark_ec;
        if (!net::set_socket_mark(socket->native_handle(), mark_, mark_ec))
        {
            LOG_WARN("tproxy udp set mark failed {}", mark_ec.message());
        }
    }

    return true;
}

bool tproxy_udp_sender::bind_socket_to_source(const std::shared_ptr<asio::ip::udp::socket>& socket, const asio::ip::udp::endpoint& src_ep)
{
    std::error_code ec;
    ec = socket->bind(src_ep, ec);
    if (!ec)
    {
        return true;
    }

    LOG_WARN("tproxy udp bind failed {}", ec.message());
    return false;
}

void tproxy_udp_sender::update_cached_socket(const endpoint_key& key,
                                             const std::shared_ptr<asio::ip::udp::socket>& socket,
                                             const std::uint64_t now_ms)
{
    sockets_[key] = cached_socket{.socket = socket, .last_used_ms = now_ms};
}

void tproxy_udp_sender::prune_sockets(const std::uint64_t now_ms)
{
    for (auto it = sockets_.begin(); it != sockets_.end();)
    {
        const bool expired = now_ms > (it->second.last_used_ms + kSocketIdleTimeoutMs);
        const bool invalid = (it->second.socket == nullptr) || !it->second.socket->is_open();
        if (expired || invalid)
        {
            if (it->second.socket != nullptr)
            {
                std::error_code ignore;
                ignore = it->second.socket->close(ignore);
            }
            it = sockets_.erase(it);
            continue;
        }
        ++it;
    }
}

void tproxy_udp_sender::evict_oldest_socket()
{
    if (sockets_.empty())
    {
        return;
    }

    auto oldest_it = sockets_.begin();
    for (auto it = std::next(sockets_.begin()); it != sockets_.end(); ++it)
    {
        if (it->second.last_used_ms < oldest_it->second.last_used_ms)
        {
            oldest_it = it;
        }
    }

    if (oldest_it->second.socket != nullptr)
    {
        std::error_code ignore;
        ignore = oldest_it->second.socket->close(ignore);
    }
    sockets_.erase(oldest_it);
}

asio::awaitable<void> tproxy_udp_sender::send_to_client(const asio::ip::udp::endpoint& client_ep,
                                                        const asio::ip::udp::endpoint& src_ep,
                                                        const std::vector<std::uint8_t>& payload)
{
    co_await asio::dispatch(io_context_, asio::use_awaitable);

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
        const endpoint_key key{norm_src.address(), norm_src.port()};
        auto it = sockets_.find(key);
        if (it != sockets_.end() && it->second.socket == socket)
        {
            std::error_code ignore;
            ignore = it->second.socket->close(ignore);
            sockets_.erase(it);
        }
        co_return;
    }

    const endpoint_key key{norm_src.address(), norm_src.port()};
    auto it = sockets_.find(key);
    if (it != sockets_.end() && it->second.socket == socket)
    {
        it->second.last_used_ms = now_ms();
    }
}

}    // namespace mux
