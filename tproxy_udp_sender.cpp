#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <functional>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "tproxy_udp_sender.h"

namespace mux
{

namespace
{

constexpr std::size_t kMaxCachedSockets = 1024;
constexpr std::uint64_t kSocketIdleTimeoutMs = 300000;
constexpr std::uint64_t kSocketPruneIntervalMs = 1000;

template <typename ByteContainer>
std::size_t hash_bytes(const ByteContainer& bytes)
{
    std::size_t hash = 1469598103934665603ULL;
    for (const auto byte : bytes)
    {
        hash ^= static_cast<std::size_t>(byte);
        hash *= 1099511628211ULL;
    }
    return hash;
}

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

[[nodiscard]] bool is_valid_udp_endpoint(const boost::asio::ip::udp::endpoint& endpoint)
{
    return !endpoint.address().is_unspecified() && endpoint.port() != 0;
}

}    // namespace

tproxy_udp_sender::tproxy_udp_sender(boost::asio::io_context& io_context, const std::uint32_t mark) : io_context_(io_context), mark_(mark) {}

std::size_t tproxy_udp_sender::endpoint_hash::operator()(const endpoint_key& key) const
{
    std::size_t h1 = 0;
    if (key.addr.is_v4())
    {
        h1 = hash_bytes(key.addr.to_v4().to_bytes()) ^ 0x4ULL;
    }
    else if (key.addr.is_v6())
    {
        h1 = hash_bytes(key.addr.to_v6().to_bytes()) ^ 0x6ULL;
    }
    else
    {
        h1 = std::hash<std::string>()(key.addr.to_string());
    }
    const std::size_t h2 = std::hash<std::uint16_t>()(key.port);
    return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
}

std::shared_ptr<boost::asio::ip::udp::socket> tproxy_udp_sender::get_socket(const boost::asio::ip::udp::endpoint& src_ep)
{
    const auto now = now_ms();
    const endpoint_key key{.addr = src_ep.address(), .port = src_ep.port()};
    if (last_prune_ms_ == 0 || now >= (last_prune_ms_ + kSocketPruneIntervalMs))
    {
        prune_sockets(now);
        last_prune_ms_ = now;
    }
    if (const auto cached = get_cached_socket(key, now); cached != nullptr)
    {
        return cached;
    }

    if (sockets_.size() >= kMaxCachedSockets)
    {
        evict_oldest_socket();
    }

    const bool ipv6 = src_ep.address().is_v6();
    auto socket = create_bound_socket(src_ep, ipv6);
    if (socket == nullptr)
    {
        return nullptr;
    }
    update_cached_socket(key, socket, now);
    return socket;
}

std::shared_ptr<boost::asio::ip::udp::socket> tproxy_udp_sender::get_cached_socket(const endpoint_key& key, const std::uint64_t now_ms)
{
    auto it = sockets_.find(key);
    if (it == sockets_.end())
    {
        return nullptr;
    }
    it->second.last_used_ms = now_ms;
    return it->second.socket;
}

std::shared_ptr<boost::asio::ip::udp::socket> tproxy_udp_sender::create_bound_socket(const boost::asio::ip::udp::endpoint& src_ep, const bool ipv6)
{
    auto socket = std::make_shared<boost::asio::ip::udp::socket>(io_context_);
    boost::system::error_code ec;
    ec = socket->open(ipv6 ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4(), ec);
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

bool tproxy_udp_sender::prepare_socket_options(const std::shared_ptr<boost::asio::ip::udp::socket>& socket, const bool ipv6)
{
    if (ipv6)
    {
        (void)set_ipv6_dual_stack_option(socket);
    }
    set_reuse_address_option(socket);
    if (!set_transparent_option(socket, ipv6))
    {
        return false;
    }
    apply_socket_mark(socket);
    return true;
}

bool tproxy_udp_sender::set_ipv6_dual_stack_option(const std::shared_ptr<boost::asio::ip::udp::socket>& socket)
{
    boost::system::error_code ec;
    ec = socket->set_option(boost::asio::ip::v6_only(false), ec);
    if (!ec)
    {
        return true;
    }
    LOG_WARN("tproxy udp v6 only failed {}", ec.message());
    return false;
}

void tproxy_udp_sender::set_reuse_address_option(const std::shared_ptr<boost::asio::ip::udp::socket>& socket)
{
    boost::system::error_code ec;
    ec = socket->set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp reuse addr failed {}", ec.message());
    }
}

bool tproxy_udp_sender::set_transparent_option(const std::shared_ptr<boost::asio::ip::udp::socket>& socket, const bool ipv6)
{
    if (auto r = net::set_socket_transparent(socket->native_handle(), ipv6); !r)
    {
        LOG_WARN("tproxy udp transparent failed {}", r.error().message());
        return false;
    }
    return true;
}

void tproxy_udp_sender::apply_socket_mark(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) const
{
    if (mark_ == 0)
    {
        return;
    }
    if (auto r = net::set_socket_mark(socket->native_handle(), mark_); !r)
    {
        LOG_WARN("tproxy udp set mark failed {}", r.error().message());
    }
}

bool tproxy_udp_sender::bind_socket_to_source(const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                                              const boost::asio::ip::udp::endpoint& src_ep)
{
    boost::system::error_code ec;
    ec = socket->bind(src_ep, ec);
    if (!ec)
    {
        return true;
    }

    LOG_WARN("tproxy udp bind failed {}", ec.message());
    return false;
}

void tproxy_udp_sender::update_cached_socket(const endpoint_key& key,
                                             const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
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
                boost::system::error_code ignore;
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
        boost::system::error_code ignore;
        ignore = oldest_it->second.socket->close(ignore);
    }
    sockets_.erase(oldest_it);
}

void tproxy_udp_sender::drop_cached_socket_if_match(const endpoint_key& key, const std::shared_ptr<boost::asio::ip::udp::socket>& socket)
{
    auto it = sockets_.find(key);
    if (it == sockets_.end() || it->second.socket != socket)
    {
        return;
    }
    boost::system::error_code ignore;
    ignore = it->second.socket->close(ignore);
    sockets_.erase(it);
}

void tproxy_udp_sender::refresh_cached_socket_timestamp(const endpoint_key& key, const std::shared_ptr<boost::asio::ip::udp::socket>& socket)
{
    auto it = sockets_.find(key);
    if (it != sockets_.end() && it->second.socket == socket)
    {
        it->second.last_used_ms = now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_sender::send_to_client(const boost::asio::ip::udp::endpoint& client_ep,
                                                               const boost::asio::ip::udp::endpoint& src_ep,
                                                               const boost::asio::const_buffer payload)
{
    co_await boost::asio::dispatch(io_context_, boost::asio::use_awaitable);

    const auto norm_src = net::normalize_endpoint(src_ep);
    const auto norm_client = net::normalize_endpoint(client_ep);
    if (!is_valid_udp_endpoint(norm_src) || !is_valid_udp_endpoint(norm_client))
    {
        LOG_WARN("tproxy udp invalid endpoint src {} {} dst {} {}", norm_src.address().to_string(), norm_src.port(), norm_client.address().to_string(), norm_client.port());
        co_return;
    }
    auto socket = get_socket(norm_src);
    if (socket == nullptr)
    {
        co_return;
    }

    const auto [ec, n] = co_await socket->async_send_to(payload, norm_client, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        LOG_WARN("tproxy udp send to client failed {}", ec.message());
        drop_cached_socket_if_match(endpoint_key{.addr = norm_src.address(), .port = norm_src.port()}, socket);
        co_return;
    }
    refresh_cached_socket_timestamp(endpoint_key{.addr = norm_src.address(), .port = norm_src.port()}, socket);
}

boost::asio::awaitable<void> tproxy_udp_sender::send_to_client(const boost::asio::ip::udp::endpoint& client_ep,
                                                               const boost::asio::ip::udp::endpoint& src_ep,
                                                               std::vector<std::uint8_t> payload)
{
    co_await send_to_client(client_ep, src_ep, boost::asio::buffer(payload));
}

}    // namespace mux
