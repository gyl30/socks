#include <array>
#include <cstddef>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "router.h"
#include "net_utils.h"
#include "context_pool.h"
#include "tproxy_client.h"
#include "client_tunnel_pool.h"
#include "tproxy_tcp_session.h"
#include "tproxy_udp_session.h"

#include <ranges>

namespace mux
{

namespace
{
void open_tcp_listener(boost::asio::ip::tcp::acceptor& acceptor, const std::string& host, uint16_t port, boost::system::error_code& ec)
{
    auto listen_addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        return;
    }

    const boost::asio::ip::tcp::endpoint ep{listen_addr, port};
    const bool is_v6 = listen_addr.is_v6();
    const bool enable_dual_stack = is_v6 && listen_addr.to_v6().is_unspecified();
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return;
    }
    ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        return;
    }
    if (enable_dual_stack)
    {
        ec = acceptor.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            return;
        }
    }
    net::set_socket_transparent(acceptor.native_handle(), is_v6, ec);
    if (ec)
    {
        return;
    }

    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        return;
    }
    ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        return;
    }
}

void open_udp_listener(boost::asio::ip::udp::socket& socket, const std::string& host, uint16_t port, boost::system::error_code& ec)
{
    auto listen_addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        return;
    }

    const boost::asio::ip::udp::endpoint endpoint{listen_addr, port};
    const bool is_v6 = listen_addr.is_v6();
    const bool enable_dual_stack = is_v6 && listen_addr.to_v6().is_unspecified();
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        return;
    }
    ec = socket.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return;
    }
    if (enable_dual_stack)
    {
        ec = socket.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            return;
        }
    }
    net::set_socket_transparent(socket.native_handle(), is_v6, ec);
    if (ec)
    {
        return;
    }
    net::set_socket_recv_origdst(socket.native_handle(), is_v6, ec);
    if (ec)
    {
        return;
    }
    ec = socket.bind(endpoint, ec);
}

}    // namespace

tproxy_client::tproxy_client(io_context_pool& pool, const config& cfg)
    : cfg_(cfg),
      owner_worker_(pool.get_io_worker()),
      router_(std::make_shared<router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg)),
      tcp_acceptor_(owner_worker_.io_context)
{
}

void tproxy_client::start()
{
    if (!cfg_.tproxy.enabled)
    {
        LOG_INFO("tproxy client disabled");
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        std::exit(EXIT_FAILURE);
    }

    if (cfg_.tproxy.tcp_port == 0 && cfg_.tproxy.udp_port == 0)
    {
        LOG_ERROR("tproxy tcp and udp ports are both zero");
        std::exit(EXIT_FAILURE);
    }

    tunnel_pool_->start();
    LOG_INFO("tproxy starting listeners on tcp:{} udp:{}", cfg_.tproxy.tcp_port, cfg_.tproxy.udp_port);
    owner_worker_.group.spawn([self = shared_from_this()]() { return self->start_listeners(); });
}

boost::asio::awaitable<void> tproxy_client::start_listeners()
{
    boost::system::error_code ec;
    if (cfg_.tproxy.tcp_port != 0)
    {
        open_tcp_listener(tcp_acceptor_, cfg_.tproxy.listen_host, cfg_.tproxy.tcp_port, ec);
        if (ec)
        {
            LOG_ERROR("tproxy tcp listen failed {}", ec.message());
            std::exit(EXIT_FAILURE);
        }
        LOG_INFO("tproxy tcp listening on {}:{}", cfg_.tproxy.listen_host, cfg_.tproxy.tcp_port);
    }
    if (cfg_.tproxy.udp_port != 0)
    {
        ec.clear();
        open_udp_listener(udp_socket_, cfg_.tproxy.listen_host, cfg_.tproxy.udp_port, ec);
        if (ec)
        {
            LOG_ERROR("tproxy udp listen failed {}", ec.message());
            std::exit(EXIT_FAILURE);
        }
        LOG_INFO("tproxy udp listening on {}:{}", cfg_.tproxy.listen_host, cfg_.tproxy.udp_port);
    }

    if (cfg_.tproxy.tcp_port != 0)
    {
        owner_worker_.group.spawn([self = shared_from_this()]() { return self->accept_tcp_loop(); });
    }
    if (cfg_.tproxy.udp_port != 0)
    {
        owner_worker_.group.spawn([self = shared_from_this()]() { return self->accept_udp_loop(); });
    }

    co_return;
}

void tproxy_client::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(owner_worker_.io_context,
                      [self = shared_from_this()]()
                      {
                          LOG_INFO("tproxy client stopping closing resources");

                          boost::system::error_code ec;
                          ec = self->tcp_acceptor_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("tproxy tcp acceptor close error {}", ec.message());
                          }
                          ec = self->udp_socket_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("tproxy udp socket close error {}", ec.message());
                          }

                          for (auto& session : self->udp_sessions_ | std::views::values)
                          {
                              if (session != nullptr)
                              {
                                  session->stop();
                              }
                          }
                          self->udp_sessions_.clear();
                          self->udp_session_lru_.clear();
                          self->udp_session_lru_index_.clear();

                          if (self->tunnel_pool_ != nullptr)
                          {
                              self->tunnel_pool_->stop();
                          }
                      });
}

boost::asio::awaitable<void> tproxy_client::accept_tcp_loop()
{
    boost::system::error_code ec;

    while (true)
    {
        boost::asio::ip::tcp::socket socket(owner_worker_.io_context);
        co_await tcp_acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_INFO("tproxy tcp accept loop stopped {}", ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("tproxy tcp accept failed {} retry", ec.message());
            ec = co_await net::wait_for(owner_worker_.io_context, std::chrono::seconds(3));
            if (ec)
            {
                LOG_ERROR("tproxy accept retry timer error {}", ec.message());
                break;
            }
            continue;
        }
        on_tcp_socket(std::move(socket));
    }

    LOG_INFO("tproxy tcp accept loop exited");
}

void tproxy_client::on_tcp_socket(boost::asio::ip::tcp::socket&& socket)
{
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy tcp set no delay failed code {}", ec.value());
    }

    const uint32_t sid = next_session_id_.fetch_add(1, std::memory_order_relaxed);
    const auto session = std::make_shared<tproxy_tcp_session>(std::move(socket), tunnel_pool_, router_, sid, cfg_);
    owner_worker_.group.spawn([session]() -> boost::asio::awaitable<void> { co_await session->start(); });
}

boost::asio::awaitable<void> tproxy_client::accept_udp_loop()
{
    boost::system::error_code ec;
    std::vector<uint8_t> payload(65535);
    std::array<char, CMSG_SPACE(sizeof(sockaddr_in6))> control{};

    while (true)
    {
        co_await udp_socket_.async_wait(boost::asio::ip::udp::socket::wait_read, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            break;
        }
        if (ec)
        {
            LOG_ERROR("tproxy udp wait failed {}", ec.message());
            break;
        }

        sockaddr_storage source_addr{};
        struct iovec iov{.iov_base = payload.data(), .iov_len = payload.size()};
        msghdr msg{};
        msg.msg_name = &source_addr;
        msg.msg_namelen = sizeof(source_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = control.size();

        const auto bytes_recv = recvmsg(udp_socket_.native_handle(), &msg, MSG_DONTWAIT);
        if (bytes_recv < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOG_ERROR("tproxy udp recv msg failed {}", std::strerror(errno));
            continue;
        }
        if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
        {
            LOG_WARN("tproxy udp recv msg truncated drop flags {} bytes {} controllen {}", msg.msg_flags, bytes_recv, msg.msg_controllen);
            continue;
        }

        const auto client_endpoint = net::normalize_endpoint(net::endpoint_from_sockaddr(source_addr, msg.msg_namelen));
        const auto target_endpoint_opt = net::parse_original_dst(msg);
        if (!target_endpoint_opt.has_value())
        {
            LOG_WARN("tproxy udp parse original dst failed");
            continue;
        }

        const auto target_endpoint = net::normalize_endpoint(*target_endpoint_opt);
        if (client_endpoint.port() == 0 || target_endpoint.port() == 0)
        {
            LOG_WARN("tproxy udp skip invalid endpoint");
            continue;
        }

        std::vector<uint8_t> packet(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(bytes_recv));
        co_await on_udp_packet(client_endpoint, target_endpoint, std::move(packet));
    }

    LOG_INFO("tproxy udp accept loop exited");
}

boost::asio::awaitable<void> tproxy_client::on_udp_packet(boost::asio::ip::udp::endpoint client_endpoint,
                                                          boost::asio::ip::udp::endpoint target_endpoint,
                                                          std::vector<uint8_t> payload)
{
    client_endpoint = net::normalize_endpoint(client_endpoint);
    target_endpoint = net::normalize_endpoint(target_endpoint);

    if (is_udp_routing_loop(target_endpoint))
    {
        LOG_WARN("tproxy udp routing loop detected drop");
        co_return;
    }

    const auto key = make_udp_session_key(client_endpoint, target_endpoint);
    if (auto session = find_udp_session(key); session != nullptr)
    {
        co_await enqueue_udp_session(key, session, std::move(payload));
        co_return;
    }

    const uint32_t conn_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);
    const auto route = co_await decide_udp_route(conn_id, target_endpoint);
    if (route == route_type::kBlock)
    {
        co_return;
    }

    if (auto session = find_udp_session(key); session != nullptr)
    {
        co_await enqueue_udp_session(key, session, std::move(payload));
        co_return;
    }

    auto session = make_udp_session(key, client_endpoint, target_endpoint, route, conn_id);
    const auto enqueue_result = co_await session->enqueue_packet(std::move(payload));
    if (enqueue_result != udp_enqueue_result::kEnqueued)
    {
        co_return;
    }
    if (!register_udp_session(key, session))
    {
        co_return;
    }
}

bool tproxy_client::is_udp_routing_loop(const boost::asio::ip::udp::endpoint& target_endpoint) const
{
    if (cfg_.tproxy.udp_port == 0)
    {
        return false;
    }

    boost::system::error_code addr_ec;
    const auto local_addr = boost::asio::ip::make_address(cfg_.tproxy.listen_host, addr_ec);
    if (addr_ec)
    {
        return false;
    }

    return target_endpoint.port() == cfg_.tproxy.udp_port && net::normalize_address(target_endpoint.address()) == net::normalize_address(local_addr);
}

boost::asio::awaitable<route_type> tproxy_client::decide_udp_route(uint32_t conn_id,
                                                                   const boost::asio::ip::udp::endpoint& target_endpoint) const
{
    route_type route = route_type::kProxy;
    if (router_ != nullptr)
    {
        route = co_await router_->decide_ip(target_endpoint.address());
    }

    LOG_INFO("event {} conn_id {} target {}:{} route {}",
             log_event::kRoute,
             conn_id,
             target_endpoint.address().to_string(),
             target_endpoint.port(),
             mux::to_string(route));
    if (route == route_type::kBlock)
    {
        LOG_INFO("event {} conn_id {} target {}:{} blocked",
                 log_event::kRoute,
                 conn_id,
                 target_endpoint.address().to_string(),
                 target_endpoint.port());
    }

    co_return route;
}

std::shared_ptr<tproxy_udp_session> tproxy_client::find_udp_session(const std::string& key) const
{
    const auto it = udp_sessions_.find(key);
    if (it == udp_sessions_.end())
    {
        return nullptr;
    }

    return it->second;
}

boost::asio::awaitable<void> tproxy_client::enqueue_udp_session(const std::string& key,
                                                                const std::shared_ptr<tproxy_udp_session>& session,
                                                                std::vector<uint8_t> payload)
{
    const auto enqueue_result = co_await session->enqueue_packet(std::move(payload));
    if (enqueue_result == udp_enqueue_result::kEnqueued)
    {
        touch_udp_session(key);
        co_return;
    }

    if (enqueue_result == udp_enqueue_result::kClosed)
    {
        erase_udp_session(key);
    }
}

std::shared_ptr<tproxy_udp_session> tproxy_client::make_udp_session(const std::string& key,
                                                                    const boost::asio::ip::udp::endpoint& client_endpoint,
                                                                    const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                    route_type route,
                                                                    uint32_t conn_id)
{
    const auto weak_self = weak_from_this();
    return std::make_shared<tproxy_udp_session>(owner_worker_,
                                                tunnel_pool_,
                                                client_endpoint,
                                                target_endpoint,
                                                route,
                                                conn_id,
                                                cfg_,
                                                [weak_self, key]()
                                                {
                                                    if (const auto self = weak_self.lock(); self != nullptr)
                                                    {
                                                        self->erase_udp_session(key);
                                                    }
                                                });
}

bool tproxy_client::register_udp_session(const std::string& key, const std::shared_ptr<tproxy_udp_session>& session)
{
    evict_udp_sessions_if_needed();
    if (udp_sessions_.size() >= constants::udp::kMaxSessions)
    {
        LOG_WARN("tproxy udp session limit reached drop packet");
        return false;
    }

    udp_sessions_.emplace(key, session);
    session->start();
    touch_udp_session(key);
    return true;
}

void tproxy_client::touch_udp_session(const std::string& key)
{
    const auto it = udp_session_lru_index_.find(key);
    if (it != udp_session_lru_index_.end())
    {
        udp_session_lru_.erase(it->second);
        udp_session_lru_index_.erase(it);
    }

    udp_session_lru_.push_back(key);
    auto tail = udp_session_lru_.end();
    --tail;
    udp_session_lru_index_[key] = tail;
}

void tproxy_client::evict_udp_sessions_if_needed()
{
    while (udp_sessions_.size() >= constants::udp::kMaxSessions)
    {
        if (udp_session_lru_.empty())
        {
            break;
        }

        const auto key = udp_session_lru_.front();
        udp_session_lru_.pop_front();
        udp_session_lru_index_.erase(key);

        const auto it = udp_sessions_.find(key);
        if (it == udp_sessions_.end())
        {
            continue;
        }
        if (it->second != nullptr)
        {
            it->second->stop();
        }
        udp_sessions_.erase(it);
    }
}

void tproxy_client::erase_udp_session(const std::string& key)
{
    udp_sessions_.erase(key);
    const auto it = udp_session_lru_index_.find(key);
    if (it != udp_session_lru_index_.end())
    {
        udp_session_lru_.erase(it->second);
        udp_session_lru_index_.erase(it);
    }
}

std::string tproxy_client::make_udp_session_key(const boost::asio::ip::udp::endpoint& client_endpoint,
                                                const boost::asio::ip::udp::endpoint& target_endpoint)
{
    const auto normalized_client = net::normalize_endpoint(client_endpoint);
    const auto normalized_target = net::normalize_endpoint(target_endpoint);
    return normalized_client.address().to_string() + "|" + std::to_string(normalized_client.port()) + "->" + normalized_target.address().to_string() +
           "|" + std::to_string(normalized_target.port());
}

}    // namespace mux
