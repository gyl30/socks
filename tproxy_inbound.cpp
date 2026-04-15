#include <array>
#include <cerrno>
#include <chrono>
#include <memory>
#include <ranges>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "constants.h"
#include "net_utils.h"
#include "context_pool.h"
#include "tproxy_inbound.h"
#include "tproxy_tcp_session.h"
#include "tproxy_udp_session.h"

namespace relay
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

tproxy_inbound::tproxy_inbound(io_context_pool& pool, const config& cfg, std::string inbound_tag, const config::tproxy_t& settings)
    : cfg_(cfg),
      inbound_tag_(std::move(inbound_tag)),
      settings_(settings),
      owner_worker_(pool.get_io_worker()),
      router_(std::make_shared<router>(cfg_, inbound_tag_)),
      tcp_acceptor_(owner_worker_.io_context)
{
}

void tproxy_inbound::start()
{
    if (!router_->load())
    {
        LOG_ERROR("{} stage start load router data failed", log_event::kConnInit);
        std::exit(EXIT_FAILURE);
    }

    if (settings_.tcp_port == 0 && settings_.udp_port == 0)
    {
        LOG_ERROR("{} inbound_tag {} stage start listen {} tcp_port {} udp_port {} both zero",
                  log_event::kConnInit,
                  inbound_tag_,
                  settings_.listen_host,
                  settings_.tcp_port,
                  settings_.udp_port);
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("{} inbound_tag {} listen {} tcp_port {} udp_port {} tproxy starting listeners",
             log_event::kConnInit,
             inbound_tag_,
             settings_.listen_host,
             settings_.tcp_port,
             settings_.udp_port);
    owner_worker_.group.spawn([self = shared_from_this()]() { return self->start_listeners(); });
}

boost::asio::awaitable<void> tproxy_inbound::start_listeners()
{
    boost::system::error_code ec;
    if (settings_.tcp_port != 0)
    {
        open_tcp_listener(tcp_acceptor_, settings_.listen_host, settings_.tcp_port, ec);
        if (ec)
        {
            LOG_ERROR("{} inbound_tag {} listen {}:{} tcp listen failed {}",
                      log_event::kConnInit,
                      inbound_tag_,
                      settings_.listen_host,
                      settings_.tcp_port,
                      ec.message());
            std::exit(EXIT_FAILURE);
        }
        LOG_INFO("{} inbound_tag {} listen {}:{} tproxy tcp listening on {}:{}",
                 log_event::kConnInit,
                 inbound_tag_,
                 settings_.listen_host,
                 settings_.tcp_port,
                 settings_.listen_host,
                 settings_.tcp_port);
    }
    if (settings_.udp_port != 0)
    {
        open_udp_listener(udp_socket_, settings_.listen_host, settings_.udp_port, ec);
        if (ec)
        {
            LOG_ERROR("{} inbound_tag {} listen {}:{} udp listen failed {}",
                      log_event::kConnInit,
                      inbound_tag_,
                      settings_.listen_host,
                      settings_.udp_port,
                      ec.message());
            std::exit(EXIT_FAILURE);
        }
        LOG_INFO("{} inbound_tag {} listen {}:{} tproxy udp listening on {}:{}",
                 log_event::kConnInit,
                 inbound_tag_,
                 settings_.listen_host,
                 settings_.udp_port,
                 settings_.listen_host,
                 settings_.udp_port);
    }

    if (settings_.tcp_port != 0)
    {
        owner_worker_.group.spawn([self = shared_from_this()]() { return self->accept_tcp_loop(); });
    }
    if (settings_.udp_port != 0)
    {
        owner_worker_.group.spawn([self = shared_from_this()]() { return self->accept_udp_loop(); });
    }

    co_return;
}

void tproxy_inbound::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(owner_worker_.io_context,
                      [self = shared_from_this()]()
                      {
                          LOG_INFO("{} listen {} tcp_port {} udp_port {} tproxy inbound stopping closing resources",
                                   log_event::kConnClose,
                                   self->settings_.listen_host,
                                   self->settings_.tcp_port,
                                   self->settings_.udp_port);

                          boost::system::error_code ec;
                          ec = self->tcp_acceptor_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("{} listen {}:{} tcp acceptor close failed {}",
                                        log_event::kConnClose,
                                        self->settings_.listen_host,
                                        self->settings_.tcp_port,
                                        ec.message());
                          }
                          ec = self->udp_socket_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("{} listen {}:{} udp socket close failed {}",
                                        log_event::kConnClose,
                                        self->settings_.listen_host,
                                        self->settings_.udp_port,
                                        ec.message());
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
                      });
}

boost::asio::awaitable<void> tproxy_inbound::accept_tcp_loop()
{
    boost::system::error_code ec;

    while (true)
    {
        boost::asio::ip::tcp::socket socket(owner_worker_.io_context);
        co_await tcp_acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_INFO("{} listen {}:{} tcp accept loop stopped {}", log_event::kConnClose, settings_.listen_host, settings_.tcp_port, ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("{} listen {}:{} tcp accept failed {} retry", log_event::kConnInit, settings_.listen_host, settings_.tcp_port, ec.message());
            ec = co_await net::wait_for(owner_worker_.io_context, std::chrono::seconds(3));
            if (ec)
            {
                LOG_ERROR("{} listen {}:{} tcp accept retry timer failed {}",
                          log_event::kConnInit,
                          settings_.listen_host,
                          settings_.tcp_port,
                          ec.message());
                break;
            }
            continue;
        }
        on_tcp_socket(std::move(socket));
    }

    LOG_INFO("{} listen {}:{} tcp accept loop exited", log_event::kConnClose, settings_.listen_host, settings_.tcp_port);
}

void tproxy_inbound::on_tcp_socket(boost::asio::ip::tcp::socket&& socket)
{
    boost::system::error_code local_ec;
    const auto local_ep = socket.local_endpoint(local_ec);
    boost::system::error_code peer_ec;
    const auto peer_ep = socket.remote_endpoint(peer_ec);
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    const uint32_t sid = next_session_id_.fetch_add(1, std::memory_order_relaxed);
    LOG_INFO("{} conn {} local {}:{} remote {}:{} accepted",
             log_event::kConnInit,
             sid,
             local_ec ? "unknown" : net::normalize_address(local_ep.address()).to_string(),
             local_ec ? 0 : local_ep.port(),
             peer_ec ? "unknown" : net::normalize_address(peer_ep.address()).to_string(),
             peer_ec ? 0 : peer_ep.port());
    if (ec)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} set no delay failed code {} error {}",
                 log_event::kConnInit,
                 sid,
                 local_ec ? "unknown" : net::normalize_address(local_ep.address()).to_string(),
                 local_ec ? 0 : local_ep.port(),
                 peer_ec ? "unknown" : net::normalize_address(peer_ep.address()).to_string(),
                 peer_ec ? 0 : peer_ep.port(),
                 ec.value(),
                 ec.message());
    }

    const auto session = std::make_shared<tproxy_tcp_session>(std::move(socket), router_, sid, cfg_, settings_);
    owner_worker_.group.spawn([session]() -> boost::asio::awaitable<void> { co_await session->start(); });
}

boost::asio::awaitable<void> tproxy_inbound::accept_udp_loop()
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
            LOG_ERROR("{} listen {}:{} udp wait failed {}", log_event::kConnInit, settings_.listen_host, settings_.udp_port, ec.message());
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
            LOG_ERROR("{} listen {}:{} udp recv msg failed errno {} error {}",
                      log_event::kConnInit,
                      settings_.listen_host,
                      settings_.udp_port,
                      errno,
                      std::strerror(errno));
            continue;
        }
        if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
        {
            LOG_WARN("{} listen {}:{} udp recv msg truncated drop flags {} bytes {} controllen {}",
                     log_event::kConnInit,
                     settings_.listen_host,
                     settings_.udp_port,
                     msg.msg_flags,
                     bytes_recv,
                     msg.msg_controllen);
            continue;
        }

        const auto client_endpoint = net::normalize_endpoint(net::endpoint_from_sockaddr(source_addr, msg.msg_namelen));
        const auto target_endpoint_opt = net::parse_original_dst(msg);
        if (!target_endpoint_opt.has_value())
        {
            LOG_WARN("{} client {}:{} udp parse original dst failed bytes {} flags {}",
                     log_event::kConnInit,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     bytes_recv,
                     msg.msg_flags);
            continue;
        }

        const auto target_endpoint = net::normalize_endpoint(*target_endpoint_opt);
        if (client_endpoint.port() == 0 || target_endpoint.port() == 0)
        {
            LOG_WARN("{} client {}:{} target {}:{} udp skip invalid endpoint bytes {}",
                     log_event::kConnInit,
                     client_endpoint.address().to_string(),
                     client_endpoint.port(),
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     bytes_recv);
            continue;
        }

        std::vector<uint8_t> packet(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(bytes_recv));
        co_await on_udp_packet(client_endpoint, target_endpoint, std::move(packet));
    }

    LOG_INFO("{} listen {}:{} udp accept loop exited", log_event::kConnClose, settings_.listen_host, settings_.udp_port);
}

boost::asio::awaitable<void> tproxy_inbound::on_udp_packet(boost::asio::ip::udp::endpoint client_endpoint,
                                                           boost::asio::ip::udp::endpoint target_endpoint,
                                                           std::vector<uint8_t> payload)
{
    client_endpoint = net::normalize_endpoint(client_endpoint);
    target_endpoint = net::normalize_endpoint(target_endpoint);

    if (is_udp_routing_loop(target_endpoint))
    {
        LOG_WARN("{} client {}:{} target {}:{} udp routing loop detected drop",
                 log_event::kConnInit,
                 client_endpoint.address().to_string(),
                 client_endpoint.port(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port());
        co_return;
    }

    const auto key = make_udp_session_key(client_endpoint, target_endpoint);
    if (auto session = find_udp_session(key); session != nullptr)
    {
        co_await enqueue_udp_session(key, session, std::move(payload));
        co_return;
    }

    const uint32_t conn_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);
    const auto decision = co_await decide_udp_route(conn_id, target_endpoint);
    if (decision.route == route_type::kBlock)
    {
        co_return;
    }

    if (auto session = find_udp_session(key); session != nullptr)
    {
        co_await enqueue_udp_session(key, session, std::move(payload));
        co_return;
    }

    auto session = make_udp_session(key, client_endpoint, target_endpoint, decision.route, decision.outbound_tag, conn_id);
    const auto enqueue_result = co_await session->enqueue_packet(std::move(payload));
    if (enqueue_result != udp_enqueue_result::kEnqueued)
    {
        co_return;
    }
    if (!register_udp_session(key, session, conn_id, client_endpoint, target_endpoint, decision.route))
    {
        co_return;
    }
}

bool tproxy_inbound::is_udp_routing_loop(const boost::asio::ip::udp::endpoint& target_endpoint) const
{
    if (settings_.udp_port == 0)
    {
        return false;
    }

    boost::system::error_code addr_ec;
    const auto local_addr = boost::asio::ip::make_address(settings_.listen_host, addr_ec);
    if (addr_ec)
    {
        return false;
    }

    return target_endpoint.port() == settings_.udp_port && net::normalize_address(target_endpoint.address()) == net::normalize_address(local_addr);
}

boost::asio::awaitable<route_decision> tproxy_inbound::decide_udp_route(uint32_t conn_id,
                                                                        const boost::asio::ip::udp::endpoint& target_endpoint) const
{
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    if (router_ != nullptr)
    {
        decision = co_await router_->decide_ip_detail(target_endpoint.address());
    }

    LOG_INFO("{} conn {} target {}:{} route {} out_tag {}",
             log_event::kRoute,
             conn_id,
             target_endpoint.address().to_string(),
             target_endpoint.port(),
             relay::to_string(decision.route),
             decision.outbound_tag.empty() ? "-" : decision.outbound_tag);
    if (decision.route == route_type::kBlock)
    {
        LOG_INFO("{} conn {} target {}:{} blocked", log_event::kRoute, conn_id, target_endpoint.address().to_string(), target_endpoint.port());
    }

    co_return decision;
}

std::shared_ptr<tproxy_udp_session> tproxy_inbound::find_udp_session(const std::string& key) const
{
    const auto it = udp_sessions_.find(key);
    if (it == udp_sessions_.end())
    {
        return nullptr;
    }

    return it->second;
}

boost::asio::awaitable<void> tproxy_inbound::enqueue_udp_session(const std::string& key,
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

std::shared_ptr<tproxy_udp_session> tproxy_inbound::make_udp_session(const std::string& key,
                                                                     const boost::asio::ip::udp::endpoint& client_endpoint,
                                                                     const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                     route_type route,
                                                                     const std::string& outbound_tag,
                                                                     uint32_t conn_id)
{
    const auto weak_self = weak_from_this();
    return std::make_shared<tproxy_udp_session>(owner_worker_,
                                                client_endpoint,
                                                target_endpoint,
                                                route,
                                                outbound_tag,
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

bool tproxy_inbound::register_udp_session(const std::string& key,
                                          const std::shared_ptr<tproxy_udp_session>& session,
                                          uint32_t conn_id,
                                          const boost::asio::ip::udp::endpoint& client_endpoint,
                                          const boost::asio::ip::udp::endpoint& target_endpoint,
                                          route_type route)
{
    evict_udp_sessions_if_needed();
    if (udp_sessions_.size() >= constants::udp::kMaxSessions)
    {
        LOG_WARN("{} conn {} client {}:{} target {}:{} route {} udp session limit reached active {} limit {} drop packet",
                 log_event::kConnInit,
                 conn_id,
                 client_endpoint.address().to_string(),
                 client_endpoint.port(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port(),
                 relay::to_string(route),
                 udp_sessions_.size(),
                 constants::udp::kMaxSessions);
        return false;
    }

    udp_sessions_.emplace(key, session);
    session->start();
    LOG_INFO("{} conn {} client {}:{} target {}:{} route {} udp session registered active {}",
             log_event::kConnEstablished,
             conn_id,
             client_endpoint.address().to_string(),
             client_endpoint.port(),
             target_endpoint.address().to_string(),
             target_endpoint.port(),
             relay::to_string(route),
             udp_sessions_.size());
    touch_udp_session(key);
    return true;
}

void tproxy_inbound::touch_udp_session(const std::string& key)
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

void tproxy_inbound::evict_udp_sessions_if_needed()
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

void tproxy_inbound::erase_udp_session(const std::string& key)
{
    udp_sessions_.erase(key);
    const auto it = udp_session_lru_index_.find(key);
    if (it != udp_session_lru_index_.end())
    {
        udp_session_lru_.erase(it->second);
        udp_session_lru_index_.erase(it);
    }
}

std::string tproxy_inbound::make_udp_session_key(const boost::asio::ip::udp::endpoint& client_endpoint,
                                                 const boost::asio::ip::udp::endpoint& target_endpoint)
{
    const auto normalized_client = net::normalize_endpoint(client_endpoint);
    const auto normalized_target = net::normalize_endpoint(target_endpoint);
    return normalized_client.address().to_string() + "|" + std::to_string(normalized_client.port()) + "->" + normalized_target.address().to_string() +
           "|" + std::to_string(normalized_target.port());
}

}    // namespace relay
