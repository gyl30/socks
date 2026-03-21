#ifndef TPROXY_CLIENT_H
#define TPROXY_CLIENT_H

#include <list>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "client_tunnel_pool.h"
#include "task_group_registry.h"

namespace mux
{

class tproxy_udp_session;

class tproxy_client : public std::enable_shared_from_this<tproxy_client>
{
   public:
    tproxy_client(io_context_pool& pool, const config& cfg);

   public:
    void start();
    void stop();
    boost::asio::awaitable<void> wait_stopped();

   private:
    boost::asio::awaitable<void> accept_tcp_loop();
    boost::asio::awaitable<void> accept_udp_loop();
    void on_tcp_socket(boost::asio::ip::tcp::socket&& socket);
    [[nodiscard]] boost::asio::awaitable<void> on_udp_packet(boost::asio::ip::udp::endpoint client_endpoint,
                                                             boost::asio::ip::udp::endpoint target_endpoint,
                                                             std::vector<std::uint8_t> payload);
    void touch_udp_session(const std::string& key);
    void evict_udp_sessions_if_needed();
    void erase_udp_session(const std::string& key);
    [[nodiscard]] static std::string make_udp_session_key(const boost::asio::ip::udp::endpoint& client_endpoint,
                                                          const boost::asio::ip::udp::endpoint& target_endpoint);

   private:
    config cfg_;
    boost::asio::io_context& io_context_;
    task_group_registry groups_;
    std::shared_ptr<router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_{io_context_};
    boost::asio::ip::udp::socket udp_socket_{io_context_};
    std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>> udp_sessions_;
    std::list<std::string> udp_session_lru_;
    std::unordered_map<std::string, std::list<std::string>::iterator> udp_session_lru_index_;
    std::atomic<bool> stopping_{false};
};

}    // namespace mux

#endif
