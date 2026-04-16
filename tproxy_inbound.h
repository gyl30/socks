#ifndef TPROXY_INBOUND_H
#define TPROXY_INBOUND_H

#include <list>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "tproxy_udp_session.h"

namespace relay
{

class tproxy_inbound : public std::enable_shared_from_this<tproxy_inbound>
{
   public:
    tproxy_inbound(io_context_pool& pool, const config& cfg, std::string inbound_tag, const config::tproxy_t& settings);

   public:
    void start();
    void stop();

   private:
    boost::asio::awaitable<void> start_listeners();
    boost::asio::awaitable<bool> handle_tcp_accept_error(boost::system::error_code& ec);
    boost::asio::awaitable<void> accept_tcp_loop();
    boost::asio::awaitable<void> accept_udp_loop();
    boost::asio::awaitable<void> process_udp_accept_event(std::vector<uint8_t>& payload);
    void on_tcp_socket(boost::asio::ip::tcp::socket&& socket);
    [[nodiscard]] boost::asio::awaitable<void> on_udp_packet(boost::asio::ip::udp::endpoint client_endpoint,
                                                             boost::asio::ip::udp::endpoint target_endpoint,
                                                             std::vector<uint8_t> payload);
    [[nodiscard]] bool is_udp_routing_loop(const boost::asio::ip::udp::endpoint& target_endpoint) const;
    [[nodiscard]] std::shared_ptr<tproxy_udp_session> find_udp_session(const std::string& key) const;
    [[nodiscard]] boost::asio::awaitable<void> enqueue_udp_session(const std::string& key,
                                                                   const std::shared_ptr<tproxy_udp_session>& session,
                                                                   std::vector<uint8_t> payload);
    [[nodiscard]] std::shared_ptr<tproxy_udp_session> make_udp_session(const std::string& key,
                                                                       const boost::asio::ip::udp::endpoint& client_endpoint,
                                                                       const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                       uint32_t conn_id);
    [[nodiscard]] bool register_udp_session(const std::string& key,
                                            const std::shared_ptr<tproxy_udp_session>& session,
                                            uint32_t conn_id,
                                            const boost::asio::ip::udp::endpoint& client_endpoint,
                                            const boost::asio::ip::udp::endpoint& target_endpoint);
    void touch_udp_session(const std::string& key);
    void evict_udp_sessions_if_needed();
    void erase_udp_session(const std::string& key);
    [[nodiscard]] static std::string make_udp_session_key(const boost::asio::ip::udp::endpoint& client_endpoint,
                                                          const boost::asio::ip::udp::endpoint& target_endpoint);

   private:
    const config& cfg_;
    std::string inbound_tag_;
    config::tproxy_t settings_;
    io_worker& owner_worker_;
    std::shared_ptr<router> router_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_{owner_worker_.io_context};
    boost::asio::ip::udp::socket udp_socket_{owner_worker_.io_context};
    std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>> udp_sessions_;
    std::list<std::string> udp_session_lru_;
    std::unordered_map<std::string, std::list<std::string>::iterator> udp_session_lru_index_;
    std::atomic<uint32_t> next_session_id_{1};
    std::atomic<bool> stopping_{false};
};

}    // namespace relay

#endif
