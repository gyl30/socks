#ifndef SOCKS_INBOUND_H
#define SOCKS_INBOUND_H

#include <atomic>
#include <memory>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"

namespace relay
{

class socks_inbound : public std::enable_shared_from_this<socks_inbound>
{
   public:
    socks_inbound(io_context_pool& pool, const config& cfg, std::string inbound_tag, const config::socks_t& settings);

    void start();
    void stop();

   private:
    boost::asio::awaitable<void> start_acceptor();
    boost::asio::awaitable<void> accept_loop();

   private:
    const config& cfg_;
    std::string inbound_tag_;
    config::socks_t settings_;
    io_context_pool& pool_;
    io_worker& owner_worker_;
    boost::asio::ip::tcp::acceptor acceptor_{owner_worker_.io_context};
    std::shared_ptr<relay::router> router_;
    std::atomic<uint32_t> next_session_id_{1};
    std::atomic<bool> stopping_{false};
};

}    // namespace relay

#endif
