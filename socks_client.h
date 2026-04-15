#ifndef SOCKS_CLIENT_H
#define SOCKS_CLIENT_H

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

enum class socks_client_state : uint8_t
{
    kStopped,
    kRunning,
    kStopping,
};

class socks_client : public std::enable_shared_from_this<socks_client>
{
   public:
    socks_client(io_context_pool& pool, const config& cfg);

    void start();
    void stop();

   private:
    boost::asio::awaitable<void> start_acceptor();
    boost::asio::awaitable<void> accept_loop();

   private:
    const config& cfg_;
    io_context_pool& pool_;
    io_worker& owner_worker_;
    boost::asio::ip::tcp::acceptor acceptor_{owner_worker_.io_context};
    std::shared_ptr<relay::router> router_;
    std::atomic<uint32_t> next_session_id_{1};
    std::atomic<bool> stopping_{false};
};

}    // namespace relay

#endif
