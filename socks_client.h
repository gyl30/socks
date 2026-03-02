#ifndef SOCKS_CLIENT_H
#define SOCKS_CLIENT_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include "config.h"
#include "router.h"
#include "task_group.h"
#include "context_pool.h"
#include "client_tunnel_pool.h"

namespace mux
{

class socks_session;
class tcp_socks_session;
class udp_socks_session;

enum class socks_client_state : std::uint8_t
{
    kStopped,
    kRunning,
    kStopping,
};

class socks_client : public std::enable_shared_from_this<socks_client>
{
   public:
    socks_client(io_context_pool& pool, const config& cfg);

    int start();
    void stop();

   private:
    boost::asio::awaitable<void> accept_loop();
    boost::asio::awaitable<void> stop_accept();

   private:
    const config& cfg_;
    boost::asio::io_context& ioc_;
    io_context_pool& pool_;
    task_group group_{ioc_};
    boost::asio::ip::tcp::acceptor acceptor_{ioc_};
    std::shared_ptr<mux::router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
};

}    // namespace mux

#endif
