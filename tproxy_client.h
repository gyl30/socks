#ifndef TPROXY_CLIENT_H
#define TPROXY_CLIENT_H

#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "router.h"
#include "task_group.h"
#include "context_pool.h"
#include "client_tunnel_pool.h"

namespace mux
{

class tproxy_client : public std::enable_shared_from_this<tproxy_client>
{
   public:
    tproxy_client(io_context_pool& pool, const config& cfg);

   public:
    void start();
    void stop();

   private:
    boost::asio::awaitable<void> accept_tcp_loop();
    void on_tcp_socket(boost::asio::ip::tcp::socket&& socket);

   private:
    config cfg_;
    io_context_pool& pool_;
    boost::asio::io_context& io_context_;
    task_group group_{io_context_};
    std::shared_ptr<router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_{io_context_};
};

}    // namespace mux

#endif
