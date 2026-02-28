#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

#include <memory>
#include <string>
#include <cstdint>
#include "task_group.h"

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/consign.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>

namespace mux
{

class monitor_server : public std::enable_shared_from_this<monitor_server>
{
   public:
    monitor_server(boost::asio::io_context& ioc, std::uint16_t port);
    monitor_server(boost::asio::io_context& ioc, std::string bind_host, std::uint16_t port);

   public:
    int start();
    void stop();

   private:
    boost::asio::awaitable<void> accept_loop();
    boost::asio::awaitable<void> stop_accept();

   private:
    uint16_t port_;
    std::string host_;
    boost::asio::io_context& ioc_;
    task_group group_{ioc_};
    boost::asio::ip::tcp::acceptor acceptor_{ioc_};
};

}    // namespace mux

#endif
