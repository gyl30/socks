#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

#include <memory>
#include <asio.hpp>

namespace mux
{

class monitor_server : public std::enable_shared_from_this<monitor_server>
{
   public:
    monitor_server(asio::io_context& ioc, std::uint16_t port);
    void start();

   private:
    void do_accept();

    asio::ip::tcp::acceptor acceptor_;
};

}    // namespace mux

#endif
