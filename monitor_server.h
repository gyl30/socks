#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>

namespace mux
{

class monitor_server : public std::enable_shared_from_this<monitor_server>
{
   public:
    monitor_server(boost::asio::io_context& ioc, std::uint16_t port);
    monitor_server(boost::asio::io_context& ioc, std::string bind_host, std::uint16_t port);
    void start();
    void stop();
    [[nodiscard]] bool running() const
    {
        return started_.load(std::memory_order_acquire) && !stop_.load(std::memory_order_acquire) && acceptor_.is_open();
    }

   private:
    void stop_local();
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<std::vector<std::weak_ptr<boost::asio::ip::tcp::socket>>> active_sockets_ =
        std::make_shared<std::vector<std::weak_ptr<boost::asio::ip::tcp::socket>>>();
    std::atomic<bool> started_ = {false};
    std::atomic<bool> stop_ = {false};
};

}    // namespace mux

#endif
