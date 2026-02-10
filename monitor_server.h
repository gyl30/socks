#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

#include <memory>
#include <mutex>
#include <asio.hpp>

namespace mux
{

class monitor_server : public std::enable_shared_from_this<monitor_server>
{
   public:
    monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token);
    monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token, std::uint32_t min_interval_ms);
    void start();

   private:
    void do_accept();

    asio::ip::tcp::acceptor acceptor_;
    std::string token_;
    std::uint32_t min_interval_ms_ = 0;
    std::mutex rate_mutex_;
    std::chrono::steady_clock::time_point last_request_time_;
};

}    // namespace mux

#endif
