#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

#include <mutex>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <asio.hpp>

namespace mux
{

struct monitor_rate_state
{
    std::mutex mutex;
    std::chrono::steady_clock::time_point last_request_time;
};

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
    std::shared_ptr<monitor_rate_state> rate_state_ = std::make_shared<monitor_rate_state>();
};

}    // namespace mux

#endif
