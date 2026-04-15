#ifndef TRACE_WEB_SERVER_H
#define TRACE_WEB_SERVER_H

#include <atomic>
#include <memory>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "config.h"
#include "context_pool.h"

namespace relay
{

class trace_web_server : public std::enable_shared_from_this<trace_web_server>
{
   public:
    trace_web_server(io_context_pool& pool, const config& cfg);

    trace_web_server(const trace_web_server&) = delete;
    trace_web_server& operator=(const trace_web_server&) = delete;

    void start();
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> accept_loop();
    [[nodiscard]] boost::asio::awaitable<void> serve_session(boost::asio::ip::tcp::socket socket);

   private:
    const config& cfg_;
    io_worker& worker_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::atomic<bool> stopping_{false};
};

}    // namespace relay

#endif
