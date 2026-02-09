#include <array>
#include <sstream>

#include "log.h"
#include "statistics.h"
#include "monitor_server.h"

namespace mux
{

class monitor_session : public std::enable_shared_from_this<monitor_session>
{
   public:
    explicit monitor_session(asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

    void start()
    {
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(buffer_),
                                [this, self](std::error_code ec, std::size_t /*length*/)
                                {
                                    if (!ec)
                                    {
                                        write_stats();
                                    }
                                });
    }

   private:
    void write_stats()
    {
        auto& stats = statistics::instance();
        std::stringstream ss;

        ss << "socks_uptime_seconds " << stats.uptime_seconds() << "\n";
        ss << "socks_active_connections " << stats.active_connections.load() << "\n";
        ss << "socks_total_connections " << stats.total_connections.load() << "\n";
        ss << "socks_active_mux_tunnels " << stats.active_mux_sessions.load() << "\n";
        ss << "socks_bytes_read_total " << stats.bytes_read.load() << "\n";
        ss << "socks_bytes_written_total " << stats.bytes_written.load() << "\n";
        ss << "socks_auth_failures_total " << stats.auth_failures.load() << "\n";
        ss << "socks_routing_blocked_total " << stats.routing_blocked.load() << "\n";

        response_ = ss.str();

        auto self = shared_from_this();
        asio::async_write(socket_,
                          asio::buffer(response_),
                          [this, self](std::error_code, std::size_t)
                          {
                              std::error_code ignored_ec;
                              ignored_ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
                              ignored_ec = socket_.close(ignored_ec);
                          });
    }

   private:
    std::string response_;
    std::array<char, 128> buffer_;
    asio::ip::tcp::socket socket_;
};

monitor_server::monitor_server(asio::io_context& ioc, std::uint16_t port) : acceptor_(ioc), ioc_(ioc)
{
    try
    {
        asio::ip::tcp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        LOG_INFO("monitor server listening on 127.0.0.1:{}", port);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("failed to start monitor server: {}", e.what());
    }
}

void monitor_server::start() { do_accept(); }

void monitor_server::do_accept()
{
    acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket)
        {
            if (!ec)
            {
                std::make_shared<monitor_session>(std::move(socket))->start();
            }
            do_accept();
        });
}

}    // namespace mux
