#include <array>
#include <sstream>

#include "log.h"
#include "statistics.h"
#include "monitor_server.h"

namespace mux
{

namespace
{

std::string escape_prometheus_label(std::string value)
{
    std::string out;
    out.reserve(value.size());
    for (const char c : value)
    {
        if (c == '\\' || c == '"')
        {
            out.push_back('\\');
        }
        if (c == '\n')
        {
            out.append("\\n");
            continue;
        }
        out.push_back(c);
    }
    return out;
}

}    // namespace

class monitor_session : public std::enable_shared_from_this<monitor_session>
{
   public:
    monitor_session(asio::ip::tcp::socket socket, std::string token, std::shared_ptr<monitor_rate_state> rate_state, std::uint32_t min_interval_ms)
        : socket_(std::move(socket)), token_(std::move(token)), rate_state_(std::move(rate_state)), min_interval_ms_(min_interval_ms)
    {
    }

    void start()
    {
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(buffer_),
                                [this, self](std::error_code ec, std::size_t length)
                                {
                                    if (!ec)
                                    {
                                        if (!check_rate_limit())
                                        {
                                            LOG_WARN("monitor rate limited");
                                            close_socket();
                                            return;
                                        }
                                        if (!token_.empty())
                                        {
                                            const std::string req(buffer_.data(), length);
                                            if (req.find(token_) == std::string::npos)
                                            {
                                                LOG_WARN("monitor auth failed");
                                                close_socket();
                                                return;
                                            }
                                        }
                                        write_stats();
                                    }
                                });
    }

   private:
    void close_socket()
    {
        std::error_code ignored_ec;
        ignored_ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
        ignored_ec = socket_.close(ignored_ec);
    }

    bool check_rate_limit()
    {
        if (min_interval_ms_ == 0 || rate_state_ == nullptr)
        {
            return true;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now - rate_state_->last_request_time < std::chrono::milliseconds(min_interval_ms_))
        {
            return false;
        }
        rate_state_->last_request_time = now;
        return true;
    }

    void write_stats()
    {
        auto& stats = statistics::instance();
        std::stringstream ss;

        ss << "socks_uptime_seconds " << stats.uptime_seconds() << "\n";
        ss << "socks_active_connections " << stats.active_connections() << "\n";
        ss << "socks_total_connections " << stats.total_connections() << "\n";
        ss << "socks_active_mux_tunnels " << stats.active_mux_sessions() << "\n";
        ss << "socks_bytes_read_total " << stats.bytes_read() << "\n";
        ss << "socks_bytes_written_total " << stats.bytes_written() << "\n";
        ss << "socks_auth_failures_total " << stats.auth_failures() << "\n";
        ss << "socks_auth_short_id_failures_total " << stats.auth_short_id_failures() << "\n";
        ss << "socks_auth_clock_skew_failures_total " << stats.auth_clock_skew_failures() << "\n";
        ss << "socks_auth_replay_failures_total " << stats.auth_replay_failures() << "\n";
        ss << "socks_cert_verify_failures_total " << stats.cert_verify_failures() << "\n";
        ss << "socks_client_finished_failures_total " << stats.client_finished_failures() << "\n";
        ss << "socks_fallback_rate_limited_total " << stats.fallback_rate_limited() << "\n";
        ss << "socks_routing_blocked_total " << stats.routing_blocked() << "\n";
        const auto handshake_failure_sni_metrics = stats.handshake_failure_sni_metrics();
        for (const auto& metric : handshake_failure_sni_metrics)
        {
            ss << "socks_handshake_failures_by_sni_total{reason=\""
               << escape_prometheus_label(metric.reason)
               << "\",sni=\""
               << escape_prometheus_label(metric.sni)
               << "\"} "
               << metric.count
               << "\n";
        }

        response_ = ss.str();

        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(response_), [this, self](std::error_code, std::size_t) { close_socket(); });
    }

   private:
    std::string response_;
    std::array<char, 128> buffer_;
    asio::ip::tcp::socket socket_;
    std::string token_;
    std::shared_ptr<monitor_rate_state> rate_state_;
    std::uint32_t min_interval_ms_ = 0;
};

monitor_server::monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token)
    : monitor_server(ioc, "127.0.0.1", port, std::move(token), 0)
{
}

monitor_server::monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token, const std::uint32_t min_interval_ms)
    : monitor_server(ioc, "127.0.0.1", port, std::move(token), min_interval_ms)
{
}

monitor_server::monitor_server(asio::io_context& ioc,
                               std::string bind_host,
                               const std::uint16_t port,
                               std::string token,
                               const std::uint32_t min_interval_ms)
    : acceptor_(ioc), token_(std::move(token)), min_interval_ms_(min_interval_ms)
{
    asio::ip::tcp::endpoint endpoint;
    asio::error_code ec;
    endpoint.address(asio::ip::make_address(bind_host, ec));
    if (ec)
    {
        LOG_ERROR("failed to parse address: {}", ec.message());
        return;
    }
    endpoint.port(port);
    if (acceptor_.open(endpoint.protocol(), ec); ec)
    {
        LOG_ERROR("failed to open acceptor: {}", ec.message());
        return;
    }
    if (acceptor_.set_option(asio::socket_base::reuse_address(true), ec); ec)
    {
        LOG_ERROR("failed to set reuse_address: {}", ec.message());
        return;
    }
    if (acceptor_.bind(endpoint, ec); ec)
    {
        LOG_ERROR("failed to bind: {}", ec.message());
        return;
    }
    if (acceptor_.listen(asio::socket_base::max_listen_connections, ec); ec)
    {
        LOG_ERROR("failed to listen: {}", ec.message());
        return;
    }
    LOG_INFO("monitor server listening on {}:{}", bind_host, port);
}

void monitor_server::start()
{
    stop_.store(false, std::memory_order_release);
    if (!acceptor_.is_open())
    {
        return;
    }
    do_accept();
}

void monitor_server::stop()
{
    stop_.store(true, std::memory_order_release);
    asio::dispatch(
        acceptor_.get_executor(),
        [self = shared_from_this()]()
        {
            std::error_code ec;
            ec = self->acceptor_.close(ec);
            if (ec && ec != asio::error::bad_descriptor)
            {
                LOG_WARN("monitor acceptor close failed {}", ec.message());
            }
        });
}

void monitor_server::do_accept()
{
    if (stop_.load(std::memory_order_acquire) || !acceptor_.is_open())
    {
        return;
    }

    const auto self = shared_from_this();
    acceptor_.async_accept(
        [self](std::error_code ec, asio::ip::tcp::socket socket)
        {
            if (self->stop_.load(std::memory_order_acquire))
            {
                return;
            }
            if (ec)
            {
                if (ec != asio::error::operation_aborted && ec != asio::error::bad_descriptor)
                {
                    LOG_WARN("monitor accept failed {}", ec.message());
                    self->do_accept();
                }
                return;
            }

            std::make_shared<monitor_session>(std::move(socket), self->token_, self->rate_state_, self->min_interval_ms_)->start();
            self->do_accept();
        });
}

}    // namespace mux
