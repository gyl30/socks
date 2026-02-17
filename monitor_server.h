#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <mutex>
#include <cstdint>
#include <functional>
#include <string_view>
#include <unordered_map>

#include <asio.hpp>

namespace mux
{

struct monitor_rate_state
{
    struct transparent_string_hash
    {
        using is_transparent = void;

        [[nodiscard]] std::size_t operator()(const std::string_view value) const noexcept
        {
            return std::hash<std::string_view>{}(value);
        }
    };

    struct transparent_string_equal
    {
        using is_transparent = void;

        [[nodiscard]] bool operator()(const std::string_view lhs, const std::string_view rhs) const noexcept
        {
            return lhs == rhs;
        }
    };

    std::mutex mutex;
    std::unordered_map<std::string,
                       std::chrono::steady_clock::time_point,
                       transparent_string_hash,
                       transparent_string_equal>
        last_request_time_by_source;
    std::chrono::steady_clock::time_point last_prune_time;
};

namespace detail
{

bool allow_monitor_request_by_source(monitor_rate_state& rate_state,
                                     std::string_view source_key,
                                     std::uint32_t min_interval_ms,
                                     std::chrono::steady_clock::time_point now);

}    // namespace detail

class monitor_server : public std::enable_shared_from_this<monitor_server>
{
   public:
    monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token);
    monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token, std::uint32_t min_interval_ms);
    monitor_server(asio::io_context& ioc, std::string bind_host, std::uint16_t port, std::string token, std::uint32_t min_interval_ms);
    void start();
    void stop();
    [[nodiscard]] bool running() const
    {
        return started_.load(std::memory_order_acquire) && !stop_.load(std::memory_order_acquire) && acceptor_.is_open();
    }

   private:
    void stop_local();
    void do_accept();

    asio::ip::tcp::acceptor acceptor_;
    std::string token_;
    std::uint32_t min_interval_ms_ = 0;
    std::shared_ptr<monitor_rate_state> rate_state_ = std::make_shared<monitor_rate_state>();
    std::atomic<bool> started_ = {false};
    std::atomic<bool> stop_ = {false};
};

}    // namespace mux

#endif
