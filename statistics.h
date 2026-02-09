#ifndef STATISTICS_H
#define STATISTICS_H

#include <atomic>
#include <chrono>
#include <cstdint>

namespace mux
{

class statistics
{
   public:
    static statistics& instance()
    {
        static statistics s;
        return s;
    }

    void start_time() { start_time_ = std::chrono::steady_clock::now(); }

    std::uint64_t uptime_seconds() const
    {
        const auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
    }

    void inc_active_connections() { active_connections_++; }
    void dec_active_connections() { active_connections_--; }
    std::uint64_t active_connections() const { return active_connections_.load(); }

    void inc_total_connections() { total_connections_++; }
    std::uint64_t total_connections() const { return total_connections_.load(); }

    void inc_active_mux_sessions() { active_mux_sessions_++; }
    void dec_active_mux_sessions() { active_mux_sessions_--; }
    std::uint64_t active_mux_sessions() const { return active_mux_sessions_.load(); }

    void add_bytes_read(std::uint64_t n) { bytes_read_ += n; }
    std::uint64_t bytes_read() const { return bytes_read_.load(); }

    void add_bytes_written(std::uint64_t n) { bytes_written_ += n; }
    std::uint64_t bytes_written() const { return bytes_written_.load(); }

    void inc_auth_failures() { auth_failures_++; }
    std::uint64_t auth_failures() const { return auth_failures_.load(); }

    void inc_routing_blocked() { routing_blocked_++; }
    std::uint64_t routing_blocked() const { return routing_blocked_.load(); }

   private:
    std::atomic<std::uint64_t> active_connections_{0};
    std::atomic<std::uint64_t> total_connections_{0};
    std::atomic<std::uint64_t> active_mux_sessions_{0};
    std::atomic<std::uint64_t> bytes_read_{0};
    std::atomic<std::uint64_t> bytes_written_{0};
    std::atomic<std::uint64_t> auth_failures_{0};
    std::atomic<std::uint64_t> routing_blocked_{0};

   private:
    statistics() = default;
    ~statistics() = default;
    std::chrono::steady_clock::time_point start_time_;
};

}    // namespace mux

#endif
