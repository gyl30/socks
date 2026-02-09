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

    std::atomic<std::uint64_t> active_connections{0};
    std::atomic<std::uint64_t> total_connections{0};
    std::atomic<std::uint64_t> active_mux_sessions{0};
    std::atomic<std::uint64_t> bytes_read{0};
    std::atomic<std::uint64_t> bytes_written{0};
    std::atomic<std::uint64_t> auth_failures{0};
    std::atomic<std::uint64_t> routing_blocked{0};

   private:
    statistics() = default;
    ~statistics() = default;
    std::chrono::steady_clock::time_point start_time_;
};

}    // namespace mux

#endif
