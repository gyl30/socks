#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include <atomic>
#include <cstdint>

namespace mux
{

class connection_tracker
{
   public:
    static connection_tracker& instance()
    {
        static connection_tracker tracker;
        return tracker;
    }

    void acquire() { active_connections_.fetch_add(1, std::memory_order_relaxed); }
    void release() { active_connections_.fetch_sub(1, std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t active_connections() const { return active_connections_.load(std::memory_order_relaxed); }

   private:
    connection_tracker() = default;

   private:
    std::atomic<std::uint64_t> active_connections_{0};
};

}    // namespace mux

#endif
