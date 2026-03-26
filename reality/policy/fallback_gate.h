#ifndef REALITY_FALLBACK_GATE_H
#define REALITY_FALLBACK_GATE_H

#include <deque>
#include <mutex>
#include <string>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>

#include "connection_context.h"

namespace reality
{

class fallback_gate
{
   public:
    struct options
    {
        std::uint32_t max_concurrent = 32;
        std::uint32_t rate_limit_window_sec = 10;
        std::size_t max_attempts_per_window_per_source = 8;
        std::size_t max_tracker_entries = 4096;
    };

    struct dependencies
    {
        options opts{};
        std::function<std::uint64_t()> now_seconds;
    };

    class budget_ticket
    {
       public:
        budget_ticket() = default;
        ~budget_ticket();

        budget_ticket(const budget_ticket&) = delete;
        budget_ticket& operator=(const budget_ticket&) = delete;

        budget_ticket(budget_ticket&& other) noexcept;
        budget_ticket& operator=(budget_ticket&& other) noexcept;

        [[nodiscard]] bool acquired() const { return owner_ != nullptr; }

        explicit operator bool() const { return acquired(); }

        void release();

       private:
        friend class fallback_gate;

        explicit budget_ticket(fallback_gate* owner) : owner_(owner) {}

        fallback_gate* owner_ = nullptr;
    };

    explicit fallback_gate(dependencies deps);

    [[nodiscard]] budget_ticket try_acquire(const mux::connection_context& ctx, const char* reason);

   private:
    void release_budget();
    [[nodiscard]] std::uint64_t now_seconds() const;

    options options_{};
    std::function<std::uint64_t()> now_seconds_fn_;
    std::mutex budget_mu_;
    std::uint32_t active_fallbacks_ = 0;
    std::unordered_map<std::string, std::deque<std::uint64_t>> fallback_attempts_by_remote_;
};

}    // namespace reality

#endif
