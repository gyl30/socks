#ifndef STOP_DISPATCH_H
#define STOP_DISPATCH_H

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <type_traits>
#include <utility>
#include <cstdint>

#include <asio/dispatch.hpp>
#include <asio/io_context.hpp>

namespace mux::detail
{

constexpr auto kStopDispatchWaitTimeout = std::chrono::milliseconds(50);

enum class dispatch_timeout_policy : std::uint8_t
{
    kNoInline,
    kRunInline,
};

template <typename Fn>
void dispatch_cleanup_or_run_inline(asio::io_context& io_context,
                                    Fn&& fn,
                                    const dispatch_timeout_policy timeout_policy = dispatch_timeout_policy::kNoInline)
{
    if (io_context.stopped() || io_context.get_executor().running_in_this_thread())
    {
        std::forward<Fn>(fn)();
        return;
    }

    using fn_type = std::decay_t<Fn>;

    struct dispatch_state
    {
        std::atomic<bool> executed{false};
        std::promise<void> dispatch_done;
        fn_type handler;

        explicit dispatch_state(fn_type&& h) : handler(std::move(h)) {}
    };

    auto state = std::make_shared<dispatch_state>(std::forward<Fn>(fn));
    auto future = state->dispatch_done.get_future();

    asio::dispatch(
        io_context,
        [state]()
        {
            bool expected = false;
            if (state->executed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                state->handler();
            }
            state->dispatch_done.set_value();
        });

    if (future.wait_for(kStopDispatchWaitTimeout) == std::future_status::ready)
    {
        return;
    }
    if (timeout_policy != dispatch_timeout_policy::kRunInline)
    {
        return;
    }

    bool expected = false;
    if (state->executed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        state->handler();
    }
}

}    // namespace mux::detail

#endif
