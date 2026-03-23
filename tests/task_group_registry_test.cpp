#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include "context_pool.h"
#include "task_group_registry.h"

namespace
{

using namespace std::chrono_literals;

[[noreturn]] void fail(const std::string& message)
{
    throw std::runtime_error(message);
}

void require(const bool condition, const std::string& message)
{
    if (!condition)
    {
        fail(message);
    }
}

void wait_until_true(const std::atomic<bool>& flag, const std::chrono::milliseconds timeout, const std::string& message)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!flag.load(std::memory_order_acquire))
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            fail(message);
        }
        std::this_thread::sleep_for(1ms);
    }
}

[[nodiscard]] std::future<bool> spawn_cancellable_task(boost::asio::io_context& io, task_group& group, std::atomic<bool>& started)
{
    return boost::asio::co_spawn(
        io,
        [&started]() -> boost::asio::awaitable<bool>
        {
            started.store(true, std::memory_order_release);

            auto exec = co_await boost::asio::this_coro::executor;
            boost::asio::steady_timer timer(exec);
            timer.expires_after(30s);

            const auto [ec] = co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            co_return ec == boost::asio::error::operation_aborted;
        },
        group.adapt(boost::asio::use_future));
}

[[nodiscard]] std::future<void> spawn_wait_all(boost::asio::io_context& io, const mux::task_group_registry& groups)
{
    return boost::asio::co_spawn(io, groups.async_wait_all(), boost::asio::use_future);
}

class pool_runner
{
   public:
    explicit pool_runner(mux::io_context_pool& pool) : pool_(pool), thread_([this]() { pool_.run(); }) {}

    pool_runner(const pool_runner&) = delete;
    pool_runner& operator=(const pool_runner&) = delete;

    ~pool_runner()
    {
        pool_.stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

   private:
    mux::io_context_pool& pool_;
    std::thread thread_;
};

void remote_context_task_blocks_wait_all_until_cancelled()
{
    mux::io_context_pool pool(2);
    mux::task_group_registry groups(pool);
    const auto ios = pool.all_io_contexts();
    require(ios.size() >= 2, "task_group_registry test requires at least two io_context instances");

    std::atomic<bool> remote_started{false};
    auto remote_task = spawn_cancellable_task(*ios[1], groups.get(*ios[1]), remote_started);

    pool_runner runner(pool);
    wait_until_true(remote_started, 2s, "remote task did not start");

    auto wait_all = spawn_wait_all(*ios[0], groups);
    require(wait_all.wait_for(50ms) == std::future_status::timeout, "async_wait_all returned before remote task stopped");

    groups.emit_all(boost::asio::cancellation_type::all);
    wait_all.get();

    require(remote_task.get(), "remote task did not observe cancellation");
}

void pre_run_tasks_are_cancelled_and_waited()
{
    mux::io_context_pool pool(2);
    mux::task_group_registry groups(pool);
    const auto ios = pool.all_io_contexts();
    require(ios.size() >= 2, "task_group_registry test requires at least two io_context instances");

    std::array<std::atomic<bool>, 2> started{};
    auto task0 = spawn_cancellable_task(*ios[0], groups.get(*ios[0]), started[0]);
    auto task1 = spawn_cancellable_task(*ios[1], groups.get(*ios[1]), started[1]);

    groups.emit_all(boost::asio::cancellation_type::all);
    auto wait_all = spawn_wait_all(*ios[0], groups);

    pool_runner runner(pool);
    wait_all.get();

    require(task0.get(), "pre-run task on io_context 0 did not observe cancellation");
    require(task1.get(), "pre-run task on io_context 1 did not observe cancellation");
}

}

int main()
{
    remote_context_task_blocks_wait_all_until_cancelled();
    pre_run_tasks_are_cancelled_and_waited();
    return 0;
}
