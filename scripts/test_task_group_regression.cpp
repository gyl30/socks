#include <chrono>
#include <future>
#include <iostream>
#include <string>
#include <thread>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "task_group.h"

namespace
{

using namespace std::chrono_literals;

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

boost::asio::awaitable<void> wait_for_group(task_group& group, std::promise<boost::system::error_code>& promise)
{
    promise.set_value(co_await group.async_wait());
}

}    // namespace

int main()
{
    boost::asio::io_context io_context;
    auto work_guard = boost::asio::make_work_guard(io_context);
    std::thread worker([&io_context]() { io_context.run(); });
    const auto cleanup = [&]() {
        work_guard.reset();
        io_context.stop();
        if (worker.joinable())
        {
            worker.join();
        }
    };

    bool ok = true;
    {
        task_group group(io_context);
        boost::asio::steady_timer task_timer(io_context, 5s);
        std::promise<void> task_started_promise;
        auto task_started = task_started_promise.get_future();

        group.spawn([&task_timer, &task_started_promise]() -> boost::asio::awaitable<void>
                    {
                        task_started_promise.set_value();
                        boost::system::error_code ec;
                        co_await task_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
                    });

        ok = require(task_started.wait_for(1s) == std::future_status::ready, "spawned task did not start");

        boost::asio::cancellation_signal wait_signal;
        std::promise<boost::system::error_code> wait_result_promise;
        auto wait_result = wait_result_promise.get_future();

        if (ok)
        {
            boost::asio::co_spawn(io_context,
                                  wait_for_group(group, wait_result_promise),
                                  boost::asio::bind_cancellation_slot(wait_signal.slot(), boost::asio::detached));

            std::this_thread::sleep_for(50ms);
            wait_signal.emit(boost::asio::cancellation_type::all);
            ok = require(wait_result.wait_for(1s) == std::future_status::ready,
                         "async_wait did not observe external cancellation");
        }

        if (ok)
        {
            const auto ec = wait_result.get();
            ok = require(ec == boost::asio::error::operation_aborted,
                         "async_wait returned unexpected error: " + ec.message());
        }
    }

    cleanup();
    return ok ? 0 : 1;
}
