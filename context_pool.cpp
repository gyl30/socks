#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "log.h"
#include "constants.h"
#include "context_pool.h"

namespace mux
{

io_context_pool::io_context_pool(std::size_t pool_size) : next_io_context_(0)
{
    if (pool_size == 0)
    {
        LOG_WARN("{} stage io_context_pool requested_threads {} clamped_threads {}", log_event::kConnInit, 0, 1);
        pool_size = 1;
    }

    for (std::size_t i = 0; i < pool_size; ++i)
    {
        auto worker = std::make_shared<io_worker>();
        work_guards_.push_back(boost::asio::make_work_guard(worker->io_context));
        workers_.push_back(worker);
    }
}

void io_context_pool::run() const
{
    std::vector<std::thread> threads;
    threads.reserve(workers_.size());

    for (const auto& worker : workers_)
    {
        threads.emplace_back([worker]() { worker->io_context.run(); });
    }

    LOG_INFO("{} stage io_context_pool running threads {}", log_event::kConnInit, threads.size());

    for (auto& t : threads)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
}

void io_context_pool::shutdown()
{
    LOG_INFO("{} stage io_context_pool shutting down work guards", log_event::kConnClose);
    work_guards_.clear();
}

io_worker& io_context_pool::get_io_worker()
{
    const std::size_t index = next_io_context_.fetch_add(1, std::memory_order_relaxed) % workers_.size();
    return *workers_[index];
}

void io_context_pool::emit_all(const boost::asio::cancellation_type type) const
{
    for (const auto& worker : workers_)
    {
        boost::asio::post(worker->io_context, [worker, type]() { worker->group.emit(type); });
    }
}

boost::asio::awaitable<void> io_context_pool::async_wait_all() const
{
    for (const auto& worker : workers_)
    {
        co_await boost::asio::post(worker->io_context, boost::asio::use_awaitable);
        const auto ec = co_await worker->group.async_wait();
        if (ec && ec != boost::asio::error::operation_aborted)
        {
            LOG_ERROR("{} stage io_context_pool wait_all error {}", log_event::kConnClose, ec.message());
        }
    }
}

}    // namespace mux
