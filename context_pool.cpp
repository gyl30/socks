#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>
#include <cstddef>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "context_pool.h"

namespace mux
{

io_context_pool::io_context_pool(std::size_t pool_size) : next_io_context_(0)
{
    if (pool_size == 0)
    {
        LOG_WARN("io context pool size clamped from 0 to 1");
        pool_size = 1;
    }

    for (std::size_t i = 0; i < pool_size; ++i)
    {
        auto worker = std::make_shared<io_worker>();
        work_guards_.push_back(boost::asio::make_work_guard(worker->io_context));
        workers_.push_back(worker);
    }
}

void io_context_pool::run()
{
    std::vector<std::thread> threads;
    threads.reserve(workers_.size());

    for (const auto& worker : workers_)
    {
        threads.emplace_back([worker]() { worker->io_context.run(); });
    }

    LOG_INFO("io context pool running with {} threads", threads.size());

    for (auto& t : threads)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
}

void io_context_pool::stop()
{
    shutdown();
    LOG_INFO("io context pool force stopping all contexts");
    for (const auto& worker : workers_)
    {
        worker->io_context.stop();
    }
}

void io_context_pool::shutdown()
{
    LOG_INFO("io context pool shutting down work guards");
    work_guards_.clear();
}

io_worker& io_context_pool::get_io_worker()
{
    const std::size_t index = next_io_context_.fetch_add(1, std::memory_order_relaxed) % workers_.size();
    return *workers_[index];
}

boost::asio::io_context& io_context_pool::get_io_context()
{
    return get_io_worker().io_context;
}

task_group& io_context_pool::get_task_group(boost::asio::io_context& io_context) const
{
    for (const auto& worker : workers_)
    {
        if (&worker->io_context == &io_context)
        {
            return worker->group;
        }
    }
    throw std::logic_error("io_context_pool missing task_group");
}

void io_context_pool::emit_all(const boost::asio::cancellation_type type) const
{
    for (const auto& worker : workers_)
    {
        boost::asio::post(
            worker->io_context,
            [worker, type]()
            {
                worker->group.emit(type);
            });
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
            LOG_ERROR("io context pool wait failed {}", ec.message());
        }
    }
}

}    // namespace mux
