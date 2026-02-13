#include <memory>
#include <thread>
#include <vector>
#include <cstddef>
#include <system_error>

#include "log.h"
#include "context_pool.h"

namespace mux
{

io_context_pool::io_context_pool(std::size_t pool_size, std::error_code& ec) : next_io_context_(0)
{
    if (pool_size == 0)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        LOG_ERROR("io context pool size cannot be 0");
        return;
    }

    for (std::size_t i = 0; i < pool_size; ++i)
    {
        auto ctx = std::make_shared<asio::io_context>();
        io_contexts_.push_back(ctx);
        work_guards_.push_back(asio::make_work_guard(*ctx));
    }
}

void io_context_pool::run()
{
    std::vector<std::thread> threads;
    threads.reserve(io_contexts_.size());

    for (auto& io_context : io_contexts_)
    {
        threads.emplace_back([ctx = io_context]() { ctx->run(); });
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
    LOG_INFO("io context pool stopping all contexts");
    work_guards_.clear();
    for (const auto& io_context : io_contexts_)
    {
        io_context->stop();
    }
}

asio::io_context& io_context_pool::get_io_context()
{
    const std::size_t index = next_io_context_.fetch_add(1, std::memory_order_relaxed) % io_contexts_.size();
    return *io_contexts_[index];
}

}    // namespace mux
