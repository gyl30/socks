#ifndef CONTEXT_POOL_H
#define CONTEXT_POOL_H

#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include "log.h"

class io_context_pool
{
   public:
    explicit io_context_pool(std::size_t pool_size) : next_io_context_(0)
    {
        if (pool_size == 0)
        {
            throw std::runtime_error("io_context_pool size is 0");
        }

        for (std::size_t i = 0; i < pool_size; ++i)
        {
            auto ctx = std::make_shared<boost::asio::io_context>();
            io_contexts_.push_back(ctx);
            work_.push_back(std::make_shared<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(ctx->get_executor()));
        }
    }

    void run()
    {
        std::vector<std::thread> threads;
        threads.reserve(io_contexts_.size());
        for (auto& io_context : io_contexts_)
        {
            threads.emplace_back([&io_context]() { io_context->run(); });
        }

        LOG_INFO("io_context_pool running with {} threads", threads.size());

        for (auto& t : threads)
        {
            if (t.joinable())
            {
                t.join();
            }
        }
    }

    void stop()
    {
        for (auto& ctx : io_contexts_)
        {
            ctx->stop();
        }
    }

    [[nodiscard]] boost::asio::io_context& get_io_context()
    {
        const std::size_t index = next_io_context_.fetch_add(1, std::memory_order_relaxed) % io_contexts_.size();
        return *io_contexts_[index];
    }

   private:
    std::atomic<std::size_t> next_io_context_ = {0};
    std::vector<std::shared_ptr<boost::asio::io_context>> io_contexts_;
    std::vector<std::shared_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>> work_;
};

#endif
