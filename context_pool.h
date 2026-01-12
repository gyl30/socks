#ifndef CONTEXT_POOL_H
#define CONTEXT_POOL_H

#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include "log.h"

class io_context_pool
{
   public:
    explicit io_context_pool(std::size_t pool_size, boost::system::error_code& ec) : next_io_context_(0)
    {
        if (pool_size == 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            LOG_ERROR("io context pool size cannot be 0");
            return;
        }

        for (std::size_t i = 0; i < pool_size; ++i)
        {
            auto ctx = std::make_shared<boost::asio::io_context>();
            io_contexts_.push_back(ctx);
            work_guards_.push_back(std::make_shared<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(ctx->get_executor()));
        }
    }

    io_context_pool(const io_context_pool&) = delete;
    io_context_pool& operator=(const io_context_pool&) = delete;

    void run()
    {
        std::vector<std::thread> threads;
        threads.reserve(io_contexts_.size());

        for (auto& io_context : io_contexts_)
        {
            threads.emplace_back([&io_context]() { io_context->run(); });
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

    void stop() const
    {
        LOG_INFO("io context pool stopping all contexts");
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
    std::vector<std::shared_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>> work_guards_;
};

#endif
