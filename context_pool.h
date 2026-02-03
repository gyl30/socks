#ifndef CONTEXT_POOL_H
#define CONTEXT_POOL_H

#include <asio.hpp>
#include <atomic>
#include <cstddef>
#include <memory>
#include <system_error>
#include <vector>

class io_context_pool
{
   public:
    explicit io_context_pool(std::size_t pool_size, std::error_code& ec);

    io_context_pool(const io_context_pool&) = delete;
    io_context_pool& operator=(const io_context_pool&) = delete;

    void run();

    void stop();

    [[nodiscard]] asio::io_context& get_io_context();

   private:
    std::vector<std::shared_ptr<asio::io_context>> io_contexts_;
    alignas(sizeof(std::size_t)) std::atomic<std::size_t> next_io_context_ = {0};
    std::vector<std::shared_ptr<asio::executor_work_guard<asio::io_context::executor_type>>> work_guards_;
};

#endif
