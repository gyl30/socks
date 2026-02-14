#ifndef CONTEXT_POOL_H
#define CONTEXT_POOL_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstddef>
#include <utility>
#include <system_error>

#include <asio/io_context.hpp>
#include <asio/executor_work_guard.hpp>

namespace mux
{

class io_context_pool
{
   public:
    explicit io_context_pool(std::size_t pool_size);

    io_context_pool(const io_context_pool&) = delete;
    io_context_pool& operator=(const io_context_pool&) = delete;

    void run();

    void stop();

    [[nodiscard]] asio::io_context& get_io_context();

   private:
    using work_guard_t = decltype(asio::make_work_guard(std::declval<asio::io_context&>()));

    std::vector<std::shared_ptr<asio::io_context>> io_contexts_;
    alignas(sizeof(std::size_t)) std::atomic<std::size_t> next_io_context_ = {0};
    std::vector<work_guard_t> work_guards_;
};

}    // namespace mux

#endif
