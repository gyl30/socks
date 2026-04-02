#ifndef CONTEXT_POOL_H
#define CONTEXT_POOL_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstddef>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "task_group.h"
namespace mux
{
struct io_worker
{
    boost::asio::io_context io_context;
    task_group group{io_context};
};

class io_context_pool
{
   public:
    explicit io_context_pool(std::size_t pool_size);

    io_context_pool(const io_context_pool&) = delete;
    io_context_pool& operator=(const io_context_pool&) = delete;

    void run() const;

    void shutdown();

    [[nodiscard]] io_worker& get_io_worker();

    void emit_all(boost::asio::cancellation_type type) const;

    [[nodiscard]] boost::asio::awaitable<void> async_wait_all() const;

   private:
    using work_guard_t = decltype(boost::asio::make_work_guard(std::declval<boost::asio::io_context&>()));

    std::vector<work_guard_t> work_guards_;
    std::vector<std::shared_ptr<io_worker>> workers_;
    alignas(sizeof(std::size_t)) std::atomic<std::size_t> next_io_context_ = {0};
};

}    // namespace mux

#endif
