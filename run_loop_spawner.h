#ifndef RUN_LOOP_SPAWNER_H
#define RUN_LOOP_SPAWNER_H

#include <memory>

#include <boost/asio/awaitable.hpp>

#include "context_pool.h"

namespace relay
{

struct run_loop_spawner
{
    template <typename Session>
    static void spawn(io_worker& worker, const std::shared_ptr<Session>& session)
    {
        worker.group.spawn([session]() -> boost::asio::awaitable<void> { co_await session->run_loop(); });
    }
};

}    // namespace relay

#endif
