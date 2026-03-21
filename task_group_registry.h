#ifndef TASK_GROUP_REGISTRY_H
#define TASK_GROUP_REGISTRY_H

#include <memory>
#include <vector>
#include <stdexcept>

#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "task_group.h"
#include "context_pool.h"

namespace mux
{

class task_group_registry
{
   private:
    struct entry
    {
        boost::asio::io_context* io = nullptr;
        std::shared_ptr<task_group> group;
    };

   public:
    explicit task_group_registry(io_context_pool& pool)
    {
        const auto ios = pool.all_io_contexts();
        groups_.reserve(ios.size());
        for (auto* io : ios)
        {
            groups_.push_back(entry{io, std::make_shared<task_group>(*io)});
        }
    }

    [[nodiscard]] task_group& get(boost::asio::io_context& io) const
    {
        for (const auto& entry : groups_)
        {
            if (entry.io == &io)
            {
                return *entry.group;
            }
        }
        throw std::logic_error("task_group_registry missing io_context");
    }

    void emit_all(boost::asio::cancellation_type type) const
    {
        for (const auto& entry : groups_)
        {
            boost::asio::post(
                *entry.io,
                [group = entry.group, type]()
                {
                    group->emit(type);
                });
        }
    }

    boost::asio::awaitable<void> async_wait_all() const
    {
        for (const auto& entry : groups_)
        {
            co_await boost::asio::post(*entry.io, boost::asio::use_awaitable);
            const auto [ec] = co_await entry.group->async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec && ec != boost::asio::error::operation_aborted)
            {
                LOG_ERROR("task group registry wait failed {}", ec.message());
            }
        }
    }

   private:
    std::vector<entry> groups_;
};

}    // namespace mux

#endif
