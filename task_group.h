#ifndef TASK_GROUP_H
#define TASK_GROUP_H

#include <list>
#include <mutex>
#include <memory>
#include <vector>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>

class task_group
{
   private:
    using cancellation_signal_ptr = std::shared_ptr<boost::asio::cancellation_signal>;
    using cancellation_list = std::list<cancellation_signal_ptr>;
    using waiter_ptr = std::shared_ptr<boost::asio::steady_timer>;
    using waiter_list = std::list<waiter_ptr>;

    struct shared_state
    {
        explicit shared_state(boost::asio::any_io_executor executor) : exec(std::move(executor)) {}

        std::mutex mtx;
        boost::asio::any_io_executor exec;
        cancellation_list css;
        waiter_list waiters;
    };

   public:
    explicit task_group(boost::asio::io_context& exec) : state_{std::make_shared<shared_state>(exec.get_executor())} {}

   private:
    template <typename CompletionToken>
    auto adapt(CompletionToken&& completion_token)
    {
        auto state = state_;
        auto lg = std::scoped_lock<std::mutex>{state->mtx};
        auto cs = state->css.emplace(state->css.end(), std::make_shared<boost::asio::cancellation_signal>());
        auto signal = *cs;

        class remover
        {
           private:
            std::shared_ptr<shared_state> state_;
            cancellation_list::iterator cs_;

           public:
            remover(std::shared_ptr<shared_state> state, cancellation_list::iterator cs) : state_{std::move(state)}, cs_{cs} {}
            remover(remover&& other) noexcept : state_{std::move(other.state_)}, cs_{other.cs_} {}
            ~remover()
            {
                if (state_ == nullptr)
                {
                    return;
                }

                std::vector<waiter_ptr> snapshot;
                {
                    auto lg = std::scoped_lock<std::mutex>{state_->mtx};
                    state_->css.erase(cs_);
                    if (state_->css.empty())
                    {
                        snapshot.reserve(state_->waiters.size());
                        for (const auto& waiter : state_->waiters)
                        {
                            snapshot.push_back(waiter);
                        }
                    }
                }

                if (!snapshot.empty())
                {
                    auto exec = state_->exec;
                    boost::asio::post(exec,
                                      [snapshot = std::move(snapshot)]() mutable
                                      {
                                          for (const auto& waiter : snapshot)
                                          {
                                              waiter->cancel();
                                          }
                                      });
                }
            }
        };

        return boost::asio::bind_cancellation_slot(signal->slot(),
                                                   boost::asio::consign(std::forward<CompletionToken>(completion_token),
                                                                        remover{std::move(state), cs},
                                                                        std::move(signal)));
    }

    template <typename Executor, typename AwaitableFactory>
    void spawn(Executor&& exec, AwaitableFactory&& task)
    {
        boost::asio::co_spawn(std::forward<Executor>(exec), std::forward<AwaitableFactory>(task), adapt(boost::asio::detached));
    }

   public:
    template <typename AwaitableFactory>
    void spawn(AwaitableFactory&& task)
    {
        spawn(state_->exec, std::forward<AwaitableFactory>(task));
    }

    void emit(boost::asio::cancellation_type type)
    {
        auto state = state_;
        std::vector<cancellation_signal_ptr> snapshot;
        {
            auto lg = std::scoped_lock<std::mutex>{state->mtx};
            snapshot.reserve(state->css.size());
            for (const auto& cs : state->css)
            {
                snapshot.push_back(cs);
            }
        }
        for (auto& cs : snapshot)
        {
            cs->emit(type);
        }
    }

    boost::asio::awaitable<boost::system::error_code> async_wait()
    {
        auto cancel_state = co_await boost::asio::this_coro::cancellation_state;
        auto state = state_;
        co_await boost::asio::dispatch(state->exec, boost::asio::use_awaitable);

        if (cancel_state.cancelled() != boost::asio::cancellation_type::none)
        {
            co_return boost::asio::error::operation_aborted;
        }

        waiter_list::iterator waiter_it;
        waiter_ptr waiter;
        {
            auto lg = std::scoped_lock<std::mutex>{state->mtx};
            if (state->css.empty())
            {
                co_return boost::system::error_code{};
            }
            waiter = std::make_shared<boost::asio::steady_timer>(state->exec, boost::asio::steady_timer::time_point::max());
            waiter_it = state->waiters.emplace(state->waiters.end(), waiter);
        }

        const auto [ec] = co_await waiter->async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        bool group_empty = false;

        {
            auto lg = std::scoped_lock<std::mutex>{state->mtx};
            state->waiters.erase(waiter_it);
            group_empty = state->css.empty();
        }

        if (ec == boost::asio::error::operation_aborted && group_empty)
        {
            co_return boost::system::error_code{};
        }

        co_return ec;
    }

   private:
    std::shared_ptr<shared_state> state_;
};

#endif
