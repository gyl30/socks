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

   public:
    explicit task_group(boost::asio::io_context& exec) : exec_{exec.get_executor()} {}

   private:
    template <typename CompletionToken>
    auto adapt(CompletionToken&& completion_token)
    {
        auto lg = std::scoped_lock<::std::mutex>{mtx_};
        auto cs = css_.emplace(css_.end(), std::make_shared<boost::asio::cancellation_signal>());

        class remover
        {
           private:
            task_group* tg_;
            cancellation_list::iterator cs_;

           public:
            remover(task_group* tg, cancellation_list::iterator cs) : tg_{tg}, cs_{cs} {}
            remover(remover&& other) noexcept : tg_{::std::exchange(other.tg_, nullptr)}, cs_{other.cs_} {}
            ~remover()
            {
                if (tg_ == nullptr)
                {
                    return;
                }

                std::vector<waiter_ptr> snapshot;
                {
                    auto lg = std::scoped_lock<::std::mutex>{tg_->mtx_};
                    tg_->css_.erase(cs_);
                    if (tg_->css_.empty())
                    {
                        snapshot.reserve(tg_->waiters_.size());
                        for (const auto& waiter : tg_->waiters_)
                        {
                            snapshot.push_back(waiter);
                        }
                    }
                }

                if (!snapshot.empty())
                {
                    auto exec = tg_->exec_;
                    boost::asio::post(exec,
                                      [snapshot = ::std::move(snapshot)]() mutable
                                      {
                                          for (const auto& waiter : snapshot)
                                          {
                                              waiter->cancel();
                                          }
                                      });
                }
            }
        };

        return boost::asio::bind_cancellation_slot((*cs)->slot(),
                                                   boost::asio::consign(::std::forward<CompletionToken>(completion_token), remover{this, cs}));
    }

    template <typename Executor, typename AwaitableFactory>
    void spawn(Executor&& exec, AwaitableFactory&& task)
    {
        boost::asio::co_spawn(::std::forward<Executor>(exec), ::std::forward<AwaitableFactory>(task), adapt(boost::asio::detached));
    }

   public:
    template <typename AwaitableFactory>
    void spawn(AwaitableFactory&& task)
    {
        spawn(exec_, ::std::forward<AwaitableFactory>(task));
    }

    void emit(boost::asio::cancellation_type type)
    {
        std::vector<cancellation_signal_ptr> snapshot;
        {
            auto lg = std::scoped_lock<::std::mutex>{mtx_};
            snapshot.reserve(css_.size());
            for (const auto& cs : css_)
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
        co_await boost::asio::dispatch(exec_, boost::asio::use_awaitable);

        if (cancel_state.cancelled() != boost::asio::cancellation_type::none)
        {
            co_return boost::asio::error::operation_aborted;
        }

        waiter_list::iterator waiter_it;
        waiter_ptr waiter;
        {
            auto lg = std::scoped_lock<::std::mutex>{mtx_};
            if (css_.empty())
            {
                co_return boost::system::error_code{};
            }
            waiter = std::make_shared<boost::asio::steady_timer>(exec_, boost::asio::steady_timer::time_point::max());
            waiter_it = waiters_.emplace(waiters_.end(), waiter);
        }

        const auto [ec] = co_await waiter->async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));

        {
            auto lg = std::scoped_lock<::std::mutex>{mtx_};
            waiters_.erase(waiter_it);
        }

        if (ec == boost::asio::error::operation_aborted && cancel_state.cancelled() == boost::asio::cancellation_type::none)
        {
            co_return boost::system::error_code{};
        }

        co_return ec;
    }

   private:
    std::mutex mtx_;
    boost::asio::any_io_executor exec_;
    cancellation_list css_;
    waiter_list waiters_;
};

#endif
