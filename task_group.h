#ifndef TASK_GROUP_H
#define TASK_GROUP_H

#include <list>
#include <mutex>
#include <cstdio>
#include <utility>
#include <boost/asio.hpp>
#include <boost/asio/consign.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>

class task_group
{
   public:
    explicit task_group(boost::asio::io_context& exec) : cv_{exec, boost::asio::steady_timer::time_point::max()} {}

   public:
    template <typename CompletionToken>
    auto adapt(CompletionToken&& completion_token)
    {
        auto lg = std::lock_guard<::std::mutex>{mtx_};
        auto cs = css_.emplace(css_.end());

        class remover
        {
            task_group* tg_;
            decltype(css_)::iterator cs_;

           public:
            remover(task_group* tg, decltype(css_)::iterator cs) : tg_{tg}, cs_{cs} {}
            remover(remover&& other) noexcept : tg_{::std::exchange(other.tg_, nullptr)}, cs_{other.cs_} {}
            ~remover()
            {
                if (tg_)
                {
                    auto lg = std::lock_guard<::std::mutex>{tg_->mtx_};
                    if (tg_->css_.erase(cs_) == tg_->css_.end())
                    {
                        tg_->cv_.cancel();
                    }
                }
            }
        };

        return boost::asio::bind_cancellation_slot(cs->slot(),
                                                   boost::asio::consign(::std::forward<CompletionToken>(completion_token), remover{this, cs}));
    }

    void emit(::boost::asio::cancellation_type type)
    {
        auto lg = std::lock_guard<::std::mutex>{mtx_};
        for (auto& cs : css_)
        {
            cs.emit(type);
        }
    }

    template <typename CompletionToken = boost::asio::default_completion_token_t<::boost::asio::any_io_executor>>
    auto async_wait(CompletionToken&& completion_token = boost::asio::default_completion_token_t<::boost::asio::any_io_executor>{})
    {
        return boost::asio::async_compose<CompletionToken, void(::boost::system::error_code)>(
            [this, scheduled = false](auto& self, boost::system::error_code ec = {}) mutable
            {
                if (!scheduled)
                {
                    self.reset_cancellation_state(::boost::asio::enable_total_cancellation());
                }

                if (!self.cancelled() && ec == boost::asio::error::operation_aborted)
                {
                    ec = {};
                }

                {
                    auto lg = std::lock_guard<::std::mutex>{mtx_};
                    if (!css_.empty() && !ec)
                    {
                        scheduled = true;

                        auto slot = boost::asio::get_associated_cancellation_slot(self);
                        return cv_.async_wait(::boost::asio::bind_cancellation_slot(
                            slot, [s = std::move(self)](::boost::system::error_code cv_ec) mutable { std::move(s)(cv_ec); }));
                    }
                }

                if (!::std::exchange(scheduled, true))
                {
                    auto slot = boost::asio::get_associated_cancellation_slot(self);
                    return boost::asio::post(
                        cv_.get_executor(),
                        boost::asio::bind_cancellation_slot(slot, [s = std::move(self), ec]() mutable { std::move(s).complete(ec); }));
                }

                self.complete(ec);
            },
            completion_token,
            cv_);
    }

   private:
    std::mutex mtx_;
    boost::asio::steady_timer cv_;
    std::list<::boost::asio::cancellation_signal> css_;
};
#endif
