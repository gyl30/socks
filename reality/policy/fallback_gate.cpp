#include <deque>
#include <mutex>
#include <string>
#include <utility>

#include "log.h"
#include "constants.h"
#include "net_utils.h"
#include "reality/policy/fallback_executor.h"
#include "reality/policy/fallback_gate.h"

namespace reality
{

namespace
{

std::string make_remote_addr_key(const fallback_request& request)
{
    if (!request.remote_addr.empty())
    {
        return request.remote_addr;
    }
    return "unknown";
}

}    // namespace

fallback_gate::budget_ticket::~budget_ticket() { release(); }

fallback_gate::budget_ticket::budget_ticket(budget_ticket&& other) noexcept : owner_(other.owner_) { other.owner_ = nullptr; }

fallback_gate::budget_ticket& fallback_gate::budget_ticket::operator=(budget_ticket&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    release();
    owner_ = other.owner_;
    other.owner_ = nullptr;
    return *this;
}

void fallback_gate::budget_ticket::release()
{
    if (owner_ == nullptr)
    {
        return;
    }

    owner_->release_budget();
    owner_ = nullptr;
}

fallback_gate::fallback_gate(dependencies deps) : options_(deps.opts), now_seconds_fn_(std::move(deps.now_seconds))
{
    if (!now_seconds_fn_)
    {
        now_seconds_fn_ = []() { return mux::net::now_second(); };
    }
}

fallback_gate::budget_ticket fallback_gate::try_acquire(const fallback_request& request, const char* reason)
{
    const auto now_sec = now_seconds();
    const auto remote_addr = make_remote_addr_key(request);
    const char* log_reason = reason == nullptr ? "unknown" : reason;
    std::scoped_lock const lock(budget_mu_);

    if (active_fallbacks_ >= options_.max_concurrent)
    {
        LOG_WARN("event {} conn_id {} remote {} reason {} stage rate_limit mode concurrency active {} limit {}",
                 mux::log_event::kFallback,
                 request.conn_id,
                 remote_addr,
                 log_reason,
                 active_fallbacks_,
                 options_.max_concurrent);
        return {};
    }

    auto it = fallback_attempts_by_remote_.find(remote_addr);
    if (it == fallback_attempts_by_remote_.end() && fallback_attempts_by_remote_.size() >= options_.max_tracker_entries)
    {
        for (auto cleanup_it = fallback_attempts_by_remote_.begin(); cleanup_it != fallback_attempts_by_remote_.end();)
        {
            auto& entry_attempts = cleanup_it->second;
            while (!entry_attempts.empty() && entry_attempts.front() + options_.rate_limit_window_sec <= now_sec)
            {
                entry_attempts.pop_front();
            }
            if (entry_attempts.empty())
            {
                cleanup_it = fallback_attempts_by_remote_.erase(cleanup_it);
                continue;
            }
            ++cleanup_it;
        }
        if (fallback_attempts_by_remote_.size() >= options_.max_tracker_entries)
        {
            LOG_WARN("event {} conn_id {} remote {} reason {} stage rate_limit mode tracker_capacity entries {} limit {}",
                     mux::log_event::kFallback,
                     request.conn_id,
                     remote_addr,
                     log_reason,
                     fallback_attempts_by_remote_.size(),
                     options_.max_tracker_entries);
            return {};
        }
    }

    if (it == fallback_attempts_by_remote_.end())
    {
        it = fallback_attempts_by_remote_.emplace(remote_addr, std::deque<uint64_t>{}).first;
    }
    auto& attempts = it->second;
    while (!attempts.empty() && attempts.front() + options_.rate_limit_window_sec <= now_sec)
    {
        attempts.pop_front();
    }

    if (attempts.size() >= options_.max_attempts_per_window_per_source)
    {
        LOG_WARN("event {} conn_id {} remote {} reason {} stage rate_limit mode per_source attempts {} window_sec {} limit {}",
                 mux::log_event::kFallback,
                 request.conn_id,
                 remote_addr,
                 log_reason,
                 attempts.size(),
                 options_.rate_limit_window_sec,
                 options_.max_attempts_per_window_per_source);
        return {};
    }

    attempts.push_back(now_sec);
    ++active_fallbacks_;
    return budget_ticket(this);
}

void fallback_gate::release_budget()
{
    const std::scoped_lock lock(budget_mu_);
    if (active_fallbacks_ == 0)
    {
        return;
    }
    --active_fallbacks_;
}

uint64_t fallback_gate::now_seconds() const { return now_seconds_fn_(); }

}    // namespace reality
