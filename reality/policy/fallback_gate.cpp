#include <deque>
#include <mutex>
#include <string>
#include <cstddef>
#include <cstdint>

#include "log.h"
#include "constants.h"
#include "net_utils.h"
#include "reality/policy/fallback_gate.h"

namespace reality
{

namespace
{

constexpr uint32_t kMaxConcurrentFallbacks = 32;
constexpr uint32_t kRateLimitWindowSec = 10;
constexpr std::size_t kMaxAttemptsPerWindowPerSource = 8;
constexpr std::size_t kMaxTrackerEntries = 4096;

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

fallback_gate::budget_ticket fallback_gate::try_acquire(const fallback_request& request, const char* reason)
{
    const auto now_sec = relay::net::now_second();
    const auto remote_addr = make_remote_addr_key(request);
    const char* log_reason = reason == nullptr ? "unknown" : reason;
    std::scoped_lock const lock(budget_mu_);

    if (active_fallbacks_ >= kMaxConcurrentFallbacks)
    {
        LOG_WARN("{} conn {} remote {}:{} reason {} stage rate_limit mode concurrency active {} limit {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 remote_addr,
                 request.remote_port,
                 log_reason,
                 active_fallbacks_,
                 kMaxConcurrentFallbacks);
        return {};
    }

    auto it = fallback_attempts_by_remote_.find(remote_addr);
    if (it == fallback_attempts_by_remote_.end() && fallback_attempts_by_remote_.size() >= kMaxTrackerEntries)
    {
        for (auto cleanup_it = fallback_attempts_by_remote_.begin(); cleanup_it != fallback_attempts_by_remote_.end();)
        {
            auto& entry_attempts = cleanup_it->second;
            while (!entry_attempts.empty() && entry_attempts.front() + kRateLimitWindowSec <= now_sec)
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
        if (fallback_attempts_by_remote_.size() >= kMaxTrackerEntries)
        {
            LOG_WARN("{} conn {} remote {}:{} reason {} stage rate_limit mode tracker_capacity entries {} limit {}",
                     relay::log_event::kFallback,
                     request.conn_id,
                     remote_addr,
                     request.remote_port,
                     log_reason,
                     fallback_attempts_by_remote_.size(),
                     kMaxTrackerEntries);
            return {};
        }
    }

    if (it == fallback_attempts_by_remote_.end())
    {
        it = fallback_attempts_by_remote_.emplace(remote_addr, std::deque<uint64_t>{}).first;
    }
    auto& attempts = it->second;
    while (!attempts.empty() && attempts.front() + kRateLimitWindowSec <= now_sec)
    {
        attempts.pop_front();
    }

    if (attempts.size() >= kMaxAttemptsPerWindowPerSource)
    {
        LOG_WARN("{} conn {} remote {}:{} reason {} stage rate_limit mode per_source attempts {} window_sec {} limit {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 remote_addr,
                 request.remote_port,
                 log_reason,
                 attempts.size(),
                 kRateLimitWindowSec,
                 kMaxAttemptsPerWindowPerSource);
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

}    // namespace reality
