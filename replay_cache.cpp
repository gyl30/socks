#include <mutex>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>

#include "constants.h"
#include "replay_cache.h"

namespace mux
{

replay_cache::replay_cache(std::size_t max_entries) : replay_cache(max_entries, constants::replay::kWindow) {}

replay_cache::replay_cache(std::size_t max_entries, const std::chrono::steady_clock::duration window)
    : max_entries_(max_entries > 0 ? max_entries : 1), window_(window)
{
}

bool replay_cache::check_and_insert(const std::vector<uint8_t>& sid)
{
    if (sid.size() != 32)
    {
        return false;
    }
    const std::string key(sid.begin(), sid.end());

    const std::scoped_lock lock(mutex_);
    rotate_if_needed(std::chrono::steady_clock::now());

    if (current_.contains(key) || previous_.contains(key))
    {
        return false;
    }

    if (current_.size() + previous_.size() >= max_entries_)
    {
        return false;
    }

    current_.insert(key);
    return true;
}

void replay_cache::rotate_if_needed(const std::chrono::steady_clock::time_point now)
{
    if (!current_ready_)
    {
        current_start_ = now;
        current_ready_ = true;
        return;
    }

    if (window_ <= std::chrono::steady_clock::duration::zero())
    {
        current_.clear();
        previous_.clear();
        current_start_ = now;
        return;
    }

    const auto elapsed = now - current_start_;
    if (elapsed < window_)
    {
        return;
    }

    if (elapsed - window_ >= window_)
    {
        current_.clear();
        previous_.clear();
        current_start_ = now;
        return;
    }

    previous_.clear();
    previous_.swap(current_);
    current_.clear();
    current_start_ = now;
}

}    // namespace mux
