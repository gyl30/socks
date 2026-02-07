#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <cstdint>

#include "replay_cache.h"

namespace mux
{

bool replay_cache::check_and_insert(const std::vector<std::uint8_t>& sid)
{
    if (sid.size() != 32)
    {
        return false;
    }
    const std::string key(sid.begin(), sid.end());

    const std::scoped_lock lock(mutex_);
    cleanup();

    if (cache_.contains(key))
    {
        return false;
    }

    cache_.insert(key);
    history_.push_back({.time = std::chrono::steady_clock::now(), .sid = key});
    return true;
}

void replay_cache::cleanup()
{
    const auto now = std::chrono::steady_clock::now();
    while (!history_.empty() && (now - history_.front().time > std::chrono::minutes(5)))
    {
        cache_.erase(history_.front().sid);
        history_.pop_front();
    }
}

}    // namespace mux
