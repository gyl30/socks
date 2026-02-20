#include <chrono>
#include <cstddef>
#include <string>
#include <vector>
#include <cstdint>

#include "constants.h"
#include "replay_cache.h"

namespace mux
{

namespace
{
constexpr auto kReplayCacheWindow = std::chrono::seconds(constants::auth::kMaxClockSkewSec * 2);
}

replay_cache::replay_cache(const std::size_t max_entries) : replay_cache(max_entries, kReplayCacheWindow) {}

replay_cache::replay_cache(const std::size_t max_entries, const std::chrono::steady_clock::duration window)
    : max_entries_(max_entries > 0 ? max_entries : 1), window_(window)
{
}

bool replay_cache::check_and_insert(const std::vector<std::uint8_t>& sid)
{
    if (sid.size() != 32)
    {
        return false;
    }
    const std::string key(sid.begin(), sid.end());

    cleanup();

    if (cache_.contains(key))
    {
        return false;
    }

    cache_.insert(key);
    history_.push_back({.time = std::chrono::steady_clock::now(), .sid = key});
    evict_excess();
    return true;
}

void replay_cache::cleanup()
{
    const auto now = std::chrono::steady_clock::now();
    while (!history_.empty() && (now - history_.front().time > window_))
    {
        cache_.erase(history_.front().sid);
        history_.pop_front();
    }
}

void replay_cache::evict_excess()
{
    while (cache_.size() > max_entries_ && !history_.empty())
    {
        cache_.erase(history_.front().sid);
        history_.pop_front();
    }
}

}    // namespace mux
