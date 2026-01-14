#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include <deque>
#include <vector>
#include <mutex>
#include <unordered_set>
#include "cert_manager.h"

namespace mux
{

class replay_cache
{
   public:
    bool check_and_insert(const std::vector<uint8_t> &sid)
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

   private:
    void cleanup()
    {
        auto now = std::chrono::steady_clock::now();
        while (!history_.empty() && (now - history_.front().time > std::chrono::minutes(5)))
        {
            cache_.erase(history_.front().sid);
            history_.pop_front();
        }
    }

    struct entry
    {
        std::chrono::steady_clock::time_point time;
        std::string sid;
    };

    std::mutex mutex_;
    std::unordered_set<std::string> cache_;
    std::deque<entry> history_;
};

}    // namespace mux

#endif
