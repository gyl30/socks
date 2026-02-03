#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include <deque>
#include <mutex>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_set>

namespace mux
{

class replay_cache
{
   public:
    bool check_and_insert(const std::vector<uint8_t>& sid);

   private:
    void cleanup();

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
