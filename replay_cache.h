#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include <deque>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <unordered_set>

namespace mux
{

class replay_cache
{
   public:
    explicit replay_cache(std::size_t max_entries = 100000);

    bool check_and_insert(const std::vector<std::uint8_t>& sid);

   private:
    void cleanup();
    void evict_excess();

    struct entry
    {
        std::chrono::steady_clock::time_point time;
        std::string sid;
    };

    std::size_t max_entries_ = 100000;
    std::unordered_set<std::string> cache_;
    std::deque<entry> history_;
};

}    // namespace mux

#endif
