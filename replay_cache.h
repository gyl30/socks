#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include <mutex>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <unordered_set>

namespace mux
{

class replay_cache
{
   public:
    explicit replay_cache(std::size_t max_entries = 100000);
    replay_cache(std::size_t max_entries, std::chrono::steady_clock::duration window);

    bool check_and_insert(const std::vector<std::uint8_t>& sid);

   private:
    void rotate_if_needed(std::chrono::steady_clock::time_point now);

    std::mutex mutex_;
    std::size_t max_entries_ = 100000;
    std::chrono::steady_clock::duration window_;
    std::chrono::steady_clock::time_point current_start_{};
    bool current_ready_ = false;
    std::unordered_set<std::string> current_;
    std::unordered_set<std::string> previous_;
};

}    // namespace mux

#endif
