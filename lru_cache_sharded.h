#ifndef LRU_CACHE_SHARDED_H
#define LRU_CACHE_SHARDED_H

#include <algorithm>
#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <thread>
#include <utility>
#include <vector>

#include "lru_cache.h"

namespace mux
{

// Thread-safe sharded LRU cache. Sharding reduces lock contention.
// Note: returns by value to avoid dangling references after unlock.
template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
class sharded_lru_cache
{
   public:
    explicit sharded_lru_cache(std::size_t capacity, std::size_t shard_count = 0)
        : shards_(std::max<std::size_t>(1, shard_count == 0 ? recommend_shard_count(capacity) : shard_count))
    {
        redistribute_capacity(capacity);
    }

    [[nodiscard]] std::size_t capacity() const
    {
        std::size_t total = 0;
        for (const auto& shard : shards_)
        {
            std::shared_lock lock(shard.mutex);
            total += shard.cache.capacity();
        }
        return total;
    }

    [[nodiscard]] std::size_t size() const
    {
        std::size_t total = 0;
        for (const auto& shard : shards_)
        {
            std::shared_lock lock(shard.mutex);
            total += shard.cache.size();
        }
        return total;
    }

    [[nodiscard]] bool empty() const { return size() == 0; }

    void set_capacity(std::size_t capacity)
    {
        auto locks = lock_all();
        (void)locks;
        redistribute_capacity_locked(capacity);
    }

    void clear()
    {
        for (auto& shard : shards_)
        {
            std::unique_lock lock(shard.mutex);
            shard.cache.clear();
        }
    }

    [[nodiscard]] bool contains(const Key& key) const
    {
        auto& shard = shard_for_key(key);
        std::shared_lock lock(shard.mutex);
        return shard.cache.contains(key);
    }

    [[nodiscard]] std::optional<Value> get(const Key& key)
    {
        Value out;
        if (!get(key, out))
        {
            return std::nullopt;
        }
        return out;
    }

    bool get(const Key& key, Value& out)
    {
        auto& shard = shard_for_key(key);
        std::unique_lock lock(shard.mutex);
        return shard.cache.get(key, out);
    }

    [[nodiscard]] std::optional<Value> peek(const Key& key) const
    {
        Value out;
        if (!peek(key, out))
        {
            return std::nullopt;
        }
        return out;
    }

    bool peek(const Key& key, Value& out) const
    {
        auto& shard = shard_for_key(key);
        std::shared_lock lock(shard.mutex);
        const auto* ptr = shard.cache.peek(key);
        if (ptr == nullptr)
        {
            return false;
        }
        out = *ptr;
        return true;
    }

    template <typename F>
    bool update(const Key& key, F&& f)
    {
        auto& shard = shard_for_key(key);
        std::unique_lock lock(shard.mutex);
        auto* ptr = shard.cache.get(key);
        if (ptr == nullptr)
        {
            return false;
        }
        f(*ptr);
        return true;
    }

    template <typename V, typename F>
    bool upsert(const Key& key, V&& initial, F&& f)
    {
        auto& shard = shard_for_key(key);
        std::unique_lock lock(shard.mutex);
        auto* ptr = shard.cache.get(key);
        if (ptr == nullptr)
        {
            shard.cache.put(key, std::forward<V>(initial));
            ptr = shard.cache.get(key);
            if (ptr == nullptr)
            {
                return false;
            }
        }
        f(*ptr);
        return true;
    }

    template <typename K, typename V>
    void put(K&& key, V&& value)
    {
        auto& shard = shard_for_key(key);
        std::unique_lock lock(shard.mutex);
        shard.cache.put(std::forward<K>(key), std::forward<V>(value));
    }

    bool erase(const Key& key)
    {
        auto& shard = shard_for_key(key);
        std::unique_lock lock(shard.mutex);
        return shard.cache.erase(key);
    }

   private:
    static constexpr std::size_t kMinEntriesPerShard = 64;

    struct shard_entry
    {
        mutable std::shared_mutex mutex;
        lru_cache<Key, Value, Hash, KeyEqual> cache{0};
    };

    static std::size_t recommend_shard_count(const std::size_t capacity)
    {
        if (capacity == 0 || capacity <= kMinEntriesPerShard)
        {
            return 1;
        }
        auto hc = std::thread::hardware_concurrency();
        if (hc == 0)
        {
            hc = 4;
        }
        auto shards = std::min<std::size_t>(64, std::max<std::size_t>(4, hc));
        const auto max_by_capacity = std::max<std::size_t>(1, capacity / kMinEntriesPerShard);
        shards = std::min(shards, max_by_capacity);
        return std::max<std::size_t>(1, shards);
    }

    shard_entry& shard_for_key(const Key& key) const
    {
        const std::size_t idx = hasher_(key) % shards_.size();
        return const_cast<shard_entry&>(shards_[idx]);
    }

    std::vector<std::unique_lock<std::shared_mutex>> lock_all()
    {
        std::vector<std::unique_lock<std::shared_mutex>> locks;
        locks.reserve(shards_.size());
        for (auto& shard : shards_)
        {
            locks.emplace_back(shard.mutex);
        }
        return locks;
    }

    void redistribute_capacity(std::size_t total_capacity)
    {
        auto locks = lock_all();
        (void)locks;
        redistribute_capacity_locked(total_capacity);
    }

    void redistribute_capacity_locked(std::size_t total_capacity)
    {
        const std::size_t n = shards_.size();
        const std::size_t base = (n == 0) ? 0 : (total_capacity / n);
        const std::size_t rem = (n == 0) ? 0 : (total_capacity % n);
        for (std::size_t i = 0; i < n; ++i)
        {
            const std::size_t cap = base + ((i < rem) ? 1 : 0);
            shards_[i].cache.set_capacity(cap);
        }
    }

    Hash hasher_{};
    std::vector<shard_entry> shards_;
};

}    // namespace mux

#endif
