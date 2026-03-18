#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <cstddef>
#include <functional>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

namespace mux
{

// Simple LRU cache (not thread-safe; caller must lock externally).
template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
class lru_cache
{
   public:
    explicit lru_cache(std::size_t capacity) : capacity_(capacity) {}

    [[nodiscard]] std::size_t capacity() const { return capacity_; }
    [[nodiscard]] std::size_t size() const { return index_.size(); }
    [[nodiscard]] bool empty() const { return index_.empty(); }

    void set_capacity(std::size_t capacity)
    {
        capacity_ = capacity;
        evict_if_needed();
    }

    void clear()
    {
        index_.clear();
        items_.clear();
    }

    [[nodiscard]] bool contains(const Key& key) const { return index_.find(key) != index_.end(); }

    // 读取并更新 LRU 顺序，返回值指针在后续 put/erase 后可能失效
    [[nodiscard]] Value* get(const Key& key)
    {
        auto it = index_.find(key);
        if (it == index_.end())
        {
            return nullptr;
        }
        touch(it->second);
        return &it->second->value;
    }

    // 只读不更新 LRU 顺序
    [[nodiscard]] const Value* peek(const Key& key) const
    {
        const auto it = index_.find(key);
        if (it == index_.end())
        {
            return nullptr;
        }
        return &it->second->value;
    }

    bool get(const Key& key, Value& out)
    {
        auto* ptr = get(key);
        if (ptr == nullptr)
        {
            return false;
        }
        out = *ptr;
        return true;
    }

    template <typename K, typename V>
    void put(K&& key, V&& value)
    {
        auto ignored = put_and_evict(std::forward<K>(key), std::forward<V>(value));
        (void)ignored;
    }

    template <typename K, typename V>
    [[nodiscard]] std::optional<std::pair<Key, Value>> put_and_evict(K&& key, V&& value)
    {
        if (capacity_ == 0)
        {
            return std::nullopt;
        }
        auto it = index_.find(key);
        if (it != index_.end())
        {
            it->second->value = std::forward<V>(value);
            touch(it->second);
            return std::nullopt;
        }
        items_.push_front(node{Key(std::forward<K>(key)), Value(std::forward<V>(value))});
        index_[items_.front().key] = items_.begin();
        if (index_.size() <= capacity_)
        {
            return std::nullopt;
        }

        auto last = std::prev(items_.end());
        auto last_index = index_.find(last->key);
        std::optional<std::pair<Key, Value>> evicted(std::in_place, std::move(last->key), std::move(last->value));
        index_.erase(last_index);
        items_.pop_back();
        return evicted;
    }

    bool erase(const Key& key)
    {
        auto it = index_.find(key);
        if (it == index_.end())
        {
            return false;
        }
        items_.erase(it->second);
        index_.erase(it);
        return true;
    }

    // Evict from LRU tail while predicate returns true.
    template <typename Pred>
    std::size_t evict_while(Pred&& pred)
    {
        std::size_t count = 0;
        while (!items_.empty())
        {
            const auto& last = items_.back();
            if (!pred(last.key, last.value))
            {
                break;
            }
            index_.erase(last.key);
            items_.pop_back();
            ++count;
        }
        return count;
    }

   private:
    struct node
    {
        Key key;
        Value value;
    };

    void touch(typename std::list<node>::iterator it)
    {
        if (it != items_.begin())
        {
            items_.splice(items_.begin(), items_, it);
        }
    }

    void evict_if_needed()
    {
        if (capacity_ == 0)
        {
            clear();
            return;
        }
        while (index_.size() > capacity_)
        {
            auto last = std::prev(items_.end());
            index_.erase(last->key);
            items_.pop_back();
        }
    }

    std::size_t capacity_ = 0;
    std::list<node> items_;
    std::unordered_map<Key, typename std::list<node>::iterator, Hash, KeyEqual> index_;
};

}    // namespace mux

#endif
