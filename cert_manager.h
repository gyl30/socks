#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <list>
#include <mutex>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>

#include "site_material.h"

namespace reality
{

class site_material_manager
{
   public:
    explicit site_material_manager(std::size_t capacity = 16);

    [[nodiscard]] std::optional<site_material_snapshot> get_material_snapshot(const std::string& cache_key);

    void mark_fetch_started(const std::string& cache_key,
                            const std::string& target_host,
                            const std::string& target_sni,
                            std::uint16_t port,
                            std::uint64_t attempt_at_unix_seconds,
                            const std::string& trace_id = "");

    void set_material(const std::string& cache_key,
                      const std::string& target_host,
                      const std::string& target_sni,
                      std::uint16_t port,
                      site_material material,
                      std::uint64_t next_refresh_at_unix_seconds,
                      const std::string& trace_id = "");

    void set_fetch_failure(const std::string& cache_key,
                           const std::string& target_host,
                           const std::string& target_sni,
                           std::uint16_t port,
                           std::string error,
                           std::uint64_t attempt_at_unix_seconds,
                           std::uint64_t next_refresh_at_unix_seconds,
                           const std::string& trace_id = "");

   private:
    struct cache_node
    {
        std::string cache_key;
        site_material_snapshot snapshot;
    };

    void touch(const std::list<cache_node>::iterator& it);
    void evict_if_needed();

    std::size_t capacity_ = 16;
    std::list<cache_node> lru_;
    std::unordered_map<std::string, std::list<cache_node>::iterator> index_;
    mutable std::mutex mutex_;
};

}    // namespace reality

#endif
