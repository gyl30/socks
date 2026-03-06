#include <list>
#include <mutex>
#include <string>
#include <string_view>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <utility>
#include <iterator>
#include <optional>

#include "log.h"
#include "log_context.h"
#include "cert_manager.h"

namespace reality
{

namespace
{

std::string normalize_sni_key(std::string_view sni)
{
    std::size_t begin = 0;
    while (begin < sni.size() && std::isspace(static_cast<unsigned char>(sni[begin])) != 0)
    {
        ++begin;
    }
    std::size_t end = sni.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(sni[end - 1])) != 0)
    {
        --end;
    }
    std::string normalized;
    normalized.reserve(end - begin);
    for (std::size_t i = begin; i < end; ++i)
    {
        const char ch = sni[i];
        if (ch == '\0')
        {
            break;
        }
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    while (!normalized.empty() && normalized.back() == '.')
    {
        normalized.pop_back();
    }
    return normalized;
}

}    // namespace

site_material_manager::site_material_manager(const std::size_t capacity) : capacity_(capacity > 0 ? capacity : 1) {}

std::optional<site_material_snapshot> site_material_manager::get_material_snapshot(const std::string& cache_key)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto key = normalize_sni_key(cache_key);
    if (auto it = index_.find(key); it != index_.end())
    {
        touch(it->second);
        return it->second->snapshot;
    }
    return std::nullopt;
}

void site_material_manager::mark_fetch_started(const std::string& cache_key,
                                               const std::string& target_host,
                                               const std::string& target_sni,
                                               const std::uint16_t port,
                                               const std::uint64_t attempt_at_unix_seconds,
                                               const std::string& trace_id)
{
    const auto key = normalize_sni_key(cache_key);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (auto it = index_.find(key); it != index_.end())
        {
            auto& snapshot = it->second->snapshot;
            snapshot.target_host = target_host;
            snapshot.target_sni = target_sni;
            snapshot.port = port;
            snapshot.fetch_in_progress = true;
            snapshot.last_attempt_at_unix_seconds = attempt_at_unix_seconds;
            touch(it->second);
        }
        else
        {
            site_material_snapshot snapshot;
            snapshot.target_host = target_host;
            snapshot.target_sni = target_sni;
            snapshot.port = port;
            snapshot.fetch_in_progress = true;
            snapshot.last_attempt_at_unix_seconds = attempt_at_unix_seconds;
            lru_.push_front({.cache_key = key, .snapshot = std::move(snapshot)});
            index_[key] = lru_.begin();
            evict_if_needed();
        }
    }

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(key);

    LOG_CTX_INFO(ctx, "{} fetch started target={}:{}", mux::log_event::kCert, target_host, port);
}

void site_material_manager::set_material(const std::string& cache_key,
                                         const std::string& target_host,
                                         const std::string& target_sni,
                                         const std::uint16_t port,
                                         site_material material,
                                         const std::uint64_t next_refresh_at_unix_seconds,
                                         const std::string& trace_id)
{
    const auto key = normalize_sni_key(cache_key);
    site_material cached_material;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        auto it = index_.find(key);
        if (it == index_.end())
        {
            site_material_snapshot snapshot;
            snapshot.target_host = target_host;
            snapshot.target_sni = target_sni;
            snapshot.port = port;
            snapshot.fetch_in_progress = false;
            snapshot.last_attempt_at_unix_seconds = material.fetched_at_unix_seconds;
            snapshot.last_success_at_unix_seconds = material.fetched_at_unix_seconds;
            snapshot.next_refresh_at_unix_seconds = next_refresh_at_unix_seconds;
            snapshot.last_error.clear();
            snapshot.material = std::move(material);
            lru_.push_front({.cache_key = key, .snapshot = std::move(snapshot)});
            index_[key] = lru_.begin();
            evict_if_needed();
            it = index_.find(key);
        }
        else
        {
            auto& snapshot = it->second->snapshot;
            snapshot.target_host = target_host;
            snapshot.target_sni = target_sni;
            snapshot.port = port;
            snapshot.fetch_in_progress = false;
            snapshot.last_attempt_at_unix_seconds = material.fetched_at_unix_seconds;
            snapshot.last_success_at_unix_seconds = material.fetched_at_unix_seconds;
            snapshot.next_refresh_at_unix_seconds = next_refresh_at_unix_seconds;
            snapshot.last_error.clear();
            snapshot.material = std::move(material);
            touch(it->second);
        }
        cached_material = *(it->second->snapshot.material);
    }

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(key);

    LOG_CTX_INFO(ctx,
                 "{} cached site material certs={} cert_msg={} alpn='{}' cipher=0x{:04x} sh_exts={} ee_exts={} groups={}",
                 mux::log_event::kCert,
                 cached_material.certificate_chain.size(),
                 cached_material.certificate_message.size(),
                 cached_material.fingerprint.alpn,
                 cached_material.fingerprint.cipher_suite,
                 cached_material.server_hello_extension_types.size(),
                 cached_material.encrypted_extension_types.size(),
                 cached_material.key_share_groups.size());
}

void site_material_manager::set_fetch_failure(const std::string& cache_key,
                                              const std::string& target_host,
                                              const std::string& target_sni,
                                              const std::uint16_t port,
                                              std::string error,
                                              const std::uint64_t attempt_at_unix_seconds,
                                              const std::uint64_t next_refresh_at_unix_seconds,
                                              const std::string& trace_id)
{
    const auto key = normalize_sni_key(cache_key);
    bool has_stale_material = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        auto it = index_.find(key);
        if (it == index_.end())
        {
            site_material_snapshot snapshot;
            snapshot.target_host = target_host;
            snapshot.target_sni = target_sni;
            snapshot.port = port;
            snapshot.fetch_in_progress = false;
            snapshot.last_attempt_at_unix_seconds = attempt_at_unix_seconds;
            snapshot.next_refresh_at_unix_seconds = next_refresh_at_unix_seconds;
            snapshot.last_error = std::move(error);
            lru_.push_front({.cache_key = key, .snapshot = std::move(snapshot)});
            index_[key] = lru_.begin();
            evict_if_needed();
            it = index_.find(key);
        }
        else
        {
            auto& snapshot = it->second->snapshot;
            snapshot.target_host = target_host;
            snapshot.target_sni = target_sni;
            snapshot.port = port;
            snapshot.fetch_in_progress = false;
            snapshot.last_attempt_at_unix_seconds = attempt_at_unix_seconds;
            snapshot.next_refresh_at_unix_seconds = next_refresh_at_unix_seconds;
            snapshot.last_error = std::move(error);
            has_stale_material = snapshot.material.has_value();
            touch(it->second);
        }
        has_stale_material = has_stale_material || (it->second->snapshot.material.has_value());
        error = it->second->snapshot.last_error;
    }

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(key);

    LOG_CTX_WARN(ctx,
                 "{} fetch failed target={}:{} stale_material={} error={}",
                 mux::log_event::kCert,
                 target_host,
                 port,
                 has_stale_material,
                 error);
}

void site_material_manager::touch(const std::list<cache_node>::iterator& it)
{
    if (it != lru_.begin())
    {
        lru_.splice(lru_.begin(), lru_, it);
    }
}

void site_material_manager::evict_if_needed()
{
    while (index_.size() > capacity_)
    {
        auto last = std::prev(lru_.end());
        index_.erase(last->cache_key);
        lru_.pop_back();
    }
}

}    // namespace reality
