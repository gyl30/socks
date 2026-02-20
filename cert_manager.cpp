#include <cstddef>
#include <mutex>
#include <cstdint>
#include <list>
#include <iterator>
#include <string>
#include <vector>
#include <utility>
#include <optional>

#include "log.h"
#include "log_context.h"
#include "cert_manager.h"
#include "reality_messages.h"

namespace reality
{

cert_manager::cert_manager(const std::size_t capacity) : capacity_(capacity > 0 ? capacity : 1) {}

std::optional<cert_entry> cert_manager::get_certificate(const std::string& sni)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (auto it = index_.find(sni); it != index_.end())
    {
        touch(it->second);
        return it->second->entry;
    }

    if (auto it = index_.find(""); it != index_.end())
    {
        touch(it->second);
        return it->second->entry;
    }
    return std::nullopt;
}

void cert_manager::set_certificate(const std::string& sni, std::vector<std::uint8_t> cert_msg, server_fingerprint fp, const std::string& trace_id)
{
    cert_entry cached_entry;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        cert_entry new_entry{.cert_msg = std::move(cert_msg), .fingerprint = std::move(fp)};
        if (auto it = index_.find(sni); it != index_.end())
        {
            it->second->entry = std::move(new_entry);
            touch(it->second);
        }
        else
        {
            lru_.push_front({.sni = sni, .entry = std::move(new_entry)});
            index_[sni] = lru_.begin();
            evict_if_needed();
        }

        const auto cache_it = index_.find(sni);
        cached_entry = cache_it->second->entry;
    }

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(sni);

    LOG_CTX_INFO(ctx,
                 "{} cached cert size {} alpn '{}' cipher 0x{:04x}",
                 mux::log_event::kCert,
                 cached_entry.cert_msg.size(),
                 cached_entry.fingerprint.alpn,
                 cached_entry.fingerprint.cipher_suite);
}

void cert_manager::touch(const std::list<cache_node>::iterator& it)
{
    if (it != lru_.begin())
    {
        lru_.splice(lru_.begin(), lru_, it);
    }
}

void cert_manager::evict_if_needed()
{
    while (index_.size() > capacity_)
    {
        auto last = std::prev(lru_.end());
        index_.erase(last->sni);
        lru_.pop_back();
    }
}

}    // namespace reality
