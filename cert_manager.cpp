#include <mutex>
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

std::optional<cert_entry> cert_manager::get_certificate(const std::string& sni)
{
    const std::scoped_lock lock(mutex_);
    if (auto it = cache_.find(sni); it != cache_.end())
    {
        return it->second;
    }

    if (auto it = cache_.find(""); it != cache_.end())
    {
        return it->second;
    }
    return std::nullopt;
}

void cert_manager::set_certificate(const std::string& sni, std::vector<uint8_t> cert_msg, server_fingerprint fp, const std::string& trace_id)
{
    const std::scoped_lock lock(mutex_);

    if (cache_.size() > 100)
    {
        cache_.clear();
    }

    cert_entry entry{.cert_msg = std::move(cert_msg), .fingerprint = std::move(fp)};
    cache_[sni] = std::move(entry);

    mux::connection_context ctx;
    ctx.trace_id = trace_id;
    ctx.sni = sni;

    LOG_CTX_INFO(ctx,
                 "{} cached cert size {} alpn '{}' cipher 0x{:04x}",
                 mux::log_event::CERT,
                 cache_[sni].cert_msg.size(),
                 cache_[sni].fingerprint.alpn,
                 cache_[sni].fingerprint.cipher_suite);
}

}    // namespace reality
