#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <optional>
#include "log.h"
#include "log_context.h"
#include "reality_messages.h"

namespace reality
{

struct cert_entry
{
    std::vector<uint8_t> cert_msg;
    server_fingerprint fingerprint;
};

class cert_manager
{
   public:
    cert_manager() = default;

    [[nodiscard]] std::optional<cert_entry> get_certificate(const std::string& sni)
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

    void set_certificate(const std::string& sni, std::vector<uint8_t> cert_msg, server_fingerprint fp, const std::string& trace_id = "")
    {
        const std::scoped_lock lock(mutex_);

        if (cache_.size() > 100)
        {
            cache_.clear();
        }

        cert_entry entry{.cert_msg = std::move(cert_msg), .fingerprint = std::move(fp)};
        cache_[sni] = std::move(entry);

        connection_context ctx;
        ctx.trace_id = trace_id;
        ctx.sni = sni;

        LOG_CTX_INFO(ctx,
                     "{} cached cert size {} alpn '{}' cipher 0x{:04x}",
                     log_event::CERT,
                     cache_[sni].cert_msg.size(),
                     cache_[sni].fingerprint.alpn,
                     cache_[sni].fingerprint.cipher_suite);
    }

   private:
    std::mutex mutex_;
    std::map<std::string, cert_entry> cache_;
};

}    // namespace reality

#endif
