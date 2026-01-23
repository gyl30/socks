#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <optional>
#include "log.h"

namespace reality
{
class cert_manager
{
   public:
    cert_manager() = default;

    [[nodiscard]] std::optional<std::vector<uint8_t>> get_certificate(const std::string& sni)
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

    void set_certificate(const std::string& sni, std::vector<uint8_t> cert_msg)
    {
        const std::scoped_lock lock(mutex_);

        if (cache_.size() > 100)
        {
            cache_.clear();
        }
        cache_[sni] = std::move(cert_msg);
        LOG_INFO("cert manager cached certificate for sni {} size {}", sni, cache_[sni].size());
    }

   private:
    std::mutex mutex_;
    std::map<std::string, std::vector<uint8_t>> cache_;
};

}    // namespace reality

#endif
