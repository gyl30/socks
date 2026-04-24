#ifndef UDP_PROXY_OUTBOUND_REGISTRY_H
#define UDP_PROXY_OUTBOUND_REGISTRY_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "udp_proxy_outbound.h"

namespace relay
{

class udp_proxy_outbound_registry
{
   public:
    [[nodiscard]] bool empty() const { return outbounds_.empty(); }

    [[nodiscard]] std::shared_ptr<udp_proxy_outbound> get(const std::string& outbound_tag) const
    {
        const auto it = outbounds_.find(outbound_tag);
        return it == outbounds_.end() ? nullptr : it->second;
    }

    void put(const std::string& outbound_tag, std::shared_ptr<udp_proxy_outbound> outbound)
    {
        outbounds_.insert_or_assign(outbound_tag, std::move(outbound));
    }

    void erase_if_current(const std::string& outbound_tag, const std::shared_ptr<udp_proxy_outbound>& outbound)
    {
        const auto it = outbounds_.find(outbound_tag);
        if (outbound == nullptr || it == outbounds_.end() || it->second != outbound)
        {
            return;
        }
        outbounds_.erase(it);
    }

    [[nodiscard]] std::vector<std::shared_ptr<udp_proxy_outbound>> take_all()
    {
        std::vector<std::shared_ptr<udp_proxy_outbound>> outbounds;
        outbounds.reserve(outbounds_.size());
        for (auto& [_, outbound] : outbounds_)
        {
            if (outbound != nullptr)
            {
                outbounds.push_back(std::move(outbound));
            }
        }
        outbounds_.clear();
        return outbounds;
    }

   private:
    std::unordered_map<std::string, std::shared_ptr<udp_proxy_outbound>> outbounds_;
};

}    // namespace relay

#endif
