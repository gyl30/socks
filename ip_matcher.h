#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#include <vector>
#include <string>
#include <fstream>
#include <asio.hpp>
#include "log.h"

namespace mux
{

class ip_matcher
{
    struct cidr_rule
    {
        asio::ip::address network;
        asio::ip::address mask;
    };

   public:
    ip_matcher() = default;

    bool load(const std::string& filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            LOG_WARN("failed to open direct ip file {}", filename);
            return false;
        }

        std::string line;
        while (std::getline(file, line))
        {
            if (line.empty() || line[0] == '#')
            {
                continue;
            }

            if (line.back() == '\r')
            {
                line.pop_back();
            }

            add_rule(line);
        }
        LOG_INFO("loaded {} direct ip rules", rules_v4_.size() + rules_v6_.size());
        return true;
    }

    [[nodiscard]] bool match(const asio::ip::address& addr) const
    {
        if (addr.is_v4())
        {
            for (const auto& rule : rules_v4_)
            {
                if ((addr.to_v4().to_uint() & rule.mask.to_v4().to_uint()) == rule.network.to_v4().to_uint())
                {
                    return true;
                }
            }
        }
        else if (addr.is_v6())
        {
            auto bytes = addr.to_v6().to_bytes();
            for (const auto& rule : rules_v6_)
            {
                auto rule_bytes = rule.network.to_v6().to_bytes();
                auto mask_bytes = rule.mask.to_v6().to_bytes();
                bool match = true;
                for (size_t i = 0; i < 16; ++i)
                {
                    if ((bytes[i] & mask_bytes[i]) != rule_bytes[i])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    return true;
                }
            }
        }
        return false;
    }

   private:
    void add_rule(const std::string& cidr)
    {
        auto slash_pos = cidr.find('/');
        if (slash_pos == std::string::npos)
        {
            return;
        }

        std::string ip_part = cidr.substr(0, slash_pos);
        int prefix_len = std::stoi(cidr.substr(slash_pos + 1));

        auto addr = asio::ip::make_address(ip_part);

        if (addr.is_v4())
        {
            if (prefix_len < 0 || prefix_len > 32)
            {
                return;
            }
            uint32_t mask_val = (prefix_len == 0) ? 0 : (0xFFFFFFFFU << (32 - prefix_len));
            asio::ip::address_v4 mask(mask_val);
            asio::ip::address_v4 network(addr.to_v4().to_uint() & mask_val);
            rules_v4_.push_back({network, mask});
        }
        else if (addr.is_v6())
        {
            if (prefix_len < 0 || prefix_len > 128)
            {
                return;
            }
            asio::ip::address_v6::bytes_type mask_bytes = {0};
            for (int i = 0; i < 16; ++i)
            {
                if (prefix_len >= 8)
                {
                    mask_bytes[i] = 0xFF;
                    prefix_len -= 8;
                }
                else if (prefix_len > 0)
                {
                    mask_bytes[i] = static_cast<uint8_t>(0xFF << (8 - prefix_len));
                    prefix_len = 0;
                }
                else
                {
                    mask_bytes[i] = 0x00;
                }
            }

            auto addr_bytes = addr.to_v6().to_bytes();
            asio::ip::address_v6::bytes_type net_bytes;
            for (int i = 0; i < 16; ++i)
            {
                net_bytes[i] = addr_bytes[i] & mask_bytes[i];
            }

            rules_v6_.push_back({asio::ip::address_v6(net_bytes), asio::ip::address_v6(mask_bytes)});
        }
    }

   private:
    std::vector<cidr_rule> rules_v4_;
    std::vector<cidr_rule> rules_v6_;
};

}    // namespace mux

#endif
