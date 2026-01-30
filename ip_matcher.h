#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#include <vector>
#include <string>
#include <fstream>
#include <array>
#include <algorithm>
#include <asio.hpp>
#include "log.h"

namespace mux
{

struct range_v4
{
    uint32_t start;
    uint32_t end;
};
struct u128_ip
{
    uint64_t hi;
    uint64_t lo;
};
struct range_v6
{
    u128_ip start;
    u128_ip end;
};

inline u128_ip make_u128_from_bytes(const std::array<uint8_t, 16>& bytes)
{
    uint64_t hi = 0;
    uint64_t lo = 0;
    for (int i = 0; i < 8; ++i)
    {
        hi = (hi << 8) | bytes[i];
    }
    for (int i = 8; i < 16; ++i)
    {
        lo = (lo << 8) | bytes[i];
    }
    return {.hi = hi, .lo = lo};
}

inline bool u128_less(const u128_ip& a, const u128_ip& b) { return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo; }
inline bool u128_less_equal(const u128_ip& a, const u128_ip& b) { return !u128_less(b, a); }
inline bool u128_equal(const u128_ip& a, const u128_ip& b) { return a.hi == b.hi && a.lo == b.lo; }
inline u128_ip u128_next(u128_ip v)
{
    if (++v.lo == 0)
    {
        ++v.hi;
    }
    return v;
}
inline bool u128_is_max(const u128_ip& v) { return v.hi == ~0ULL && v.lo == ~0ULL; }

inline uint32_t make_mask_v4(int prefix_len)
{
    if (prefix_len == 0)
    {
        return 0;
    }
    if (prefix_len == 32)
    {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32 - prefix_len);
}

inline u128_ip make_mask_v6(int prefix_len)
{
    if (prefix_len <= 0)
    {
        return {.hi = 0, .lo = 0};
    }
    if (prefix_len >= 128)
    {
        return {.hi = ~0ULL, .lo = ~0ULL};
    }

    u128_ip mask{.hi = 0, .lo = 0};
    if (prefix_len >= 64)
    {
        mask.hi = ~0ULL;
        mask.lo = (prefix_len == 64) ? 0 : (~0ULL << (128 - prefix_len));
    }
    else
    {
        mask.hi = ~0ULL << (64 - prefix_len);
        mask.lo = 0;
    }
    return mask;
}

class ip_matcher
{
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
        optimize();
        LOG_INFO("loaded and optimized ip rules {} v4 ranges {} v6 ranges", rules_v4_.size(), rules_v6_.size());
        return true;
    }

    [[nodiscard]] bool match(const asio::ip::address& addr) const
    {
        if (addr.is_v4())
        {
            uint32_t val = addr.to_v4().to_uint();
            auto it = std::ranges::upper_bound(rules_v4_, val, {}, &range_v4::start);
            if (it != rules_v4_.begin())
            {
                --it;
                return val <= it->end;
            }
            return false;
        }
        if (addr.is_v6())
        {
            u128_ip val = make_u128_from_bytes(addr.to_v6().to_bytes());
            auto it = std::ranges::upper_bound(rules_v6_, val, u128_less, &range_v6::start);
            if (it != rules_v6_.begin())
            {
                --it;
                return u128_less_equal(val, it->end);
            }
            return false;
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
        std::error_code ec;
        auto addr = asio::ip::make_address(ip_part, ec);
        if (ec)
        {
            LOG_ERROR("{} parse address failed {}", ip_part, ec.message());
            return;
        }

        if (addr.is_v4())
        {
            if (prefix_len < 0 || prefix_len > 32)
            {
                return;
            }
            uint32_t mask = make_mask_v4(prefix_len);
            uint32_t start = addr.to_v4().to_uint() & mask;
            uint32_t end = start | (~mask);
            rules_v4_.push_back({start, end});
        }
        else if (addr.is_v6())
        {
            if (prefix_len < 0 || prefix_len > 128)
            {
                return;
            }
            u128_ip mask = make_mask_v6(prefix_len);
            u128_ip start = make_u128_from_bytes(addr.to_v6().to_bytes());
            start.hi &= mask.hi;
            start.lo &= mask.lo;
            u128_ip end = start;
            end.hi |= ~mask.hi;
            end.lo |= ~mask.lo;
            rules_v6_.push_back({start, end});
        }
    }

    void optimize()
    {
        if (!rules_v4_.empty())
        {
            optimize_v4();
        }
        if (!rules_v6_.empty())
        {
            optimize_v6();
        }
    }

    void optimize_v4()
    {
        std::ranges::sort(rules_v4_, {}, &range_v4::start);
        std::vector<range_v4> merged;
        merged.reserve(rules_v4_.size());
        merged.push_back(rules_v4_[0]);
        for (size_t i = 1; i < rules_v4_.size(); ++i)
        {
            auto& last = merged.back();
            auto& curr = rules_v4_[i];
            bool connected = (curr.start <= last.end) || (last.end != 0xFFFFFFFF && curr.start == last.end + 1);
            if (connected)
            {
                last.end = std::max(last.end, curr.end);
            }
            else
            {
                merged.push_back(curr);
            }
        }
        rules_v4_ = std::move(merged);
    }

    void optimize_v6()
    {
        std::ranges::sort(rules_v6_, u128_less, &range_v6::start);
        std::vector<range_v6> merged;
        merged.reserve(rules_v6_.size());
        merged.push_back(rules_v6_[0]);
        for (size_t i = 1; i < rules_v6_.size(); ++i)
        {
            auto& last = merged.back();
            auto& curr = rules_v6_[i];

            bool overlap = u128_less_equal(curr.start, last.end);
            bool adjacent = !overlap && !u128_is_max(last.end) && u128_equal(u128_next(last.end), curr.start);
            if (overlap || adjacent)
            {
                last.end = u128_less(last.end, curr.end) ? curr.end : last.end;
            }
            else
            {
                merged.push_back(curr);
            }
        }
        rules_v6_ = std::move(merged);
    }

   private:
    std::vector<range_v4> rules_v4_;
    std::vector<range_v6> rules_v6_;
};

}    // namespace mux

#endif
