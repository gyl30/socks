#include "ip_matcher.h"
#include <fstream>
#include <algorithm>
#include <charconv>

namespace mux
{

static uint32_t make_mask_v4(int prefix_len)
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

static u128_ip make_mask_v6(int prefix_len)
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

bool ip_matcher::load(const std::string& filename)
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

bool ip_matcher::match(const asio::ip::address& addr) const
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

static std::string_view trim(std::string_view sv)
{
    auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos)
        return {};
    auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

void ip_matcher::add_rule(const std::string& cidr)
{
    std::string_view line_sv = cidr;
    auto slash_pos = line_sv.find('/');
    if (slash_pos == std::string_view::npos)
    {
        return;
    }
    auto ip_part = trim(line_sv.substr(0, slash_pos));
    auto len_part = trim(line_sv.substr(slash_pos + 1));

    int prefix_len = 0;
    auto [ptr, from_ec] = std::from_chars(len_part.data(), len_part.data() + len_part.size(), prefix_len);
    if (from_ec != std::errc() || ptr != len_part.data() + len_part.size())
    {
        LOG_WARN("invalid prefix length {}", len_part);
        return;
    }
    std::error_code ec;

    auto addr = asio::ip::make_address(std::string(ip_part), ec);
    if (ec)
    {
        LOG_ERROR("{} parse address failed {}", ip_part, ec.message());
        return;
    }

    if (addr.is_v4())
    {
        if (prefix_len < 0 || prefix_len > 32)
        {
            LOG_WARN("invalid ipv4 prefix length {}", prefix_len);
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
            LOG_WARN("invalid ipv6 prefix length {}", prefix_len);
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

void ip_matcher::optimize()
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

void ip_matcher::optimize_v4()
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

void ip_matcher::optimize_v6()
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

}    // namespace mux
