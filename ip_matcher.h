#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#include <vector>
#include <string>
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

class ip_matcher
{
   public:
    ip_matcher() = default;

    bool load(const std::string& filename);

    [[nodiscard]] bool match(const asio::ip::address& addr) const;

    void add_rule(const std::string& cidr);

    void optimize();

   private:
    void optimize_v4();

    void optimize_v6();

   private:
    std::vector<range_v4> rules_v4_;
    std::vector<range_v6> rules_v6_;
};

}    // namespace mux

#endif
