#ifndef CH_PARSER_H
#define CH_PARSER_H

#include <vector>
#include <string>
#include <cstdint>
#include "reality_core.h"

namespace mux
{
struct client_hello_info_t
{
    std::vector<uint8_t> session_id, random, x25519_pub;
    std::string sni;
    bool is_tls13 = false;
    uint32_t sid_offset = 0;
};

class ch_parser
{
   public:
    [[nodiscard]] static client_hello_info_t parse(const std::vector<uint8_t>& buf);

   private:
    struct reader
    {
        const uint8_t* ptr;
        const uint8_t* end;
        const uint8_t* start;

        explicit reader(const std::vector<uint8_t>& buf) : ptr(buf.data()), end(buf.data() + buf.size()), start(buf.data()) {}
        reader(const uint8_t* p, size_t len, const uint8_t* s) : ptr(p), end(p + len), start(s) {}

        [[nodiscard]] bool valid() const { return ptr != nullptr; }
        [[nodiscard]] bool has(size_t n) const { return ptr + n <= end; }
        [[nodiscard]] size_t remaining() const { return end - ptr; }
        [[nodiscard]] size_t offset() const { return ptr - start; }
        [[nodiscard]] uint8_t peek(size_t off) const { return ptr[off]; }

        bool skip(size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            ptr += n;
            return true;
        }

        bool read_u8(uint8_t& out)
        {
            if (!has(1))
            {
                return false;
            }
            out = *ptr++;
            return true;
        }

        bool read_u16(uint16_t& out)
        {
            if (!has(2))
            {
                return false;
            }
            out = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
            ptr += 2;
            return true;
        }

        bool read_vector(std::vector<uint8_t>& out, size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            out.assign(ptr, ptr + n);
            ptr += n;
            return true;
        }

        reader slice(size_t n)
        {
            if (!has(n))
            {
                return {nullptr, 0, nullptr};
            }
            reader s(ptr, n, start);
            ptr += n;
            return s;
        }
    };

    static void parse_extensions(reader& r, client_hello_info_t& info);
    static void parse_sni(reader& r, client_hello_info_t& info);
    static void parse_key_share(reader& r, client_hello_info_t& info);
};

}    // namespace mux
#endif
