#ifndef CH_PARSER_H
#define CH_PARSER_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <span>

#include "reality_core.h"

namespace mux
{
struct client_hello_info
{
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> random;
    std::vector<uint8_t> x25519_pub;
    std::string sni;
    bool is_tls13 = false;
    uint32_t sid_offset = 0;
};

class ch_parser
{
   public:
    [[nodiscard]] static client_hello_info parse(const std::vector<uint8_t>& buf);

   private:
    class reader
    {
       public:
        explicit reader(const std::vector<uint8_t>& buf) : ptr_(buf.data()), end_(buf.data() + buf.size()), start_(buf.data()) {}
        reader(const uint8_t* p, const size_t len, const uint8_t* s) : ptr_(p), end_(p + len), start_(s) {}

        [[nodiscard]] bool valid() const { return ptr_ != nullptr; }
        [[nodiscard]] bool has(const size_t n) const { return valid() && (ptr_ + n <= end_); }
        [[nodiscard]] size_t remaining() const { return valid() ? static_cast<size_t>(end_ - ptr_) : 0; }
        [[nodiscard]] size_t offset() const { return valid() ? static_cast<size_t>(ptr_ - start_) : 0; }
        [[nodiscard]] uint8_t peek(const size_t off) const { return has(off + 1) ? ptr_[off] : static_cast<uint8_t>(0); }
        [[nodiscard]] const uint8_t* data() const { return ptr_; }

        bool skip(const size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            ptr_ += n;
            return true;
        }

        bool read_u8(uint8_t& out)
        {
            if (!has(1))
            {
                return false;
            }
            out = *ptr_++;
            return true;
        }

        bool read_u16(uint16_t& out)
        {
            if (!has(2))
            {
                return false;
            }
            out = static_cast<uint16_t>((ptr_[0] << 8) | ptr_[1]);
            ptr_ += 2;
            return true;
        }

        bool read_vector(std::vector<uint8_t>& out, const size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            out.assign(ptr_, ptr_ + n);
            ptr_ += n;
            return true;
        }

        reader slice(const size_t n)
        {
            if (!has(n))
            {
                return reader(nullptr, 0, nullptr);
            }
            reader s(ptr_, n, start_);
            ptr_ += n;
            return s;
        }

       private:
        const uint8_t* ptr_;
        const uint8_t* end_;
        const uint8_t* start_;
    };

    static void parse_extensions(reader& r, client_hello_info& info);
    static void parse_sni(reader& r, client_hello_info& info);
    static void parse_key_share(reader& r, client_hello_info& info);
};

}    // namespace mux
#endif