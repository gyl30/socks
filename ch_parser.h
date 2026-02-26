#ifndef CH_PARSER_H
#define CH_PARSER_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace mux
{

struct client_hello_info
{
    std::vector<std::uint8_t> session_id;
    std::vector<std::uint8_t> random;
    std::vector<std::uint8_t> x25519_pub;
    std::string sni;
    bool malformed_sni = false;
    bool malformed_key_share = false;
    bool is_tls13 = false;
    bool has_x25519_share = false;
    std::uint16_t key_share_group = 0;
    std::uint32_t sid_offset = 0;
};

class ch_parser
{
   public:
    [[nodiscard]] static client_hello_info parse(const std::vector<std::uint8_t>& buf);

   private:
    class reader
    {
       public:
        explicit reader(const std::vector<std::uint8_t>& buf) : ptr_(buf.data()), end_(buf.data() + buf.size()), start_(buf.data()) {}
        reader(const std::uint8_t* p, const std::size_t len, const std::uint8_t* s) : ptr_(p), end_(p + len), start_(s) {}

        [[nodiscard]] bool valid() const { return ptr_ != nullptr; }
        [[nodiscard]] bool has(const std::size_t n) const { return valid() && (ptr_ + n <= end_); }
        [[nodiscard]] std::size_t remaining() const { return valid() ? static_cast<std::size_t>(end_ - ptr_) : 0; }
        [[nodiscard]] std::size_t offset() const { return valid() ? static_cast<std::size_t>(ptr_ - start_) : 0; }
        [[nodiscard]] std::uint8_t peek(const std::size_t off) const { return has(off + 1) ? ptr_[off] : static_cast<std::uint8_t>(0); }
        [[nodiscard]] const std::uint8_t* data() const { return ptr_; }

        bool skip(const std::size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            ptr_ += n;
            return true;
        }

        bool read_u8(std::uint8_t& out)
        {
            if (!has(1))
            {
                return false;
            }
            out = *ptr_++;
            return true;
        }

        bool read_u16(std::uint16_t& out)
        {
            if (!has(2))
            {
                return false;
            }
            out = static_cast<std::uint16_t>((ptr_[0] << 8) | ptr_[1]);
            ptr_ += 2;
            return true;
        }

        bool read_vector(std::vector<std::uint8_t>& out, const std::size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            out.assign(ptr_, ptr_ + n);
            ptr_ += n;
            return true;
        }

        reader slice(const std::size_t n)
        {
            if (!has(n))
            {
                return {nullptr, 0, nullptr};
            }
            reader s(ptr_, n, start_);
            ptr_ += n;
            return s;
        }

       private:
        const std::uint8_t* ptr_;
        const std::uint8_t* end_;
        const std::uint8_t* start_;
    };

    static bool read_tls_record_header(reader& r);
    static bool read_client_hello_prefix(reader& r, client_hello_info& info);
    static bool read_session_id(reader& r, client_hello_info& info);
    static bool skip_cipher_suites_and_compression(reader& r);
    static bool read_extension_header(reader& r, std::uint16_t& type, std::uint16_t& len);
    static bool read_sni_item_header(reader& r, std::uint8_t& type, std::uint16_t& len);
    static bool handle_sni_item(reader& r, std::uint8_t type, std::uint16_t len, client_hello_info& info);
    static bool read_key_share_item_header(reader& r, std::uint16_t& group, std::uint16_t& len);
    static void handle_key_share_item(reader& r, std::uint16_t group, std::uint16_t len, client_hello_info& info);
    static void finalize_key_share_info(client_hello_info& info);
    static bool parse_before_extensions(reader& r, client_hello_info& info);
    static void parse_extension_block(reader& r, client_hello_info& info);

    static void parse_extensions(reader& r, client_hello_info& info);
    static void parse_sni(reader& r, client_hello_info& info);
    static void parse_key_share(reader& r, client_hello_info& info);
};

}    // namespace mux

#endif
