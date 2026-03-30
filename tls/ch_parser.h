#ifndef TLS_CH_PARSER_H
#define TLS_CH_PARSER_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace tls
{

struct client_hello_info
{
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> random;
    std::vector<uint8_t> x25519_pub;
    std::vector<uint8_t> x25519_mlkem768_share;
    std::vector<uint8_t> compression_methods;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> supported_groups;
    std::vector<uint16_t> supported_versions;
    std::vector<uint16_t> signature_algorithms;
    std::vector<std::string> alpn_protocols;
    std::vector<uint8_t> secure_renegotiation;
    std::string sni;
    bool malformed_sni = false;
    bool malformed_extensions = false;
    bool malformed_key_share = false;
    bool malformed_supported_groups = false;
    bool malformed_supported_versions = false;
    bool malformed_signature_algorithms = false;
    bool malformed_renegotiation_info = false;
    bool is_tls13 = false;
    bool has_x25519_share = false;
    bool has_x25519_mlkem768_share = false;
    bool has_renegotiation_info = false;
    uint16_t key_share_group = 0;
    uint32_t sid_offset = 0;
};

class client_hello_parser
{
   public:
    [[nodiscard]] static client_hello_info parse(const std::vector<uint8_t>& buf);

   private:
    class reader
    {
       public:
        explicit reader(const std::vector<uint8_t>& buf) : ptr_(buf.data()), end_(buf.data() + buf.size()), start_(buf.data()) {}
        reader(const uint8_t* p, const std::size_t len, const uint8_t* s) : ptr_(p), end_(p + len), start_(s) {}

        [[nodiscard]] bool valid() const { return ptr_ != nullptr; }
        [[nodiscard]] bool has(const std::size_t n) const { return valid() && std::cmp_less_equal(n, end_ - ptr_); }
        [[nodiscard]] std::size_t remaining() const { return valid() ? static_cast<std::size_t>(end_ - ptr_) : 0; }
        [[nodiscard]] std::size_t offset() const { return valid() ? static_cast<std::size_t>(ptr_ - start_) : 0; }
        [[nodiscard]] uint8_t peek(const std::size_t off) const { return has(off + 1) ? ptr_[off] : static_cast<uint8_t>(0); }
        [[nodiscard]] const uint8_t* data() const { return ptr_; }

        bool skip(const std::size_t n)
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

        bool read_vector(std::vector<uint8_t>& out, const std::size_t n)
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
        const uint8_t* ptr_;
        const uint8_t* end_;
        const uint8_t* start_;
    };

    static bool read_client_hello_prefix(reader& r, client_hello_info& info);
    static bool read_session_id(reader& r, client_hello_info& info);
    static bool parse_cipher_suites_and_compression(reader& r, client_hello_info& info);
    static bool read_extension_header(reader& r, uint16_t& type, uint16_t& len);
    static bool read_sni_item_header(reader& r, uint8_t& type, uint16_t& len);
    static bool handle_sni_item(reader& r, uint8_t type, uint16_t len, client_hello_info& info);
    static bool read_key_share_item_header(reader& r, uint16_t& group, uint16_t& len);
    static void handle_key_share_item(const reader& r, uint16_t group, uint16_t len, client_hello_info& info);
    static void finalize_key_share_info(client_hello_info& info);
    static void finalize_tls13_info(client_hello_info& info);
    static bool parse_before_extensions(reader& r, client_hello_info& info);
    static void parse_extension_block(reader& r, client_hello_info& info);

    static void parse_extensions(reader& r, client_hello_info& info);
    static void parse_sni(reader& r, client_hello_info& info);
    static void parse_alpn(reader& r, client_hello_info& info);
    static void parse_supported_groups(reader& r, client_hello_info& info);
    static void parse_supported_versions(reader& r, client_hello_info& info);
    static void parse_signature_algorithms(reader& r, client_hello_info& info);
    static void parse_key_share(reader& r, client_hello_info& info);
    static void parse_renegotiation_info(reader& r, client_hello_info& info);
};

}    // namespace tls

#endif
