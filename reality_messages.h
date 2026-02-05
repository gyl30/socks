#ifndef REALITY_MESSAGES_H
#define REALITY_MESSAGES_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

extern "C"
{
#include <openssl/evp.h>
}

#include "reality_core.h"
#include "reality_fingerprint.h"

namespace reality
{

struct server_fingerprint
{
    std::uint16_t cipher_suite = 0;
    std::string alpn;
};

class message_builder
{
   public:
    static void push_u8(std::vector<std::uint8_t>& buf, std::uint8_t val);

    static void push_u16(std::vector<std::uint8_t>& buf, std::uint16_t val);

    static void push_u24(std::vector<std::uint8_t>& buf, std::uint32_t val);

    static void push_u32(std::vector<std::uint8_t>& buf, std::uint32_t val);

    static void push_bytes(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data);

    static void push_bytes(std::vector<std::uint8_t>& buf, const std::uint8_t* data, std::size_t len);

    static void push_string(std::vector<std::uint8_t>& buf, const std::string& str);

    static void push_vector_u8(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data);

    static void push_vector_u16(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data);
};

class ClientHelloBuilder
{
   public:
    static std::vector<std::uint8_t> build(const FingerprintSpec& spec,
                                           const std::vector<std::uint8_t>& session_id,
                                           const std::vector<std::uint8_t>& random,
                                           const std::vector<std::uint8_t>& x25519_pubkey,
                                           const std::string& hostname);
};

std::vector<std::uint8_t> write_record_header(std::uint8_t record_type, std::uint16_t length);

std::vector<std::uint8_t> construct_server_hello(const std::vector<std::uint8_t>& server_random,
                                                 const std::vector<std::uint8_t>& session_id,
                                                 std::uint16_t cipher_suite,
                                                 const std::vector<std::uint8_t>& server_public_key);

std::vector<std::uint8_t> construct_encrypted_extensions(const std::string& alpn);

std::vector<std::uint8_t> construct_certificate(const std::vector<std::uint8_t>& cert_der);

std::vector<std::uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<std::uint8_t>& handshake_hash);

std::vector<std::uint8_t> construct_finished(const std::vector<std::uint8_t>& verify_data);

struct certificate_verify_info
{
    std::uint16_t scheme = 0;
    std::vector<std::uint8_t> signature;
};

std::optional<certificate_verify_info> parse_certificate_verify(const std::vector<std::uint8_t>& msg);

[[nodiscard]] bool is_supported_certificate_verify_scheme(std::uint16_t scheme);

std::optional<std::uint16_t> extract_cipher_suite_from_server_hello(const std::vector<std::uint8_t>& server_hello);

std::vector<std::uint8_t> extract_server_public_key(const std::vector<std::uint8_t>& server_hello);

std::optional<std::string> extract_alpn_from_encrypted_extensions(const std::vector<std::uint8_t>& ee_msg);

}    // namespace reality

#endif
