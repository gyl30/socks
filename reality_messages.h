#ifndef REALITY_MESSAGES_H
#define REALITY_MESSAGES_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>
#include <openssl/evp.h>

#include "reality_core.h"
#include "reality_fingerprint.h"

namespace reality
{

struct server_fingerprint
{
    uint16_t cipher_suite = 0;
    std::string alpn;
};

class message_builder
{
   public:
    static void push_u8(std::vector<uint8_t>& buf, uint8_t val);

    static void push_u16(std::vector<uint8_t>& buf, uint16_t val);

    static void push_u24(std::vector<uint8_t>& buf, uint32_t val);

    static void push_u32(std::vector<uint8_t>& buf, uint32_t val);

    static void push_bytes(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data);

    static void push_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len);

    static void push_string(std::vector<uint8_t>& buf, const std::string& str);

    static void push_vector_u8(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data);

    static void push_vector_u16(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data);
};

class ClientHelloBuilder
{
   public:
    static std::vector<uint8_t> build(FingerprintSpec spec,
                                      const std::vector<uint8_t>& session_id,
                                      const std::vector<uint8_t>& random,
                                      const std::vector<uint8_t>& x25519_pubkey,
                                      const std::string& hostname);
};

std::vector<uint8_t> write_record_header(uint8_t record_type, uint16_t length);

std::vector<uint8_t> construct_server_hello(const std::vector<uint8_t>& server_random,
                                            const std::vector<uint8_t>& session_id,
                                            uint16_t cipher_suite,
                                            const std::vector<uint8_t>& server_public_key);

std::vector<uint8_t> construct_encrypted_extensions(const std::string& alpn);

std::vector<uint8_t> construct_certificate(const std::vector<uint8_t>& cert_der);

std::vector<uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<uint8_t>& handshake_hash);

std::vector<uint8_t> construct_finished(const std::vector<uint8_t>& verify_data);

struct certificate_verify_info
{
    uint16_t scheme = 0;
    std::vector<uint8_t> signature;
};

std::optional<certificate_verify_info> parse_certificate_verify(const std::vector<uint8_t>& msg);

[[nodiscard]] bool is_supported_certificate_verify_scheme(uint16_t scheme);

std::optional<uint16_t> extract_cipher_suite_from_server_hello(const std::vector<uint8_t>& server_hello);

std::vector<uint8_t> extract_server_public_key(const std::vector<uint8_t>& server_hello);

std::optional<std::string> extract_alpn_from_encrypted_extensions(const std::vector<uint8_t>& ee_msg);

}    // namespace reality

#endif
