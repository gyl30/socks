#ifndef REALITY_TYPES_H
#define REALITY_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

extern "C"
{
#include <openssl/types.h>
}

namespace reality
{

enum class client_auth_mode : uint8_t
{
    kRealityTunnel,
    kRealCertificateFallback,
};

enum class accept_mode : uint8_t
{
    kAuthenticated,
    kFallbackToTarget,
    kReject,
};

struct negotiated_params
{
    uint16_t cipher_suite = 0;
    uint16_t key_share_group = 0;
    std::string negotiated_alpn;
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
};

struct traffic_secrets
{
    std::vector<uint8_t> c_app_secret;
    std::vector<uint8_t> s_app_secret;
};

struct traffic_key_material
{
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
};

struct client_handshake_result
{
    traffic_secrets secrets;
    negotiated_params negotiated;
    client_auth_mode auth_mode = client_auth_mode::kRealityTunnel;
};

struct accept_decision_context
{
    std::vector<uint8_t> client_hello_record;
};

struct authenticated_session
{
    traffic_secrets secrets;
    negotiated_params negotiated;
};

struct server_accept_result
{
    accept_mode mode = accept_mode::kReject;
    authenticated_session authenticated;
    std::string decision_reason;
    accept_decision_context decision_context;
};

}    // namespace reality

#endif
