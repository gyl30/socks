#ifndef TLS_KEY_SCHEDULE_H
#define TLS_KEY_SCHEDULE_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstring>
#include <utility>

#include <boost/system/error_code.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/types.h>
}

#include "tls/core.h"
#include "tls/crypto_util.h"

namespace tls
{

namespace key_schedule
{
[[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_traffic_keys(const std::vector<uint8_t>& secret,
                                                                                        boost::system::error_code& ec,
                                                                                        std::size_t key_len = 16,
                                                                                        std::size_t iv_len = 12,
                                                                                        const EVP_MD* md = EVP_sha256());

[[nodiscard]] handshake_keys derive_handshake_keys(const std::vector<uint8_t>& shared_secret,
                                                   const std::vector<uint8_t>& server_hello_hash,
                                                   const EVP_MD* md,
                                                   boost::system::error_code& ec);

[[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_application_secrets(const std::vector<uint8_t>& master_secret,
                                                                                               const std::vector<uint8_t>& handshake_hash,
                                                                                               const EVP_MD* md,
                                                                                               boost::system::error_code& ec);

[[nodiscard]] std::vector<uint8_t> compute_finished_verify_data(const std::vector<uint8_t>& base_key,
                                                                const std::vector<uint8_t>& handshake_hash,
                                                                const EVP_MD* md,
                                                                boost::system::error_code& ec);

}    // namespace key_schedule

}    // namespace tls

#endif
