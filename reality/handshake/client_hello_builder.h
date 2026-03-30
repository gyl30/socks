#ifndef REALITY_CLIENT_HELLO_BUILDER_H
#define REALITY_CLIENT_HELLO_BUILDER_H

#include <cstdint>
#include <string>
#include <vector>

#include "reality/handshake/fingerprint.h"

namespace reality
{

class client_hello_builder
{
   public:
    static std::vector<uint8_t> build(const fingerprint_template& spec,
                                      const std::vector<uint8_t>& session_id,
                                      const std::vector<uint8_t>& random,
                                      const std::vector<uint8_t>& x25519_pubkey,
                                      const std::vector<uint8_t>& x25519_mlkem768_key_share,
                                      const std::string& hostname);
};

}    // namespace reality

#endif
