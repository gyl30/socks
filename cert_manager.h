#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <map>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include "reality_messages.h"

namespace reality
{

struct cert_entry
{
    std::vector<std::uint8_t> cert_msg;
    server_fingerprint fingerprint;
};

class cert_manager
{
   public:
    cert_manager() = default;

    [[nodiscard]] std::optional<cert_entry> get_certificate(const std::string& sni);

    void set_certificate(const std::string& sni, std::vector<std::uint8_t> cert_msg, server_fingerprint fp, const std::string& trace_id = "");

   private:
    std::map<std::string, cert_entry> cache_;
};

}    // namespace reality

#endif
