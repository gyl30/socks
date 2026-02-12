#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <list>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <unordered_map>

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
    explicit cert_manager(std::size_t capacity = 100);

    [[nodiscard]] std::optional<cert_entry> get_certificate(const std::string& sni);

    void set_certificate(const std::string& sni, std::vector<std::uint8_t> cert_msg, server_fingerprint fp, const std::string& trace_id = "");

   private:
    struct cache_node
    {
        std::string sni;
        cert_entry entry;
    };

    void touch(const std::list<cache_node>::iterator& it);
    void evict_if_needed();

    std::size_t capacity_ = 100;
    std::list<cache_node> lru_;
    std::unordered_map<std::string, std::list<cache_node>::iterator> index_;
};

}    // namespace reality

#endif
