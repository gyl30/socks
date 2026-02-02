#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <asio.hpp>
#include "log.h"

namespace mux
{

class ip_matcher
{
   public:
    ip_matcher();
    ~ip_matcher();

    bool load(const std::string& filename);

    [[nodiscard]] bool match(const asio::ip::address& addr) const;

    void add_rule(const std::string& cidr);

    void optimize();

   private:
    struct TrieNode;
    std::unique_ptr<TrieNode> root_v4_;
    std::unique_ptr<TrieNode> root_v6_;

    void optimize_node(std::unique_ptr<TrieNode>& node);
};

}    // namespace mux

#endif
