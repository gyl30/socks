#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#include <array>
#include <memory>
#include <vector>
#include <string>
#include <asio.hpp>
#include <algorithm>

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

    void optimize() const;

   private:
    struct trie_node;
    std::unique_ptr<trie_node> root_v4_;
    std::unique_ptr<trie_node> root_v6_;

    static bool match_v4(const asio::ip::address_v4& addr, const std::unique_ptr<trie_node>& root);
    static bool match_v6(const asio::ip::address_v6& addr, const std::unique_ptr<trie_node>& root);
    static void add_rule_v4(int prefix_len, const asio::ip::address_v4& addr, std::unique_ptr<trie_node>& root);
    static void add_rule_v6(int prefix_len, const asio::ip::address_v6& addr, std::unique_ptr<trie_node>& root);

    static void optimize_node(const std::unique_ptr<trie_node>& node);
};

}    // namespace mux

#endif
