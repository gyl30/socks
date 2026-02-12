#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#include <array>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <utility>

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
    struct trie_node;
    std::unique_ptr<trie_node> root_v4_;
    std::unique_ptr<trie_node> root_v6_;

    static bool match_v4(const asio::ip::address_v4& addr, const std::unique_ptr<trie_node>& root);
    static bool match_v6(const asio::ip::address_v6& addr, const std::unique_ptr<trie_node>& root);
    static void add_rule_v4(int prefix_len, const asio::ip::address_v4& addr, std::unique_ptr<trie_node>& root);
    static void add_rule_v6(int prefix_len, const asio::ip::address_v6& addr, std::unique_ptr<trie_node>& root);

    static bool is_valid_prefix_length(int prefix_len, int max_prefix_len);
    static trie_node* ensure_root(std::unique_ptr<trie_node>& root);
    static trie_node* advance_or_create_child(trie_node* node, bool bit);
    static void prune_children(trie_node* node);
    static void mark_node_match(trie_node* node);
    static bool can_merge_match_children(const trie_node* node);
    static void process_optimize_stack_entry(trie_node* curr, bool visited, std::vector<std::pair<trie_node*, bool>>& stack);

    static void optimize_node(const std::unique_ptr<trie_node>& node);
};

}    // namespace mux

#endif
