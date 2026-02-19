#include <array>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <charconv>
#include <string_view>
#include <system_error>

#include <boost/asio.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include "log.h"
#include "ip_matcher.h"

namespace mux
{

struct ip_matcher::trie_node
{
    std::array<std::unique_ptr<trie_node>, 2> children;
    bool is_match = false;
};

namespace
{
constexpr std::size_t to_index(bool bit) { return bit ? 1U : 0U; }

bool get_bit_v4(std::uint32_t val, int index) { return ((val >> (31 - index)) & 1U) != 0U; }

bool get_bit_v6(const std::array<std::uint8_t, 16>& bytes, int index)
{
    const int byte_index = index / 8;
    const int bit_index = 7 - (index % 8);
    return ((bytes[static_cast<std::size_t>(byte_index)] >> bit_index) & 1U) != 0U;
}
}    // namespace

bool ip_matcher::match_v4(const boost::asio::ip::address_v4& addr, const std::unique_ptr<trie_node>& root)
{
    if (root == nullptr)
    {
        return false;
    }
    ip_matcher::trie_node* curr = root.get();
    if (curr->is_match)
    {
        return true;
    }

    const std::uint32_t val = addr.to_uint();
    for (int i = 0; i < 32; ++i)
    {
        const bool bit = get_bit_v4(val, i);
        curr = curr->children[to_index(bit)].get();
        if (curr == nullptr)
        {
            return false;
        }
        if (curr->is_match)
        {
            return true;
        }
    }
    return false;
}

bool ip_matcher::match_v6(const boost::asio::ip::address_v6& addr, const std::unique_ptr<trie_node>& root)
{
    if (root == nullptr)
    {
        return false;
    }
    ip_matcher::trie_node* curr = root.get();
    if (curr->is_match)
    {
        return true;
    }

    const auto bytes = addr.to_bytes();
    for (int i = 0; i < 128; ++i)
    {
        const bool bit = get_bit_v6(bytes, i);
        curr = curr->children[to_index(bit)].get();
        if (curr == nullptr)
        {
            return false;
        }
        if (curr->is_match)
        {
            return true;
        }
    }
    return false;
}

bool ip_matcher::is_valid_prefix_length(const int prefix_len, const int max_prefix_len)
{
    return prefix_len >= 0 && prefix_len <= max_prefix_len;
}

ip_matcher::trie_node* ip_matcher::ensure_root(std::unique_ptr<trie_node>& root)
{
    if (root == nullptr)
    {
        root = std::make_unique<trie_node>();
    }
    return root.get();
}

ip_matcher::trie_node* ip_matcher::advance_or_create_child(trie_node* node, const bool bit)
{
    const std::size_t idx = to_index(bit);
    if (node->children[idx] == nullptr)
    {
        node->children[idx] = std::make_unique<trie_node>();
    }
    return node->children[idx].get();
}

void ip_matcher::prune_children(trie_node* node)
{
    node->children[0].reset();
    node->children[1].reset();
}

void ip_matcher::mark_node_match(trie_node* node)
{
    node->is_match = true;
    prune_children(node);
}

bool ip_matcher::can_merge_match_children(const trie_node* node)
{
    return node->children[0] != nullptr && node->children[0]->is_match && node->children[1] != nullptr && node->children[1]->is_match;
}

void ip_matcher::add_rule_v4(const int prefix_len, const boost::asio::ip::address_v4& addr, std::unique_ptr<trie_node>& root)
{
    if (!is_valid_prefix_length(prefix_len, 32))
    {
        return;
    }
    ip_matcher::trie_node* curr = ensure_root(root);
    if (curr->is_match)
    {
        return;
    }

    const std::uint32_t val = addr.to_uint();
    for (int i = 0; i < prefix_len; ++i)
    {
        curr = advance_or_create_child(curr, get_bit_v4(val, i));
        if (curr->is_match)
        {
            return;
        }
    }
    mark_node_match(curr);
}

void ip_matcher::add_rule_v6(const int prefix_len, const boost::asio::ip::address_v6& addr, std::unique_ptr<trie_node>& root)
{
    if (!is_valid_prefix_length(prefix_len, 128))
    {
        return;
    }
    ip_matcher::trie_node* curr = ensure_root(root);
    if (curr->is_match)
    {
        return;
    }

    const auto bytes = addr.to_bytes();
    for (int i = 0; i < prefix_len; ++i)
    {
        curr = advance_or_create_child(curr, get_bit_v6(bytes, i));
        if (curr->is_match)
        {
            return;
        }
    }
    mark_node_match(curr);
}

ip_matcher::ip_matcher() = default;
ip_matcher::~ip_matcher() = default;

bool ip_matcher::load(const std::string& filename)
{
    struct file_guard
    {
        FILE* file = nullptr;
        ~file_guard()
        {
            if (file != nullptr)
            {
                (void)std::fclose(file);
            }
        }
    };

    file_guard guard{std::fopen(filename.c_str(), "r")};
    if (guard.file == nullptr)
    {
        LOG_WARN("failed to open direct ip file {}", filename);
        return false;
    }

    char* raw_line = nullptr;
    std::size_t raw_line_capacity = 0;
    struct line_buffer_guard
    {
        char*& raw_line;
        ~line_buffer_guard() { std::free(raw_line); }
    } raw_line_guard{raw_line};

    while (true)
    {
        const ssize_t line_size = ::getline(&raw_line, &raw_line_capacity, guard.file);
        if (line_size < 0)
        {
            break;
        }

        std::string line(raw_line, static_cast<std::size_t>(line_size));
        if (line.empty() || line[0] == '#')
        {
            continue;
        }
        if (line.back() == '\r')
        {
            line.pop_back();
        }
        add_rule(line);
    }
    optimize();
    return true;
}

bool ip_matcher::match(const boost::asio::ip::address& addr) const
{
    if (addr.is_v4())
    {
        return match_v4(addr.to_v4(), root_v4_);
    }
    if (addr.is_v6())
    {
        return match_v6(addr.to_v6(), root_v6_);
    }
    return false;
}

namespace
{
std::string_view trim(const std::string_view sv)
{
    const auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos)
    {
        return {};
    }
    const auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

bool split_cidr_line(const std::string& cidr, std::string_view& ip_part, std::string_view& len_part)
{
    const std::string_view line_sv = cidr;
    const auto slash_pos = line_sv.find('/');
    if (slash_pos == std::string_view::npos)
    {
        return false;
    }
    ip_part = trim(line_sv.substr(0, slash_pos));
    len_part = trim(line_sv.substr(slash_pos + 1));
    return !ip_part.empty() && !len_part.empty();
}

bool parse_prefix_length(const std::string_view len_part, int& prefix_len)
{
    const auto [ptr, from_ec] = std::from_chars(len_part.data(), len_part.data() + len_part.size(), prefix_len);
    return from_ec == std::errc{} && ptr == len_part.data() + len_part.size();
}
}    // namespace

void ip_matcher::add_rule(const std::string& cidr)
{
    std::string_view ip_part;
    std::string_view len_part;
    if (!split_cidr_line(cidr, ip_part, len_part))
    {
        return;
    }

    int prefix_len = 0;
    if (!parse_prefix_length(len_part, prefix_len))
    {
        LOG_WARN("invalid prefix length {}", len_part);
        return;
    }
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(ip_part, ec);
    if (ec)
    {
        LOG_ERROR("{} parse address failed {}", ip_part, ec.message());
        return;
    }

    if (addr.is_v4())
    {
        add_rule_v4(prefix_len, addr.to_v4(), root_v4_);
    }
    else if (addr.is_v6())
    {
        add_rule_v6(prefix_len, addr.to_v6(), root_v6_);
    }
}

void ip_matcher::optimize()
{
    if (root_v4_ != nullptr)
    {
        optimize_node(root_v4_);
    }
    if (root_v6_ != nullptr)
    {
        optimize_node(root_v6_);
    }
}

void ip_matcher::process_optimize_stack_entry(trie_node* curr, const bool visited, std::vector<std::pair<trie_node*, bool>>& stack)
{
    if (curr == nullptr)
    {
        return;
    }
    if (!visited)
    {
        stack.emplace_back(curr, true);
        stack.emplace_back(curr->children[1].get(), false);
        stack.emplace_back(curr->children[0].get(), false);
        return;
    }
    if (curr->is_match)
    {
        prune_children(curr);
        return;
    }
    if (can_merge_match_children(curr))
    {
        mark_node_match(curr);
    }
}

void ip_matcher::optimize_node(const std::unique_ptr<trie_node>& node)
{
    if (node == nullptr)
    {
        return;
    }

    std::vector<std::pair<trie_node*, bool>> stack;
    stack.emplace_back(node.get(), false);

    while (!stack.empty())
    {
        const auto [curr, visited] = stack.back();
        stack.pop_back();
        process_optimize_stack_entry(curr, visited, stack);
    }
}

}    // namespace mux
