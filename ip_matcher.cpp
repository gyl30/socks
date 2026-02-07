#include <array>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <utility>
#include <asio.hpp>
#include <charconv>
#include <string_view>
#include <system_error>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>

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

bool ip_matcher::match_v4(const asio::ip::address_v4& addr, const std::unique_ptr<trie_node>& root)
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

bool ip_matcher::match_v6(const asio::ip::address_v6& addr, const std::unique_ptr<trie_node>& root)
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

void ip_matcher::add_rule_v4(const int prefix_len, const asio::ip::address_v4& addr, std::unique_ptr<trie_node>& root)
{
    if (prefix_len < 0 || prefix_len > 32)
    {
        return;
    }
    if (root == nullptr)
    {
        root = std::make_unique<ip_matcher::trie_node>();
    }
    ip_matcher::trie_node* curr = root.get();
    if (curr->is_match)
    {
        return;
    }

    const std::uint32_t val = addr.to_uint();
    for (int i = 0; i < prefix_len; ++i)
    {
        const bool bit = get_bit_v4(val, i);
        const std::size_t idx = to_index(bit);
        if (curr->children[idx] == nullptr)
        {
            curr->children[idx] = std::make_unique<ip_matcher::trie_node>();
        }
        curr = curr->children[idx].get();
        if (curr->is_match)
        {
            return;
        }
    }
    curr->is_match = true;
    curr->children[0].reset();
    curr->children[1].reset();
}

void ip_matcher::add_rule_v6(const int prefix_len, const asio::ip::address_v6& addr, std::unique_ptr<trie_node>& root)
{
    if (prefix_len < 0 || prefix_len > 128)
    {
        return;
    }
    if (root == nullptr)
    {
        root = std::make_unique<ip_matcher::trie_node>();
    }
    ip_matcher::trie_node* curr = root.get();
    if (curr->is_match)
    {
        return;
    }

    const auto bytes = addr.to_bytes();
    for (int i = 0; i < prefix_len; ++i)
    {
        const bool bit = get_bit_v6(bytes, i);
        const std::size_t idx = to_index(bit);
        if (curr->children[idx] == nullptr)
        {
            curr->children[idx] = std::make_unique<ip_matcher::trie_node>();
        }
        curr = curr->children[idx].get();
        if (curr->is_match)
        {
            return;
        }
    }
    curr->is_match = true;
    curr->children[0].reset();
    curr->children[1].reset();
}

ip_matcher::ip_matcher() = default;
ip_matcher::~ip_matcher() = default;

bool ip_matcher::load(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        LOG_WARN("failed to open direct ip file {}", filename);
        return false;
    }
    std::string line;
    while (std::getline(file, line))
    {
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

bool ip_matcher::match(const asio::ip::address& addr) const
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
}    // namespace

void ip_matcher::add_rule(const std::string& cidr)
{
    const std::string_view line_sv = cidr;
    const auto slash_pos = line_sv.find('/');
    if (slash_pos == std::string_view::npos)
    {
        return;
    }
    const auto ip_part = trim(line_sv.substr(0, slash_pos));
    const auto len_part = trim(line_sv.substr(slash_pos + 1));

    int prefix_len = 0;
    const auto [ptr, from_ec] = std::from_chars(len_part.data(), len_part.data() + len_part.size(), prefix_len);
    if (from_ec != std::errc{} || ptr != len_part.data() + len_part.size())
    {
        LOG_WARN("invalid prefix length {}", len_part);
        return;
    }
    std::error_code ec;
    const auto addr = asio::ip::make_address(ip_part, ec);
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

void ip_matcher::optimize() const
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
        if (curr == nullptr)
        {
            continue;
        }
        if (!visited)
        {
            stack.emplace_back(curr, true);
            stack.emplace_back(curr->children[1].get(), false);
            stack.emplace_back(curr->children[0].get(), false);
            continue;
        }

        if (curr->is_match)
        {
            curr->children[0].reset();
            curr->children[1].reset();
            continue;
        }

        if (curr->children[0] != nullptr && curr->children[0]->is_match && curr->children[1] != nullptr && curr->children[1]->is_match)
        {
            curr->is_match = true;
            curr->children[0].reset();
            curr->children[1].reset();
        }
    }
}

}    // namespace mux
