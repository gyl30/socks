#include "ip_matcher.h"
#include <fstream>
#include <algorithm>
#include <charconv>
#include <bit>

namespace mux
{

struct ip_matcher::TrieNode
{
    std::array<std::unique_ptr<TrieNode>, 2> children;
    bool is_match = false;
};

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

static bool get_bit_v4(uint32_t val, int index) { return (val >> (31 - index)) & 1; }

static bool get_bit_v6(const std::array<uint8_t, 16>& bytes, int index)
{
    int byte_index = index / 8;
    int bit_index = 7 - (index % 8);
    return (bytes[byte_index] >> bit_index) & 1;
}

bool ip_matcher::match(const asio::ip::address& addr) const
{
    if (addr.is_v4())
    {
        if (!root_v4_)
        {
            return false;
        }
        TrieNode* curr = root_v4_.get();
        if (curr->is_match)
        {
            return true;
        }

        uint32_t val = addr.to_v4().to_uint();
        for (int i = 0; i < 32; ++i)
        {
            bool bit = get_bit_v4(val, i);
            curr = curr->children[bit].get();
            if (!curr)
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
    if (addr.is_v6())
    {
        if (!root_v6_)
        {
            return false;
        }
        TrieNode* curr = root_v6_.get();
        if (curr->is_match)
        {
            return true;
        }

        auto bytes = addr.to_v6().to_bytes();
        for (int i = 0; i < 128; ++i)
        {
            bool bit = get_bit_v6(bytes, i);
            curr = curr->children[bit].get();
            if (!curr)
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
    return false;
}

static std::string_view trim(std::string_view sv)
{
    auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos)
    {
        return {};
    }
    auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

void ip_matcher::add_rule(const std::string& cidr)
{
    std::string_view line_sv = cidr;
    auto slash_pos = line_sv.find('/');
    if (slash_pos == std::string_view::npos)
    {
        return;
    }
    auto ip_part = trim(line_sv.substr(0, slash_pos));
    auto len_part = trim(line_sv.substr(slash_pos + 1));

    int prefix_len = 0;
    auto [ptr, from_ec] = std::from_chars(len_part.data(), len_part.data() + len_part.size(), prefix_len);
    if (from_ec != std::errc() || ptr != len_part.data() + len_part.size())
    {
        LOG_WARN("invalid prefix length {}", len_part);
        return;
    }
    std::error_code ec;
    auto addr = asio::ip::make_address(std::string(ip_part), ec);
    if (ec)
    {
        LOG_ERROR("{} parse address failed {}", ip_part, ec.message());
        return;
    }

    if (addr.is_v4())
    {
        if (prefix_len < 0 || prefix_len > 32)
        {
            return;
        }
        if (!root_v4_)
        {
            root_v4_ = std::make_unique<TrieNode>();
        }
        TrieNode* curr = root_v4_.get();

        if (curr->is_match)
        {
            return;
        }

        uint32_t val = addr.to_v4().to_uint();
        for (int i = 0; i < prefix_len; ++i)
        {
            bool bit = get_bit_v4(val, i);
            if (!curr->children[bit])
            {
                curr->children[bit] = std::make_unique<TrieNode>();
            }
            curr = curr->children[bit].get();
            if (curr->is_match)
            {
                return;
            }
        }
        curr->is_match = true;

        curr->children[0].reset();
        curr->children[1].reset();
    }
    else if (addr.is_v6())
    {
        if (prefix_len < 0 || prefix_len > 128)
        {
            return;
        }
        if (!root_v6_)
        {
            root_v6_ = std::make_unique<TrieNode>();
        }
        TrieNode* curr = root_v6_.get();

        if (curr->is_match)
        {
            return;
        }

        auto bytes = addr.to_v6().to_bytes();
        for (int i = 0; i < prefix_len; ++i)
        {
            bool bit = get_bit_v6(bytes, i);
            if (!curr->children[bit])
            {
                curr->children[bit] = std::make_unique<TrieNode>();
            }
            curr = curr->children[bit].get();
            if (curr->is_match)
            {
                return;
            }
        }
        curr->is_match = true;
        curr->children[0].reset();
        curr->children[1].reset();
    }
}

void ip_matcher::optimize()
{
    if (root_v4_)
    {
        optimize_node(root_v4_);
    }
    if (root_v6_)
    {
        optimize_node(root_v6_);
    }
}

void ip_matcher::optimize_node(std::unique_ptr<TrieNode>& node)
{
    if (!node)
    {
        return;
    }

    optimize_node(node->children[0]);
    optimize_node(node->children[1]);

    if (node->is_match)
    {
        node->children[0].reset();
        node->children[1].reset();
        return;
    }

    if (node->children[0] && node->children[0]->is_match && node->children[1] && node->children[1]->is_match)
    {
        node->is_match = true;
        node->children[0].reset();
        node->children[1].reset();
    }
}

}    // namespace mux
