#include <cctype>
#include <cstddef>
#include <string_view>

#include "tls/server_name.h"
namespace tls
{

namespace
{

constexpr std::size_t kMaxSniHostLen = 255;
constexpr std::size_t kMaxSniLabelLen = 63;

struct sni_label_state
{
    std::size_t label_len = 0;
    bool label_has_content = false;
    bool label_ends_with_hyphen = false;
};

[[nodiscard]] bool is_invalid_sni_ascii(const unsigned char ch) { return ch >= 0x80 || ch <= 0x20 || ch == 0x7f; }

[[nodiscard]] bool is_sni_label_complete(const sni_label_state& state)
{
    return state.label_has_content && !state.label_ends_with_hyphen && state.label_len <= kMaxSniLabelLen;
}

void reset_sni_label_state(sni_label_state& state)
{
    state.label_len = 0;
    state.label_has_content = false;
    state.label_ends_with_hyphen = false;
}

void append_alnum_to_sni_label(sni_label_state& state)
{
    ++state.label_len;
    state.label_has_content = true;
    state.label_ends_with_hyphen = false;
}

[[nodiscard]] bool consume_sni_hostname_char(const unsigned char ch, sni_label_state& state)
{
    if (is_invalid_sni_ascii(ch))
    {
        return false;
    }
    if (ch == '.')
    {
        if (!is_sni_label_complete(state))
        {
            return false;
        }
        reset_sni_label_state(state);
        return true;
    }
    if (std::isalnum(ch) != 0)
    {
        append_alnum_to_sni_label(state);
        return true;
    }
    if (ch == '-')
    {
        if (!state.label_has_content)
        {
            return false;
        }
        ++state.label_len;
        state.label_ends_with_hyphen = true;
        return true;
    }
    return false;
}

}    // namespace

bool valid_sni_hostname(const std::string_view hostname)
{
    if (hostname.empty())
    {
        return false;
    }
    if (hostname.size() > kMaxSniHostLen)
    {
        return false;
    }

    sni_label_state state;
    for (const char ch_value : hostname)
    {
        const auto ch = static_cast<unsigned char>(ch_value);
        if (!consume_sni_hostname_char(ch, state))
        {
            return false;
        }
    }

    return is_sni_label_complete(state);
}

}    // namespace tls
