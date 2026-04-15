#include <cstdio>
#include <cctype>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <utility>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <optional>
#include <algorithm>
#include <charconv>
#include <iterator>
#include <stdexcept>
#include <string_view>
#include <unordered_set>

#include <boost/asio/ip/address.hpp>

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>

#include "config.h"
#include "rule_file_utils.h"
#include "tls/crypto_util.h"

namespace relay
{

namespace
{

constexpr std::size_t kMaxConfigBytes = 1024UL * 1024UL;

[[nodiscard]] std::string read_file_to_string(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        return {};
    }

    std::string content;
    content.reserve(4096);
    char buffer[8192] = {0};
    while (file.good())
    {
        file.read(buffer, static_cast<std::streamsize>(sizeof(buffer)));
        const auto bytes = static_cast<std::size_t>(file.gcount());
        if (bytes == 0)
        {
            break;
        }
        content.append(buffer, bytes);
        if (content.size() > kMaxConfigBytes)
        {
            break;
        }
    }
    return content;
}

void print_config_error(const std::string& filename, const std::string& message)
{
    std::fprintf(stderr, "config file %s error %s\n", filename.c_str(), message.c_str());
}

bool fail_config(const std::string& filename, const std::string& message)
{
    print_config_error(filename, message);
    return false;
}

[[nodiscard]] std::string join_path(const std::string& prefix, const std::string& suffix)
{
    if (prefix.empty())
    {
        return suffix;
    }
    return prefix + "." + suffix;
}

[[nodiscard]] std::string join_index_path(const std::string& prefix, const std::size_t index)
{
    return prefix + "[" + std::to_string(index) + "]";
}

[[nodiscard]] const rapidjson::Value* find_member_object(const rapidjson::Value& value, const char* key)
{
    if (!value.IsObject())
    {
        return nullptr;
    }
    const auto member = value.FindMember(key);
    if (member == value.MemberEnd())
    {
        return nullptr;
    }
    return &member->value;
}

[[nodiscard]] bool parse_string_field(const rapidjson::Value& value,
                                      const char* key,
                                      const std::string& path,
                                      std::string& out,
                                      const std::string& filename,
                                      const bool required)
{
    const auto* field = find_member_object(value, key);
    if (field == nullptr)
    {
        if (!required)
        {
            return true;
        }
        return fail_config(filename, join_path(path, key) + " missing");
    }
    if (!field->IsString())
    {
        return fail_config(filename, join_path(path, key) + " type invalid");
    }
    out = field->GetString();
    if (required && out.empty())
    {
        return fail_config(filename, join_path(path, key) + " empty");
    }
    return true;
}

template <typename T>
[[nodiscard]] bool parse_unsigned_field(const rapidjson::Value& value,
                                        const char* key,
                                        const std::string& path,
                                        T& out,
                                        const std::string& filename,
                                        const bool required)
{
    const auto* field = find_member_object(value, key);
    if (field == nullptr)
    {
        if (!required)
        {
            return true;
        }
        return fail_config(filename, join_path(path, key) + " missing");
    }
    if constexpr (sizeof(T) <= sizeof(uint32_t))
    {
        if (!field->IsUint())
        {
            return fail_config(filename, join_path(path, key) + " type invalid");
        }
        out = static_cast<T>(field->GetUint());
    }
    else
    {
        if (!field->IsUint64())
        {
            return fail_config(filename, join_path(path, key) + " type invalid");
        }
        out = static_cast<T>(field->GetUint64());
    }
    return true;
}

[[nodiscard]] bool parse_bool_field(const rapidjson::Value& value,
                                    const char* key,
                                    const std::string& path,
                                    bool& out,
                                    const std::string& filename,
                                    const bool required)
{
    const auto* field = find_member_object(value, key);
    if (field == nullptr)
    {
        if (!required)
        {
            return true;
        }
        return fail_config(filename, join_path(path, key) + " missing");
    }
    if (!field->IsBool())
    {
        return fail_config(filename, join_path(path, key) + " type invalid");
    }
    out = field->GetBool();
    return true;
}

[[nodiscard]] bool is_ascii_domain_char(const char ch)
{
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '-' || ch == '.';
}

[[nodiscard]] bool normalize_ascii_domain(std::string& domain)
{
    if (domain.empty())
    {
        return false;
    }
    if (domain.back() == '.')
    {
        domain.pop_back();
    }
    if (domain.empty())
    {
        return false;
    }

    for (char& ch : domain)
    {
        if (static_cast<unsigned char>(ch) > 0x7F || !is_ascii_domain_char(ch))
        {
            return false;
        }
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    std::size_t label_start = 0;
    while (label_start < domain.size())
    {
        const auto label_end = domain.find('.', label_start);
        const auto length = (label_end == std::string::npos) ? (domain.size() - label_start) : (label_end - label_start);
        if (length == 0)
        {
            return false;
        }
        const auto first = domain[label_start];
        const auto last = domain[label_start + length - 1];
        if (first == '-' || last == '-')
        {
            return false;
        }
        if (label_end == std::string::npos)
        {
            break;
        }
        label_start = label_end + 1;
    }
    return true;
}

[[nodiscard]] bool parse_cidr(const std::string& value)
{
    const auto slash = value.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= value.size())
    {
        return false;
    }

    const std::string ip_part = value.substr(0, slash);
    const std::string prefix_part = value.substr(slash + 1);
    int prefix = 0;
    const auto [ptr, ec] = std::from_chars(prefix_part.data(), prefix_part.data() + prefix_part.size(), prefix);
    if (ec != std::errc{} || ptr != prefix_part.data() + prefix_part.size())
    {
        return false;
    }

    boost::system::error_code addr_ec;
    const auto address = boost::asio::ip::make_address(ip_part, addr_ec);
    if (addr_ec)
    {
        return false;
    }

    const int max_prefix = address.is_v4() ? 32 : 128;
    return prefix >= 0 && prefix <= max_prefix;
}

[[nodiscard]] bool validate_route_value(const std::string& type,
                                        std::string& value,
                                        const std::string& filename,
                                        const std::string& path)
{
    if (type == "inbound")
    {
        if (value.empty())
        {
            return fail_config(filename, path + " empty");
        }
        return true;
    }
    if (type == "ip")
    {
        if (!parse_cidr(value))
        {
            return fail_config(filename, path + " invalid_cidr");
        }
        return true;
    }
    if (type == "domain")
    {
        if (!normalize_ascii_domain(value))
        {
            return fail_config(filename, path + " invalid_domain");
        }
        return true;
    }
    return fail_config(filename, path + " invalid_type");
}

[[nodiscard]] bool load_rule_file_values(const std::string& type,
                                         const std::string& rule_file,
                                         const std::string& filename,
                                         const std::string& path,
                                         std::vector<std::string>& out)
{
    std::ifstream file(rule_file);
    if (!file.is_open())
    {
        return fail_config(filename, path + " open_failed");
    }

    std::string line;
    std::size_t line_number = 0;
    while (rule_file_util::read_rule_line(file, line))
    {
        ++line_number;
        if (line.empty())
        {
            continue;
        }
        if (!validate_route_value(type, line, filename, path + " line " + std::to_string(line_number)))
        {
            return false;
        }
        out.push_back(line);
    }
    return true;
}

[[nodiscard]] bool parse_log_config(const rapidjson::Value& value, const std::string& filename, config::log_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, "log type invalid");
    }
    if (!parse_string_field(value, "level", "log", out.level, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "file", "log", out.file, filename, true))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_timeout_config(const rapidjson::Value& value, const std::string& filename, config::timeout_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, "timeout type invalid");
    }
    if (!parse_unsigned_field(value, "read", "timeout", out.read, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "write", "timeout", out.write, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "connect", "timeout", out.connect, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "idle", "timeout", out.idle, filename, true))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_socks_settings(const rapidjson::Value& value,
                                        const std::string& filename,
                                        const std::string& path,
                                        config::socks_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, path + " type invalid");
    }
    out.enabled = true;
    if (!parse_string_field(value, "host", path, out.host, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "port", path, out.port, filename, true))
    {
        return false;
    }
    if (!parse_bool_field(value, "auth", path, out.auth, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "username", path, out.username, filename, false))
    {
        return false;
    }
    if (!parse_string_field(value, "password", path, out.password, filename, false))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_tproxy_settings(const rapidjson::Value& value,
                                         const std::string& filename,
                                         const std::string& path,
                                         config::tproxy_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, path + " type invalid");
    }
    out.enabled = true;
    if (!parse_string_field(value, "listen_host", path, out.listen_host, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "tcp_port", path, out.tcp_port, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "udp_port", path, out.udp_port, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "mark", path, out.mark, filename, true))
    {
        return false;
    }
    if (out.tcp_port == 0 && out.udp_port == 0)
    {
        return fail_config(filename, path + " both_ports_zero");
    }
    return true;
}

[[nodiscard]] bool parse_tun_settings(const rapidjson::Value& value, const std::string& filename, const std::string& path, config::tun_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, path + " type invalid");
    }
    out.enabled = true;
    if (!parse_string_field(value, "name", path, out.name, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "mtu", path, out.mtu, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "ipv4", path, out.ipv4, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "ipv4_prefix", path, out.ipv4_prefix, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "ipv6", path, out.ipv6, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "ipv6_prefix", path, out.ipv6_prefix, filename, true))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_reality_inbound_settings(const rapidjson::Value& value,
                                                  const std::string& filename,
                                                  const std::string& path,
                                                  config::reality_inbound_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, path + " type invalid");
    }
    if (!parse_string_field(value, "host", path, out.host, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "port", path, out.port, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "sni", path, out.sni, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "private_key", path, out.private_key, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "public_key", path, out.public_key, filename, false))
    {
        return false;
    }
    if (!parse_string_field(value, "short_id", path, out.short_id, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "replay_cache_max_entries", path, out.replay_cache_max_entries, filename, true))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_reality_outbound_settings(const rapidjson::Value& value,
                                                   const std::string& filename,
                                                   const std::string& path,
                                                   config::reality_outbound_t& out)
{
    if (!value.IsObject())
    {
        return fail_config(filename, path + " type invalid");
    }
    if (!parse_string_field(value, "host", path, out.host, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "port", path, out.port, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "sni", path, out.sni, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "fingerprint", path, out.fingerprint, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "public_key", path, out.public_key, filename, true))
    {
        return false;
    }
    if (!parse_string_field(value, "short_id", path, out.short_id, filename, true))
    {
        return false;
    }
    if (!parse_unsigned_field(value, "max_handshake_records", path, out.max_handshake_records, filename, true))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_inbounds(const rapidjson::Value& value, const std::string& filename, std::vector<config::inbound_entry_t>& out)
{
    if (!value.IsArray())
    {
        return fail_config(filename, "inbounds type invalid");
    }

    std::unordered_set<std::string> seen_tags;
    out.clear();
    out.reserve(value.Size());
    for (rapidjson::SizeType index = 0; index < value.Size(); ++index)
    {
        const auto& entry = value[index];
        const std::string entry_path = join_index_path("inbounds", index);
        if (!entry.IsObject())
        {
            return fail_config(filename, entry_path + " type invalid");
        }

        config::inbound_entry_t parsed;
        if (!parse_string_field(entry, "type", entry_path, parsed.type, filename, true))
        {
            return false;
        }
        if (!parse_string_field(entry, "tag", entry_path, parsed.tag, filename, true))
        {
            return false;
        }
        if (!seen_tags.insert(parsed.tag).second)
        {
            return fail_config(filename, entry_path + " duplicate_tag");
        }

        const auto* settings = find_member_object(entry, "settings");
        if (settings == nullptr)
        {
            return fail_config(filename, entry_path + ".settings missing");
        }
        if (parsed.type == "socks")
        {
            config::socks_t socks;
            if (!parse_socks_settings(*settings, filename, entry_path + ".settings", socks))
            {
                return false;
            }
            parsed.socks = std::move(socks);
        }
        else if (parsed.type == "tproxy")
        {
            config::tproxy_t tproxy;
            if (!parse_tproxy_settings(*settings, filename, entry_path + ".settings", tproxy))
            {
                return false;
            }
            parsed.tproxy = std::move(tproxy);
        }
        else if (parsed.type == "tun")
        {
            config::tun_t tun;
            if (!parse_tun_settings(*settings, filename, entry_path + ".settings", tun))
            {
                return false;
            }
            parsed.tun = std::move(tun);
        }
        else if (parsed.type == "reality")
        {
            config::reality_inbound_t reality;
            if (!parse_reality_inbound_settings(*settings, filename, entry_path + ".settings", reality))
            {
                return false;
            }
            parsed.reality = std::move(reality);
        }
        else
        {
            return fail_config(filename, entry_path + " unsupported_type");
        }

        out.push_back(std::move(parsed));
    }
    return true;
}

[[nodiscard]] bool parse_outbounds(const rapidjson::Value& value, const std::string& filename, std::vector<config::outbound_entry_t>& out)
{
    if (!value.IsArray())
    {
        return fail_config(filename, "outbounds type invalid");
    }

    std::unordered_set<std::string> seen_tags;
    std::size_t reality_count = 0;
    out.clear();
    out.reserve(value.Size());
    for (rapidjson::SizeType index = 0; index < value.Size(); ++index)
    {
        const auto& entry = value[index];
        const std::string entry_path = join_index_path("outbounds", index);
        if (!entry.IsObject())
        {
            return fail_config(filename, entry_path + " type invalid");
        }

        config::outbound_entry_t parsed;
        if (!parse_string_field(entry, "type", entry_path, parsed.type, filename, true))
        {
            return false;
        }
        if (!parse_string_field(entry, "tag", entry_path, parsed.tag, filename, true))
        {
            return false;
        }
        if (!seen_tags.insert(parsed.tag).second)
        {
            return fail_config(filename, entry_path + " duplicate_tag");
        }

        if (parsed.type == "direct" || parsed.type == "block")
        {
            out.push_back(std::move(parsed));
            continue;
        }

        if (parsed.type == "reality")
        {
            const auto* settings = find_member_object(entry, "settings");
            if (settings == nullptr)
            {
                return fail_config(filename, entry_path + ".settings missing");
            }
            config::reality_outbound_t reality;
            if (!parse_reality_outbound_settings(*settings, filename, entry_path + ".settings", reality))
            {
                return false;
            }
            parsed.reality = std::move(reality);
            ++reality_count;
            out.push_back(std::move(parsed));
            continue;
        }

        return fail_config(filename, entry_path + " unsupported_type");
    }

    if (reality_count > 1)
    {
        return fail_config(filename, "outbounds reality_multiple_not_supported_yet");
    }
    return true;
}

[[nodiscard]] bool parse_values_array(const rapidjson::Value& value,
                                      const std::string& type,
                                      const std::string& filename,
                                      const std::string& path,
                                      std::vector<std::string>& out)
{
    if (!value.IsArray())
    {
        return fail_config(filename, path + " type invalid");
    }
    out.clear();
    out.reserve(value.Size());
    for (rapidjson::SizeType index = 0; index < value.Size(); ++index)
    {
        const auto& item = value[index];
        if (!item.IsString())
        {
            return fail_config(filename, join_index_path(path, index) + " type invalid");
        }
        std::string parsed = item.GetString();
        if (!validate_route_value(type, parsed, filename, join_index_path(path, index)))
        {
            return false;
        }
        out.push_back(std::move(parsed));
    }
    return true;
}

[[nodiscard]] bool parse_routing(const rapidjson::Value& value, const std::string& filename, config& cfg)
{
    if (!value.IsArray())
    {
        return fail_config(filename, "routing type invalid");
    }

    cfg.routing.clear();
    cfg.routing.reserve(value.Size());
    for (rapidjson::SizeType index = 0; index < value.Size(); ++index)
    {
        const auto& entry = value[index];
        const std::string entry_path = join_index_path("routing", index);
        if (!entry.IsObject())
        {
            return fail_config(filename, entry_path + " type invalid");
        }

        config::route_rule_t parsed;
        if (!parse_string_field(entry, "type", entry_path, parsed.type, filename, true))
        {
            return false;
        }
        if (!parse_string_field(entry, "out", entry_path, parsed.out, filename, true))
        {
            return false;
        }
        const bool has_values = find_member_object(entry, "values") != nullptr;
        const bool has_file = find_member_object(entry, "file") != nullptr;
        if (has_values == has_file)
        {
            return fail_config(filename, entry_path + " values_file_conflict");
        }
        if (parsed.type != "inbound" && parsed.type != "ip" && parsed.type != "domain")
        {
            return fail_config(filename, entry_path + " unsupported_type");
        }
        if (parsed.type == "inbound" && has_file)
        {
            return fail_config(filename, entry_path + " inbound_file_unsupported");
        }

        if (has_values)
        {
            const auto* values = find_member_object(entry, "values");
            if (values == nullptr)
            {
                return fail_config(filename, entry_path + ".values missing");
            }
            if (!parse_values_array(*values, parsed.type, filename, entry_path + ".values", parsed.values))
            {
                return false;
            }
            if (parsed.values.empty())
            {
                return fail_config(filename, entry_path + ".values empty");
            }
        }
        else
        {
            if (!parse_string_field(entry, "file", entry_path, parsed.file, filename, true))
            {
                return false;
            }
            if (!load_rule_file_values(parsed.type, parsed.file, filename, entry_path + ".file", parsed.file_values))
            {
                return false;
            }
            if (parsed.file_values.empty())
            {
                return fail_config(filename, entry_path + ".file empty");
            }
        }

        if (parsed.type == "inbound")
        {
            for (const auto& inbound_tag : parsed.values)
            {
                if (find_inbound_entry(cfg, inbound_tag) == nullptr)
                {
                    return fail_config(filename, entry_path + " inbound_not_found");
                }
            }
        }
        if (find_outbound_entry(cfg, parsed.out) == nullptr)
        {
            return fail_config(filename, entry_path + " outbound_not_found");
        }
        cfg.routing.push_back(std::move(parsed));
    }
    return true;
}

void write_string_array(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const std::vector<std::string>& values)
{
    writer.StartArray();
    for (const auto& value : values)
    {
        writer.String(value.c_str());
    }
    writer.EndArray();
}

void write_log(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::log_t& value)
{
    writer.Key("level");
    writer.String(value.level.c_str());
    writer.Key("file");
    writer.String(value.file.c_str());
}

void write_timeout(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::timeout_t& value)
{
    writer.Key("read");
    writer.Uint(value.read);
    writer.Key("write");
    writer.Uint(value.write);
    writer.Key("connect");
    writer.Uint(value.connect);
    writer.Key("idle");
    writer.Uint(value.idle);
}

void write_socks_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::socks_t& value)
{
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
    writer.Key("auth");
    writer.Bool(value.auth);
    if (value.auth)
    {
        writer.Key("username");
        writer.String(value.username.c_str());
        writer.Key("password");
        writer.String(value.password.c_str());
    }
}

void write_tproxy_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::tproxy_t& value)
{
    writer.Key("listen_host");
    writer.String(value.listen_host.c_str());
    writer.Key("tcp_port");
    writer.Uint(value.tcp_port);
    writer.Key("udp_port");
    writer.Uint(value.udp_port);
    writer.Key("mark");
    writer.Uint(value.mark);
}

void write_tun_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::tun_t& value)
{
    writer.Key("name");
    writer.String(value.name.c_str());
    writer.Key("mtu");
    writer.Uint(value.mtu);
    writer.Key("ipv4");
    writer.String(value.ipv4.c_str());
    writer.Key("ipv4_prefix");
    writer.Uint(value.ipv4_prefix);
    writer.Key("ipv6");
    writer.String(value.ipv6.c_str());
    writer.Key("ipv6_prefix");
    writer.Uint(value.ipv6_prefix);
}

void write_reality_inbound_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::reality_inbound_t& value)
{
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
    writer.Key("sni");
    writer.String(value.sni.c_str());
    writer.Key("private_key");
    writer.String(value.private_key.c_str());
    if (!value.public_key.empty())
    {
        writer.Key("public_key");
        writer.String(value.public_key.c_str());
    }
    writer.Key("short_id");
    writer.String(value.short_id.c_str());
    writer.Key("replay_cache_max_entries");
    writer.Uint(value.replay_cache_max_entries);
}

void write_reality_outbound_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::reality_outbound_t& value)
{
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
    writer.Key("sni");
    writer.String(value.sni.c_str());
    writer.Key("fingerprint");
    writer.String(value.fingerprint.c_str());
    writer.Key("public_key");
    writer.String(value.public_key.c_str());
    writer.Key("short_id");
    writer.String(value.short_id.c_str());
    writer.Key("max_handshake_records");
    writer.Uint(value.max_handshake_records);
}

void materialize_client_runtime(config& runtime_cfg)
{
    const auto* reality_outbound = find_first_outbound_entry(runtime_cfg, "reality");
    if (reality_outbound != nullptr && reality_outbound->reality.has_value())
    {
        const auto& outbound = *reality_outbound->reality;
        runtime_cfg.outbound.host = outbound.host;
        runtime_cfg.outbound.port = outbound.port;
        runtime_cfg.reality.sni = outbound.sni;
        runtime_cfg.reality.fingerprint = outbound.fingerprint;
        runtime_cfg.reality.public_key = outbound.public_key;
        runtime_cfg.reality.short_id = outbound.short_id;
        runtime_cfg.reality.max_handshake_records = outbound.max_handshake_records;
    }

    const auto* first_tproxy = find_first_inbound_entry(runtime_cfg, "tproxy");
    if (first_tproxy != nullptr && first_tproxy->tproxy.has_value())
    {
        runtime_cfg.tproxy = *first_tproxy->tproxy;
        runtime_cfg.tproxy.enabled = true;
    }

    const auto* first_tun = find_first_inbound_entry(runtime_cfg, "tun");
    if (first_tun != nullptr && first_tun->tun.has_value())
    {
        runtime_cfg.tun = *first_tun->tun;
        runtime_cfg.tun.enabled = true;
    }
}

}    // namespace

const config::inbound_entry_t* find_inbound_entry(const config& cfg, const std::string_view tag)
{
    for (const auto& inbound : cfg.inbounds)
    {
        if (inbound.tag == tag)
        {
            return &inbound;
        }
    }
    return nullptr;
}

const config::outbound_entry_t* find_outbound_entry(const config& cfg, const std::string_view tag)
{
    for (const auto& outbound : cfg.outbounds)
    {
        if (outbound.tag == tag)
        {
            return &outbound;
        }
    }
    return nullptr;
}

const config::inbound_entry_t* find_first_inbound_entry(const config& cfg, const std::string_view type)
{
    for (const auto& inbound : cfg.inbounds)
    {
        if (inbound.type == type)
        {
            return &inbound;
        }
    }
    return nullptr;
}

const config::outbound_entry_t* find_first_outbound_entry(const config& cfg, const std::string_view type)
{
    for (const auto& outbound : cfg.outbounds)
    {
        if (outbound.type == type)
        {
            return &outbound;
        }
    }
    return nullptr;
}

config make_runtime_config(const config& cfg, const config::inbound_entry_t& inbound)
{
    config runtime_cfg = cfg;
    runtime_cfg.active_inbound_tag = inbound.tag;
    runtime_cfg.inbound = config::inbound_t{};
    runtime_cfg.outbound = config::outbound_t{};
    runtime_cfg.socks = config::socks_t{};
    runtime_cfg.socks.enabled = false;
    runtime_cfg.tproxy = config::tproxy_t{};
    runtime_cfg.tproxy.enabled = false;
    runtime_cfg.tun = config::tun_t{};
    runtime_cfg.tun.enabled = false;
    runtime_cfg.reality = config::reality_t{};
    materialize_client_runtime(runtime_cfg);

    if (inbound.type == "socks" && inbound.socks.has_value())
    {
        runtime_cfg.socks = *inbound.socks;
        runtime_cfg.socks.enabled = true;
    }
    else if (inbound.type == "tproxy" && inbound.tproxy.has_value())
    {
        runtime_cfg.tproxy = *inbound.tproxy;
        runtime_cfg.tproxy.enabled = true;
    }
    else if (inbound.type == "tun" && inbound.tun.has_value())
    {
        runtime_cfg.tun = *inbound.tun;
        runtime_cfg.tun.enabled = true;
    }
    else if (inbound.type == "reality" && inbound.reality.has_value())
    {
        const auto& reality = *inbound.reality;
        runtime_cfg.inbound.host = reality.host;
        runtime_cfg.inbound.port = reality.port;
        runtime_cfg.reality.sni = reality.sni;
        runtime_cfg.reality.private_key = reality.private_key;
        runtime_cfg.reality.public_key = reality.public_key;
        runtime_cfg.reality.short_id = reality.short_id;
        runtime_cfg.reality.replay_cache_max_entries = reality.replay_cache_max_entries;
    }

    return runtime_cfg;
}

std::optional<config> parse_config(const std::string& filename)
{
    const auto file_content = read_file_to_string(filename);
    if (file_content.empty())
    {
        fail_config(filename, "read_failed");
        return std::nullopt;
    }
    if (file_content.size() > kMaxConfigBytes)
    {
        fail_config(filename, "too_large");
        return std::nullopt;
    }

    rapidjson::Document document;
    document.Parse(file_content.c_str());
    if (document.HasParseError())
    {
        fail_config(filename, std::string("json_parse ") + rapidjson::GetParseError_En(document.GetParseError()));
        return std::nullopt;
    }
    if (!document.IsObject())
    {
        fail_config(filename, "root type invalid");
        return std::nullopt;
    }

    config cfg;
    if (!parse_unsigned_field(document, "workers", "", cfg.workers, filename, true))
    {
        return std::nullopt;
    }

    const auto* log_value = find_member_object(document, "log");
    if (log_value == nullptr || !parse_log_config(*log_value, filename, cfg.log))
    {
        return std::nullopt;
    }

    const auto* timeout_value = find_member_object(document, "timeout");
    if (timeout_value == nullptr || !parse_timeout_config(*timeout_value, filename, cfg.timeout))
    {
        return std::nullopt;
    }

    const auto* inbounds_value = find_member_object(document, "inbounds");
    if (inbounds_value == nullptr || !parse_inbounds(*inbounds_value, filename, cfg.inbounds))
    {
        return std::nullopt;
    }

    const auto* outbounds_value = find_member_object(document, "outbounds");
    if (outbounds_value == nullptr || !parse_outbounds(*outbounds_value, filename, cfg.outbounds))
    {
        return std::nullopt;
    }

    const auto* routing_value = find_member_object(document, "routing");
    if (routing_value == nullptr || !parse_routing(*routing_value, filename, cfg))
    {
        return std::nullopt;
    }

    return cfg;
}

std::string dump_config(const config& cfg)
{
    rapidjson::StringBuffer buffer;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);

    writer.StartObject();
    writer.Key("workers");
    writer.Uint(cfg.workers);

    writer.Key("log");
    writer.StartObject();
    write_log(writer, cfg.log);
    writer.EndObject();

    writer.Key("timeout");
    writer.StartObject();
    write_timeout(writer, cfg.timeout);
    writer.EndObject();

    writer.Key("inbounds");
    writer.StartArray();
    for (const auto& inbound : cfg.inbounds)
    {
        writer.StartObject();
        writer.Key("type");
        writer.String(inbound.type.c_str());
        writer.Key("tag");
        writer.String(inbound.tag.c_str());
        writer.Key("settings");
        writer.StartObject();
        if (inbound.type == "socks" && inbound.socks.has_value())
        {
            write_socks_settings(writer, *inbound.socks);
        }
        else if (inbound.type == "tproxy" && inbound.tproxy.has_value())
        {
            write_tproxy_settings(writer, *inbound.tproxy);
        }
        else if (inbound.type == "tun" && inbound.tun.has_value())
        {
            write_tun_settings(writer, *inbound.tun);
        }
        else if (inbound.type == "reality" && inbound.reality.has_value())
        {
            write_reality_inbound_settings(writer, *inbound.reality);
        }
        writer.EndObject();
        writer.EndObject();
    }
    writer.EndArray();

    writer.Key("outbounds");
    writer.StartArray();
    for (const auto& outbound : cfg.outbounds)
    {
        writer.StartObject();
        writer.Key("type");
        writer.String(outbound.type.c_str());
        writer.Key("tag");
        writer.String(outbound.tag.c_str());
        if (outbound.type == "reality" && outbound.reality.has_value())
        {
            writer.Key("settings");
            writer.StartObject();
            write_reality_outbound_settings(writer, *outbound.reality);
            writer.EndObject();
        }
        writer.EndObject();
    }
    writer.EndArray();

    writer.Key("routing");
    writer.StartArray();
    for (const auto& rule : cfg.routing)
    {
        writer.StartObject();
        writer.Key("type");
        writer.String(rule.type.c_str());
        if (!rule.file.empty())
        {
            writer.Key("file");
            writer.String(rule.file.c_str());
        }
        else
        {
            writer.Key("values");
            write_string_array(writer, rule.values);
        }
        writer.Key("out");
        writer.String(rule.out.c_str());
        writer.EndObject();
    }
    writer.EndArray();

    writer.EndObject();
    return buffer.GetString();
}

std::string dump_default_config()
{
    config cfg;
    cfg.workers = 1;

    uint8_t public_key[32] = {0};
    uint8_t private_key[32] = {0};
    uint8_t short_id[8] = {0};
    if (tls::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        const std::vector<uint8_t> public_bytes(public_key, public_key + 32);
        const std::vector<uint8_t> private_bytes(private_key, private_key + 32);
        const std::string public_hex = tls::crypto_util::bytes_to_hex(public_bytes);
        const std::string private_hex = tls::crypto_util::bytes_to_hex(private_bytes);

        config::inbound_entry_t socks_inbound;
        socks_inbound.type = "socks";
        socks_inbound.tag = "socks-in";
        socks_inbound.socks = config::socks_t{};

        config::outbound_entry_t reality_outbound;
        reality_outbound.type = "reality";
        reality_outbound.tag = "reality-out";
        reality_outbound.reality = config::reality_outbound_t{};
        reality_outbound.reality->host = "1.2.3.4";
        reality_outbound.reality->port = 443;
        reality_outbound.reality->sni = "www.apple.com";
        reality_outbound.reality->fingerprint = "random";
        reality_outbound.reality->public_key = public_hex;

        if (RAND_bytes(short_id, static_cast<int>(sizeof(short_id))) != 1)
        {
            std::memcpy(short_id, private_key, sizeof(short_id));
        }
        const std::vector<uint8_t> short_id_bytes(short_id, short_id + sizeof(short_id));
        const std::string short_id_hex = tls::crypto_util::bytes_to_hex(short_id_bytes);
        reality_outbound.reality->short_id = short_id_hex;

        config::outbound_entry_t direct_outbound;
        direct_outbound.type = "direct";
        direct_outbound.tag = "direct";

        config::outbound_entry_t block_outbound;
        block_outbound.type = "block";
        block_outbound.tag = "block";

        config::route_rule_t rule;
        rule.type = "inbound";
        rule.values = {"socks-in"};
        rule.out = "reality-out";

        cfg.inbounds.push_back(std::move(socks_inbound));
        cfg.outbounds.push_back(std::move(reality_outbound));
        cfg.outbounds.push_back(std::move(direct_outbound));
        cfg.outbounds.push_back(std::move(block_outbound));
        cfg.routing.push_back(std::move(rule));

        OPENSSL_cleanse(private_key, sizeof(private_key));
        OPENSSL_cleanse(public_key, sizeof(public_key));
        OPENSSL_cleanse(short_id, sizeof(short_id));
        return dump_config(cfg);
    }

    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(short_id, sizeof(short_id));
    return dump_config(cfg);
}

}    // namespace relay
