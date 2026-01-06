#ifndef TLS_PARSER_H
#define TLS_PARSER_H

#include <vector>
#include <cstdint>
#include <string>
#include <optional>

namespace reality
{

struct ClientHelloInfo
{
    std::string sni;
    std::vector<uint8_t> session_id;
    bool is_tls_handshake = false;
};

class TlsParser
{
   public:
    static std::optional<ClientHelloInfo> parse_client_hello(const std::vector<uint8_t>& data)
    {
        if (data.size() < 5)
            return std::nullopt;

        if (data[0] != 0x16)
            return std::nullopt;

        size_t pos = 5;
        if (pos >= data.size())
            return std::nullopt;

        if (data[pos] != 0x01)
            return std::nullopt;

        ClientHelloInfo info;
        info.is_tls_handshake = true;
        pos += 4;

        pos += 34;

        if (pos >= data.size())
            return std::nullopt;

        uint8_t session_id_len = data[pos++];
        if (pos + session_id_len > data.size())
            return std::nullopt;

        if (session_id_len > 0)
        {
            info.session_id.assign(data.begin() + pos, data.begin() + pos + session_id_len);
        }
        pos += session_id_len;

        if (pos + 2 > data.size())
            return std::nullopt;
        uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        pos += 2 + cipher_suites_len;

        if (pos + 1 > data.size())
            return std::nullopt;
        uint8_t compression_len = data[pos++];
        pos += compression_len;

        if (pos + 2 > data.size())
            return std::nullopt;
        uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        pos += 2;

        size_t extensions_end = pos + extensions_len;
        if (extensions_end > data.size())
            return std::nullopt;

        while (pos + 4 <= extensions_end)
        {
            uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
            uint16_t ext_len = (static_cast<uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
            pos += 4;

            if (pos + ext_len > extensions_end)
                break;

            if (ext_type == 0x0000)
            {
                parse_sni(data, pos, ext_len, info);
            }

            pos += ext_len;
        }

        return info;
    }

   private:
    static void parse_sni(const std::vector<uint8_t>& data, size_t offset, size_t len, ClientHelloInfo& info)
    {
        if (len < 2)
            return;
        size_t pos = offset + 2;

        while (pos + 3 <= offset + len)
        {
            uint8_t name_type = data[pos];
            uint16_t name_len = (static_cast<uint16_t>(data[pos + 1]) << 8) | data[pos + 2];
            pos += 3;

            if (pos + name_len > offset + len)
                break;

            if (name_type == 0x00)
            {
                info.sni = std::string(reinterpret_cast<const char*>(&data[pos]), name_len);
                return;
            }
            pos += name_len;
        }
    }
};

}    // namespace reality

#endif
