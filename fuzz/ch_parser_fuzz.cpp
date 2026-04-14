#include <array>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include "tls/core.h"
#include "tls/ch_parser.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/fingerprint_patch.h"
#include "reality/handshake/client_hello_builder.h"

namespace
{

constexpr std::array<const char*, 4> kHostnames = {"example.com", "www.example.com", "localhost", "a.example.net"};

std::vector<uint8_t> take_bytes(const uint8_t* data, std::size_t size, std::size_t offset, std::size_t len)
{
    std::vector<uint8_t> out(len, 0x00);
    if (data == nullptr || size == 0 || len == 0)
    {
        return out;
    }

    for (std::size_t i = 0; i < len; ++i)
    {
        out[i] = data[(offset + i) % size];
    }
    return out;
}

reality::fingerprint_type select_fingerprint_type(const uint8_t* data, std::size_t size)
{
    if (data == nullptr || size == 0)
    {
        return reality::fingerprint_type::kChrome120;
    }

    switch (data[0] & 0x03)
    {
        case 0:
            return reality::fingerprint_type::kChrome120;
        case 1:
            return reality::fingerprint_type::kFirefox120;
        case 2:
            return reality::fingerprint_type::kIOS14;
        default:
            return reality::fingerprint_type::kAndroid11OkHttp;
    }
}

std::string select_hostname(const uint8_t* data, std::size_t size, bool with_sni)
{
    if (!with_sni)
    {
        return {};
    }
    if (data == nullptr || size == 0)
    {
        return kHostnames[0];
    }

    const std::size_t idx = (size > 1 ? static_cast<std::size_t>(data[1]) : static_cast<std::size_t>(data[0])) % kHostnames.size();
    return kHostnames[idx];
}

std::vector<uint8_t> build_client_hello(const uint8_t* data, std::size_t size, bool with_sni)
{
    auto spec = reality::fingerprint_factory::get(select_fingerprint_type(data, size));
    const auto session_id_len = (data == nullptr || size == 0) ? std::size_t{0} : static_cast<std::size_t>(data[0] % 33);
    const auto session_id = take_bytes(data, size, 1, session_id_len);
    const auto random = take_bytes(data, size, 2, 32);
    const auto x25519_pubkey = take_bytes(data, size, 34, 32);
    std::vector<uint8_t> x25519_mlkem768_key_share;

    if (data != nullptr && size != 0 && (data[0] & 0x04) != 0)
    {
        x25519_mlkem768_key_share = take_bytes(data, size, 66, tls::kMlkem768PublicKeySize + 32);
        reality::fingerprint_append_key_share_group(spec, tls::consts::group::kX25519MLKEM768);
    }

    const auto hostname = select_hostname(data, size, with_sni);
    return reality::client_hello_builder::build(spec, session_id, random, x25519_pubkey, x25519_mlkem768_key_share, hostname);
}

}    // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    std::vector<uint8_t> raw;
    if (data != nullptr && size != 0)
    {
        raw.assign(data, data + size);
    }

    (void)tls::client_hello_parser::parse(raw);

    const auto hello_with_sni = build_client_hello(data, size, true);
    if (!hello_with_sni.empty())
    {
        (void)tls::client_hello_parser::parse(hello_with_sni);
    }

    const auto hello_without_sni = build_client_hello(data, size, false);
    if (!hello_without_sni.empty())
    {
        (void)tls::client_hello_parser::parse(hello_without_sni);
    }

    return 0;
}
