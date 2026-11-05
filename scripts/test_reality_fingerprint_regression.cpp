#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

#include "tls/core.h"
#include "reality/config_validation.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/fingerprint_internal.h"
#include "reality/handshake/client_hello_builder.h"

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

bool is_grease_value(const uint16_t value)
{
    return (value & 0x0F0FU) == 0x0A0AU && ((value >> 8U) == (value & 0xFFU));
}

uint16_t load_u16(const std::vector<uint8_t>& data, const std::size_t pos)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1]);
}

bool extract_grease_ech_enc_key(const std::vector<uint8_t>& hello, std::vector<uint8_t>& enc_key)
{
    if (hello.size() < 4 + 2 + 32 + 1)
    {
        return false;
    }

    std::size_t pos = 4 + 2 + 32;
    const auto session_id_len = static_cast<std::size_t>(hello[pos++]);
    if (pos + session_id_len + 2 > hello.size())
    {
        return false;
    }
    pos += session_id_len;

    const auto cipher_len = static_cast<std::size_t>(load_u16(hello, pos));
    pos += 2;
    if (pos + cipher_len + 1 > hello.size())
    {
        return false;
    }
    pos += cipher_len;

    const auto compression_len = static_cast<std::size_t>(hello[pos++]);
    if (pos + compression_len + 2 > hello.size())
    {
        return false;
    }
    pos += compression_len;

    const auto exts_len = static_cast<std::size_t>(load_u16(hello, pos));
    pos += 2;
    if (pos + exts_len > hello.size())
    {
        return false;
    }
    const auto exts_end = pos + exts_len;
    while (pos + 4 <= exts_end)
    {
        const auto ext_type = load_u16(hello, pos);
        pos += 2;
        const auto ext_len = static_cast<std::size_t>(load_u16(hello, pos));
        pos += 2;
        if (pos + ext_len > exts_end)
        {
            return false;
        }
        if (ext_type != tls::consts::ext::kGreaseEch)
        {
            pos += ext_len;
            continue;
        }

        if (ext_len < 1 + 4 + 1 + 2)
        {
            return false;
        }
        std::size_t body_pos = pos + 1 + 4 + 1;
        const auto enc_key_len = static_cast<std::size_t>(load_u16(hello, body_pos));
        body_pos += 2;
        if (body_pos + enc_key_len > pos + ext_len)
        {
            return false;
        }
        enc_key.assign(hello.begin() + static_cast<std::ptrdiff_t>(body_pos), hello.begin() + static_cast<std::ptrdiff_t>(body_pos + enc_key_len));
        return true;
    }
    return false;
}

bool client_hello_has_extension(const std::vector<uint8_t>& hello, const uint16_t wanted_type)
{
    if (hello.size() < 4 + 2 + 32 + 1)
    {
        return false;
    }

    std::size_t pos = 4 + 2 + 32;
    const auto session_id_len = static_cast<std::size_t>(hello[pos++]);
    if (pos + session_id_len + 2 > hello.size())
    {
        return false;
    }
    pos += session_id_len;

    const auto cipher_len = static_cast<std::size_t>(load_u16(hello, pos));
    pos += 2;
    if (pos + cipher_len + 1 > hello.size())
    {
        return false;
    }
    pos += cipher_len;

    const auto compression_len = static_cast<std::size_t>(hello[pos++]);
    if (pos + compression_len + 2 > hello.size())
    {
        return false;
    }
    pos += compression_len;

    const auto exts_len = static_cast<std::size_t>(load_u16(hello, pos));
    pos += 2;
    if (pos + exts_len > hello.size())
    {
        return false;
    }
    const auto exts_end = pos + exts_len;
    while (pos + 4 <= exts_end)
    {
        const auto ext_type = load_u16(hello, pos);
        pos += 2;
        const auto ext_len = static_cast<std::size_t>(load_u16(hello, pos));
        pos += 2;
        if (pos + ext_len > exts_end)
        {
            return false;
        }
        if (ext_type == wanted_type)
        {
            return true;
        }
        pos += ext_len;
    }
    return false;
}

bool has_extension_type(const reality::fingerprint_template& spec, const reality::extension_type type)
{
    const auto& extensions = reality::fingerprint_extensions(spec);
    return std::ranges::any_of(extensions,
                               [type](const std::shared_ptr<reality::extension_blueprint>& ext)
                               {
                                   return ext != nullptr && ext->type() == type;
                               });
}

}    // namespace

int main()
{
    reality::fingerprint_template chrome_spec;
    reality::fingerprint_template chrome_mlkem_spec;
    reality::fingerprint_template invalid_spec;

    const bool support_ok =
        require(reality::is_supported_fingerprint_name("random"), "random should be supported") &&
        require(reality::is_supported_fingerprint_name("chrome"), "chrome should be supported") &&
        require(reality::is_supported_fingerprint_name("chrome-mlkem768"), "chrome-mlkem768 should normalize to a supported name") &&
        require(!reality::is_supported_fingerprint_name("chrome_120"), "legacy chrome_120 should stay unsupported");

    const bool build_ok =
        require(reality::build_named_fingerprint_template("chrome", chrome_spec), "build chrome fingerprint failed") &&
        require(reality::build_named_fingerprint_template("chrome_mlkem768", chrome_mlkem_spec), "build chrome_mlkem768 fingerprint failed") &&
        require(!reality::build_named_fingerprint_template("not-real", invalid_spec), "unknown fingerprint should fail");

    const bool chrome_shape_ok =
        require(reality::fingerprint_has_key_share_group(chrome_spec, tls::consts::group::kX25519), "chrome should advertise x25519") &&
        require(!reality::fingerprint_has_key_share_group(chrome_spec, tls::consts::group::kX25519MLKEM768),
                "chrome should not advertise x25519_mlkem768");

    const bool chrome_mlkem_shape_ok =
        require(reality::fingerprint_has_key_share_group(chrome_mlkem_spec, tls::consts::group::kX25519), "chrome_mlkem768 should keep x25519") &&
        require(reality::fingerprint_has_key_share_group(chrome_mlkem_spec, tls::consts::group::kX25519MLKEM768),
                "chrome_mlkem768 should advertise x25519_mlkem768") &&
        require(has_extension_type(chrome_spec, reality::extension_type::kPadding), "chrome should keep boring padding") &&
        require(!has_extension_type(chrome_mlkem_spec, reality::extension_type::kPadding), "chrome_mlkem768 should not send a padding extension");

    const reality::grease_context grease;
    const auto cipher_grease = grease.get_grease(0);
    const auto group_grease = grease.get_grease(1);
    const auto ext_grease1 = grease.get_extension_grease(0);
    const auto ext_grease2 = grease.get_extension_grease(1);
    const auto version_grease = grease.get_grease(4);
    const bool grease_shape_ok =
        require(is_grease_value(cipher_grease), "cipher grease should use a valid grease value") &&
        require(is_grease_value(group_grease), "group grease should use a valid grease value") &&
        require(is_grease_value(ext_grease1), "first extension grease should use a valid grease value") &&
        require(is_grease_value(ext_grease2), "second extension grease should use a valid grease value") &&
        require(is_grease_value(version_grease), "version grease should use a valid grease value") &&
        require(ext_grease1 != ext_grease2, "grease extension values should differ");

    reality::fingerprint_template padding_spec;
    reality::fingerprint_template_storage::set_client_version(padding_spec, tls::consts::kVer12);
    reality::fingerprint_template_storage::mutable_cipher_suites(padding_spec) = {tls::consts::cipher::kTlsAes128GcmSha256};
    auto& padding_exts = reality::fingerprint_template_storage::mutable_extensions(padding_spec);
    padding_exts.push_back(std::make_shared<reality::sni_blueprint>());
    padding_exts.push_back(std::make_shared<reality::grease_ech_blueprint>());
    padding_exts.push_back(std::make_shared<reality::padding_blueprint>());
    const std::vector<uint8_t> session_id(32, 0x11);
    const std::vector<uint8_t> random(32, 0x22);
    const auto padded_hello =
        reality::client_hello_builder::build(padding_spec, session_id, random, {}, {}, "example.com");

    reality::fingerprint_template small_padding_spec;
    reality::fingerprint_template_storage::set_client_version(small_padding_spec, tls::consts::kVer12);
    reality::fingerprint_template_storage::mutable_cipher_suites(small_padding_spec) = {tls::consts::cipher::kTlsAes128GcmSha256};
    reality::fingerprint_template_storage::mutable_extensions(small_padding_spec).push_back(std::make_shared<reality::padding_blueprint>());
    const auto unpadded_hello =
        reality::client_hello_builder::build(small_padding_spec, session_id, random, {}, {}, "");

    const bool padding_shape_ok =
        require(!padded_hello.empty(), "padding client hello build failed") &&
        require(padded_hello.size() == 512, "client hello padding should reach 512 bytes") &&
        require(!unpadded_hello.empty(), "small padding client hello build failed") &&
        require(!client_hello_has_extension(unpadded_hello, tls::consts::ext::kPadding), "padding extension should be omitted when boring padding is disabled");

    bool grease_ech_key_shape_ok = true;
    for (int i = 0; i < 16; ++i)
    {
        const auto hello = reality::client_hello_builder::build(padding_spec, session_id, random, {}, {}, "example.com");
        std::vector<uint8_t> enc_key;
        if (!require(extract_grease_ech_enc_key(hello, enc_key), "grease ech extension should contain an encapsulated key") ||
            !require(enc_key.size() == 32, "grease ech encapsulated key should be 32 bytes") ||
            !require((enc_key.back() & 0x80U) == 0, "grease ech encapsulated key should look like an x25519 public key"))
        {
            grease_ech_key_shape_ok = false;
            break;
        }
    }

    return support_ok && build_ok && chrome_shape_ok && chrome_mlkem_shape_ok && grease_shape_ok && padding_shape_ok && grease_ech_key_shape_ok ? 0 : 1;
}
