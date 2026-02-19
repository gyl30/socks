#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <algorithm>

#include <boost/system/error_code.hpp>

extern "C"
{
#include <openssl/ssl.h>
}

#include "../crypto_util.h"

std::string to_hex(const std::vector<std::uint8_t>& bytes)
{
    std::ostringstream oss;
    for (const std::uint8_t c : bytes)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

std::vector<std::uint8_t> from_hex(const std::string& hex)
{
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byte_string = hex.substr(i, 2);
        std::uint8_t byte = static_cast<std::uint8_t>(std::strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void test_ecdh_set(const std::string& label,
                   const std::vector<std::uint8_t>& priv1,
                   const std::vector<std::uint8_t>& pub1,
                   const std::vector<std::uint8_t>& priv2,
                   const std::vector<std::uint8_t>& pub2)
{
    std::cout << "--- " << label << " ---" << std::endl;
    auto shared1 = reality::crypto_util::x25519_derive(priv1, pub2);
    if (!shared1)
    {
        std::cout << "  [1] Derive Error: " << shared1.error().message() << std::endl;
    }

    auto shared2 = reality::crypto_util::x25519_derive(priv2, pub1);
    if (!shared2)
    {
        std::cout << "  [2] Derive Error: " << shared2.error().message() << std::endl;
    }

    const auto shared1_value = shared1.value_or(std::vector<std::uint8_t>{});
    const auto shared2_value = shared2.value_or(std::vector<std::uint8_t>{});
    std::cout << "  Shared1: " << to_hex(shared1_value) << std::endl;
    std::cout << "  Shared2: " << to_hex(shared2_value) << std::endl;

    if (shared1_value == shared2_value && !shared1_value.empty())
    {
        std::cout << "  RESULT: PASS" << std::endl;
    }
    else
    {
        std::cout << "  RESULT: FAIL" << std::endl;
    }
}

int main()
{
    std::uint8_t pub_a_raw[32], priv_a_raw[32];
    std::uint8_t pub_b_raw[32], priv_b_raw[32];
    if (!reality::crypto_util::generate_x25519_keypair(pub_a_raw, priv_a_raw) ||
        !reality::crypto_util::generate_x25519_keypair(pub_b_raw, priv_b_raw))
    {
        std::cerr << "Failed to generate keypairs" << std::endl;
        return 1;
    }

    std::vector<std::uint8_t> pub_a(pub_a_raw, pub_a_raw + 32);
    std::vector<std::uint8_t> priv_a(priv_a_raw, priv_a_raw + 32);
    std::vector<std::uint8_t> pub_b(pub_b_raw, pub_b_raw + 32);
    std::vector<std::uint8_t> priv_b(priv_b_raw, priv_b_raw + 32);

    test_ecdh_set("随机密钥", priv_a, pub_a, priv_b, pub_b);

    std::string s_priv_hex = "0044286aa923f9f05cc9e33f299c221e9cd446b963e6ebfbef9b24dd4edab169";
    std::string s_pub_hex = "7de33da743d60ec55838d7173351662eead6004b9fb164bd19d1f3e6e9da742e";
    auto s_priv = from_hex(s_priv_hex);
    auto s_pub = from_hex(s_pub_hex);

    test_ecdh_set("硬编码密钥对 vs 随机", s_priv, s_pub, priv_b, pub_b);

    return 0;
}
