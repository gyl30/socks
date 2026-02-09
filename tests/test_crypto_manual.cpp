#include <vector>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <algorithm>

#include <openssl/ssl.h>

#include "../crypto_util.h"

std::string to_hex(const std::vector<uint8_t>& bytes)
{
    std::ostringstream oss;
    for (const uint8_t c : bytes)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

std::vector<uint8_t> from_hex(const std::string& hex)
{
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

void test_ecdh_set(const std::string& label,
                   const std::vector<uint8_t>& priv1,
                   const std::vector<uint8_t>& pub1,
                   const std::vector<uint8_t>& priv2,
                   const std::vector<uint8_t>& pub2)
{
    std::cout << "--- " << label << " ---" << std::endl;
    std::error_code ec;

    auto shared1 = reality::crypto_util::x25519_derive(priv1, pub2, ec);
    if (ec)
    {
        std::cout << "  [1] Derive Error: " << ec.message() << std::endl;
    }

    auto shared2 = reality::crypto_util::x25519_derive(priv2, pub1, ec);
    if (ec)
    {
        std::cout << "  [2] Derive Error: " << ec.message() << std::endl;
    }

    std::cout << "  Shared1: " << to_hex(shared1) << std::endl;
    std::cout << "  Shared2: " << to_hex(shared2) << std::endl;

    if (shared1 == shared2 && !shared1.empty())
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
    uint8_t pubA_raw[32], privA_raw[32];
    uint8_t pubB_raw[32], privB_raw[32];
    if (!reality::crypto_util::generate_x25519_keypair(pubA_raw, privA_raw) || !reality::crypto_util::generate_x25519_keypair(pubB_raw, privB_raw))
    {
        std::cerr << "Failed to generate keypairs" << std::endl;
        return 1;
    }

    std::vector<uint8_t> pubA(pubA_raw, pubA_raw + 32), privA(privA_raw, privA_raw + 32);
    std::vector<uint8_t> pubB(pubB_raw, pubB_raw + 32), privB(privB_raw, privB_raw + 32);

    test_ecdh_set("随机密钥", privA, pubA, privB, pubB);

    std::string s_priv_hex = "0044286aa923f9f05cc9e33f299c221e9cd446b963e6ebfbef9b24dd4edab169";
    std::string s_pub_hex = "7de33da743d60ec55838d7173351662eead6004b9fb164bd19d1f3e6e9da742e";
    auto s_priv = from_hex(s_priv_hex);
    auto s_pub = from_hex(s_pub_hex);

    test_ecdh_set("硬编码密钥对 vs 随机", s_priv, s_pub, privB, pubB);

    return 0;
}
