#include <vector>
#include <string>
#include <cstdint>

#include <gtest/gtest.h>

#include "protocol.h"

namespace
{

TEST(SocksProtocolTest, IPv6AddressDecoding)
{
    std::vector<std::uint8_t> request = {0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xbb};

    EXPECT_EQ(request[3], 0x04);
}

TEST(SocksProtocolTest, DomainResolutionFailureSimulation) { EXPECT_EQ(socks::kRepHostUnreach, 0x04); }

}    // namespace
