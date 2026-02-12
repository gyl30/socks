#include <array>
#include <cstdint>

#include <gtest/gtest.h>

#include "tls_record_validation.h"

TEST(TlsRecordValidationTest, ValidTls13CompatCcs)
{
    const std::array<std::uint8_t, 5> header = {0x14, 0x03, 0x03, 0x00, 0x01};
    EXPECT_TRUE(reality::is_valid_tls13_compat_ccs(header, 0x01));
}

TEST(TlsRecordValidationTest, InvalidCcsLengthRejected)
{
    const std::array<std::uint8_t, 5> header = {0x14, 0x03, 0x03, 0x00, 0x02};
    EXPECT_FALSE(reality::is_valid_tls13_compat_ccs(header, 0x01));
}

TEST(TlsRecordValidationTest, InvalidCcsBodyRejected)
{
    const std::array<std::uint8_t, 5> header = {0x14, 0x03, 0x03, 0x00, 0x01};
    EXPECT_FALSE(reality::is_valid_tls13_compat_ccs(header, 0x02));
}

TEST(TlsRecordValidationTest, NonCcsRecordRejected)
{
    const std::array<std::uint8_t, 5> header = {0x17, 0x03, 0x03, 0x00, 0x01};
    EXPECT_FALSE(reality::is_valid_tls13_compat_ccs(header, 0x01));
}
