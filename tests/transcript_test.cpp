#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "transcript.h"

namespace reality
{

TEST(TranscriptTest, SetProtocolHash)
{
    transcript trans;
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
    trans.update(data1);

    auto hash1 = trans.finish();
    EXPECT_EQ(hash1.size(), 32);

    trans.set_protocol_hash(EVP_sha384());
    std::vector<uint8_t> data2 = {0x04, 0x05};
    trans.update(data2);

    auto hash2 = trans.finish();
    EXPECT_EQ(hash2.size(), 48);

    transcript trans_direct;
    trans_direct.set_protocol_hash(EVP_sha384());
    trans_direct.update(data1);
    trans_direct.update(data2);
    EXPECT_EQ(hash2, trans_direct.finish());
}

TEST(TranscriptTest, SameHashNoOp)
{
    transcript trans;
    const EVP_MD* old_md = EVP_sha256();
    trans.set_protocol_hash(old_md);
    trans.update({0xAA});
    EXPECT_EQ(trans.finish().size(), 32);
}

}    // namespace reality
