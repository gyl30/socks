#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <boost/system/error_code.hpp>

#include "tls/core.h"
#include "vision_tcp.h"

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

bool test_continue_padding_policy()
{
    bool first_continue = true;
    bool ok = require(relay::vision::next_continue_padding_mode(first_continue) == relay::vision::padding_mode::kLong,
                      "first continue segment should use long padding");
    ok = ok && require(relay::vision::next_continue_padding_mode(first_continue) == relay::vision::padding_mode::kShort,
                       "subsequent continue segments should use short padding");
    ok = ok && require(relay::vision::next_continue_padding_mode(first_continue) == relay::vision::padding_mode::kShort,
                       "continue padding should stay short after first segment");
    return ok;
}

bool test_padding_block_sizes()
{
    const std::vector<uint8_t> content{'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> encoded;
    boost::system::error_code ec;

    bool ok = require(relay::vision::encode_block(relay::vision::command::kContinue, content, relay::vision::padding_mode::kShort, encoded, ec) && !ec,
                      "short padding encode failed") &&
              require(encoded.size() <= relay::vision::kBlockHeaderSize + content.size() + 255U, "short padded block should stay bounded");

    ok = ok && require(relay::vision::encode_block(relay::vision::command::kContinue, content, relay::vision::padding_mode::kLong, encoded, ec) && !ec,
                       "long padding encode failed") &&
         require(encoded.size() >= relay::vision::kBlockHeaderSize + 512U, "long padded block should hide small payloads") &&
         require(encoded.size() <= relay::vision::kBlockHeaderSize + 639U, "long padded block should stay bounded");

    const std::vector<uint8_t> oversized(tls::kMaxTlsApplicationDataPayloadLen, 0x42);
    ok = ok && require(!relay::vision::encode_block(relay::vision::command::kContinue, oversized, relay::vision::padding_mode::kNone, encoded, ec),
                       "oversized content should fail");
    return ok;
}

}    // namespace

int main()
{
    return test_continue_padding_policy() && test_padding_block_sizes() ? 0 : 1;
}
