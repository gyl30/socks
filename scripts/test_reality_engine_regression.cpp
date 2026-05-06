#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>

#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include "reality/session/engine.h"
#include "reality/session/record_context.h"

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

bool append_ciphertext(relay::reality_engine& engine, const std::vector<uint8_t>& data)
{
    boost::system::error_code ec;
    auto buffer = engine.read_buffer(data.size(), ec);
    if (!require(!ec, "read_buffer failed: " + ec.message()))
    {
        return false;
    }
    if (!require(boost::asio::buffer_size(buffer) >= data.size(), "read_buffer returned too small buffer"))
    {
        return false;
    }

    auto* output = static_cast<uint8_t*>(buffer.data());
    std::copy(data.begin(), data.end(), output);
    engine.commit_read(data.size());
    return true;
}

}    // namespace

int main()
{
    relay::reality_engine engine(reality::reality_record_context{});
    const bool empty_ok = require(engine.take_buffered_ciphertext().empty(), "initial buffered ciphertext should be empty");

    const std::vector<uint8_t> first{0x01, 0x02, 0x03, 0x04};
    const bool first_ok = append_ciphertext(engine, first) &&
                          require(engine.take_buffered_ciphertext() == first, "take_buffered_ciphertext returned wrong bytes") &&
                          require(engine.take_buffered_ciphertext().empty(), "take_buffered_ciphertext should clear buffered bytes");

    const std::vector<uint8_t> second{0x10, 0x20, 0x30};
    const bool reset_ok = append_ciphertext(engine, second) &&
                          require(engine.take_buffered_ciphertext() == second, "engine did not accept new bytes after take");

    return empty_ok && first_ok && reset_ok ? 0 : 1;
}
