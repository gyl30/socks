#include <span>
#include <vector>
#include <cstddef>

#include <boost/system/error_code.hpp>

#include "constants.h"
#include "tls/handshake_reassembler.h"

namespace tls
{

handshake_reassembler::handshake_reassembler() : buffer_(constants::tls_limits::kMaxHandshakeReassembleBuffer) {}

void handshake_reassembler::append(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return;
    }
    if (data.size() > buffer_.capacity() - buffer_.size())
    {
        buffer_.clear();
        overflowed_ = true;
        return;
    }
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

bool handshake_reassembler::next(std::vector<uint8_t>& out, boost::system::error_code& ec)
{
    ec.clear();
    if (overflowed_)
    {
        overflowed_ = false;
        ec = std::make_error_code(std::errc::message_size);
        return false;
    }
    if (buffer_.size() < 4)
    {
        return false;
    }

    const uint32_t msg_len = (static_cast<uint32_t>(buffer_[1]) << 16) | (static_cast<uint32_t>(buffer_[2]) << 8) | static_cast<uint32_t>(buffer_[3]);

    if (msg_len > constants::tls_limits::kMaxHandshakeMessageSize)
    {
        buffer_.clear();
        ec = std::make_error_code(std::errc::message_size);
        return false;
    }

    const uint32_t full_len = 4 + msg_len;
    if (buffer_.size() < full_len)
    {
        return false;
    }

    out.assign(buffer_.begin(), buffer_.begin() + full_len);
    buffer_.erase_begin(static_cast<std::size_t>(full_len));
    return true;
}

}    // namespace tls
