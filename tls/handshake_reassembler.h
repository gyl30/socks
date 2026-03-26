#ifndef TLS_HANDSHAKE_REASSEMBLER_H
#define TLS_HANDSHAKE_REASSEMBLER_H

#include <span>
#include <vector>

#include <boost/circular_buffer.hpp>
#include <boost/system/error_code.hpp>

namespace tls
{

class handshake_reassembler
{
   public:
    handshake_reassembler();
    void append(std::span<const std::uint8_t> data);
    bool next(std::vector<std::uint8_t>& out, boost::system::error_code& ec);

   private:
    boost::circular_buffer<std::uint8_t> buffer_;
    bool overflowed_ = false;
};

}    // namespace tls

#endif
