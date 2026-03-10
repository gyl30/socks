#ifndef CERTIFICATE_COMPRESSION_H
#define CERTIFICATE_COMPRESSION_H

#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/system/error_code.hpp>

namespace reality
{

[[nodiscard]] bool decompress_certificate_message(const std::vector<std::uint8_t>& compressed_msg,
                                                  std::size_t max_uncompressed_len,
                                                  std::vector<std::uint8_t>& certificate_msg,
                                                  boost::system::error_code& ec);

}    // namespace reality

#endif
