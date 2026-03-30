#include <vector>
#include <limits>
#include <cstddef>

#include <boost/asio.hpp>

extern "C"
{
#include <brotli/decode.h>
}

#include "tls/core.h"
#include "tls/certificate_compression.h"

namespace tls
{

namespace
{

constexpr uint8_t kHandshakeTypeCertificate = 0x0b;
constexpr uint8_t kHandshakeTypeCompressedCertificate = 0x19;
constexpr std::size_t kCompressedCertificateFixedPrefixLen = 8;

bool read_u24_field(const std::vector<uint8_t>& data, std::size_t pos, uint32_t& value)
{
    if (pos + 3 > data.size())
    {
        return false;
    }
    value = (static_cast<uint32_t>(data[pos]) << 16) | (static_cast<uint32_t>(data[pos + 1]) << 8) | static_cast<uint32_t>(data[pos + 2]);
    return true;
}

bool read_u16_field(const std::vector<uint8_t>& data, std::size_t pos, uint16_t& value)
{
    if (pos + 2 > data.size())
    {
        return false;
    }
    value = static_cast<uint16_t>((static_cast<uint16_t>(data[pos]) << 8U) | static_cast<uint16_t>(data[pos + 1]));
    return true;
}

}    // namespace

bool decompress_certificate_message(const std::vector<uint8_t>& compressed_msg,
                                    std::size_t max_uncompressed_len,
                                    std::vector<uint8_t>& certificate_msg,
                                    boost::system::error_code& ec)
{
    ec.clear();
    certificate_msg.clear();

    if (compressed_msg.size() < 4 + kCompressedCertificateFixedPrefixLen || compressed_msg[0] != kHandshakeTypeCompressedCertificate)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }

    uint32_t msg_len = 0;
    if (!read_u24_field(compressed_msg, 1, msg_len))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    if (compressed_msg.size() != 4U + static_cast<std::size_t>(msg_len) || msg_len <= kCompressedCertificateFixedPrefixLen)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }

    uint16_t algorithm = 0;
    if (!read_u16_field(compressed_msg, 4, algorithm))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    if (algorithm != tls::consts::compress::kBrotli)
    {
        ec = boost::asio::error::no_protocol_option;
        return false;
    }

    uint32_t uncompressed_len = 0;
    if (!read_u24_field(compressed_msg, 6, uncompressed_len))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    if (uncompressed_len == 0 || static_cast<std::size_t>(uncompressed_len) > max_uncompressed_len)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return false;
    }
    if (static_cast<std::size_t>(uncompressed_len) > std::numeric_limits<std::size_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return false;
    }

    uint32_t compressed_body_len = 0;
    if (!read_u24_field(compressed_msg, 9, compressed_body_len))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    if (compressed_msg.size() != 12U + static_cast<std::size_t>(compressed_body_len))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }

    const auto* compressed_body = compressed_msg.data() + 12;
    std::size_t decoded_len = static_cast<std::size_t>(uncompressed_len);
    certificate_msg.resize(decoded_len + 4);
    const auto result =
        BrotliDecoderDecompress(static_cast<std::size_t>(compressed_body_len), compressed_body, &decoded_len, certificate_msg.data() + 4);
    if (result != BROTLI_DECODER_RESULT_SUCCESS || decoded_len != static_cast<std::size_t>(uncompressed_len))
    {
        certificate_msg.clear();
        ec = boost::asio::error::invalid_argument;
        return false;
    }

    certificate_msg[0] = kHandshakeTypeCertificate;
    certificate_msg[1] = static_cast<uint8_t>((uncompressed_len >> 16) & 0xffU);
    certificate_msg[2] = static_cast<uint8_t>((uncompressed_len >> 8) & 0xffU);
    certificate_msg[3] = static_cast<uint8_t>(uncompressed_len & 0xffU);
    return true;
}

}    // namespace tls
