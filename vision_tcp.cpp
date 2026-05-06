#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <algorithm>

extern "C"
{
#include <openssl/rand.h>
}
#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>

#include "tls/core.h"
#include "constants.h"
#include "vision_tcp.h"

namespace relay::vision
{

namespace
{

constexpr uint16_t kTlsAes128Ccm8Sha256 = 0x1305;
constexpr std::size_t kLongPaddingThreshold = 900;

[[nodiscard]] std::size_t dir_index(const direction dir) { return static_cast<std::size_t>(dir); }

[[nodiscard]] bool valid_command(const command cmd)
{
    return cmd == command::kContinue || cmd == command::kEnd || cmd == command::kDirect;
}

[[nodiscard]] uint16_t read_u16(const std::span<const uint8_t> data, const std::size_t pos)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[pos]) << 8U) | data[pos + 1U]);
}

void append_u16(std::vector<uint8_t>& out, const std::size_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

[[nodiscard]] bool block_size_valid(const std::size_t content_len, const std::size_t padding_len)
{
    return content_len <= UINT16_MAX && padding_len <= UINT16_MAX &&
           content_len + padding_len + kBlockHeaderSize <= tls::kMaxTlsApplicationDataPayloadLen;
}

[[nodiscard]] std::size_t random_u16(boost::system::error_code& ec)
{
    uint16_t value = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), static_cast<int>(sizeof(value))) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
        return 0;
    }
    ec.clear();
    return value;
}

[[nodiscard]] std::size_t choose_padding_len(const padding_mode mode, const std::size_t content_len, boost::system::error_code& ec)
{
    ec.clear();
    if (mode == padding_mode::kNone)
    {
        return 0;
    }
    if (content_len + kBlockHeaderSize > tls::kMaxTlsApplicationDataPayloadLen)
    {
        ec = boost::asio::error::message_size;
        return 0;
    }

    const auto max_padding = tls::kMaxTlsApplicationDataPayloadLen - kBlockHeaderSize - content_len;
    const auto seed = random_u16(ec);
    if (ec)
    {
        return 0;
    }

    std::size_t wanted = seed % 256U;
    if (mode == padding_mode::kLong && content_len < kLongPaddingThreshold)
    {
        wanted = (kLongPaddingThreshold - content_len) + (seed % 500U);
    }
    return std::min(wanted, max_padding);
}

[[nodiscard]] bool fill_random(std::vector<uint8_t>& out, const std::size_t size, boost::system::error_code& ec)
{
    out.assign(size, 0);
    if (size == 0)
    {
        ec.clear();
        return true;
    }
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
        out.clear();
        return false;
    }
    ec.clear();
    return true;
}

[[nodiscard]] bool looks_like_tls_record_header(const std::span<const uint8_t> data)
{
    if (data.size() < tls::kTlsRecordHeaderSize)
    {
        return false;
    }
    const auto content_type = data[0];
    if (content_type != tls::kContentTypeChangeCipherSpec && content_type != tls::kContentTypeAlert &&
        content_type != tls::kContentTypeHandshake && content_type != tls::kContentTypeApplicationData)
    {
        return false;
    }
    if (data[1] != 0x03)
    {
        return false;
    }
    const auto record_len = read_u16(data, 3);
    return record_len != 0 && record_len <= constants::tls_limits::kMaxCiphertextRecordLen;
}

[[nodiscard]] bool is_application_record_header(const std::span<const uint8_t> data)
{
    if (data.size() < tls::kTlsRecordHeaderSize || data[0] != tls::kContentTypeApplicationData)
    {
        return false;
    }
    if (data[1] != 0x03 || data[2] != 0x03)
    {
        return false;
    }
    const auto record_len = read_u16(data, 3);
    if (record_len == 0 || record_len > constants::tls_limits::kMaxCiphertextRecordLen)
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool complete_record_at(const std::span<const uint8_t> data, const std::size_t pos, std::size_t& record_size)
{
    record_size = 0;
    if (data.size() - pos < tls::kTlsRecordHeaderSize)
    {
        return false;
    }
    const auto header = data.subspan(pos, tls::kTlsRecordHeaderSize);
    if (!looks_like_tls_record_header(header))
    {
        return false;
    }
    record_size = tls::kTlsRecordHeaderSize + static_cast<std::size_t>(read_u16(header, 3));
    return data.size() - pos >= record_size;
}

[[nodiscard]] std::optional<std::size_t> find_direct_offset(const std::span<const uint8_t> data, const bool tls13_confirmed)
{
    if (!tls13_confirmed)
    {
        return std::nullopt;
    }

    for (std::size_t pos = 0; pos < data.size();)
    {
        if (data.size() - pos < tls::kTlsRecordHeaderSize)
        {
            return std::nullopt;
        }
        const auto tail = data.subspan(pos);
        if (is_application_record_header(tail))
        {
            return pos;
        }

        std::size_t record_size = 0;
        if (!complete_record_at(data, pos, record_size))
        {
            return std::nullopt;
        }
        pos += record_size;
    }
    return std::nullopt;
}

enum class server_hello_status : uint8_t
{
    kUnknown,
    kTls13,
    kNotTls13,
};

[[nodiscard]] server_hello_status parse_server_hello(const std::span<const uint8_t> payload)
{
    if (payload.size() < 4 || payload[0] != 0x02)
    {
        return server_hello_status::kUnknown;
    }

    const auto handshake_len =
        (static_cast<std::size_t>(payload[1]) << 16U) | (static_cast<std::size_t>(payload[2]) << 8U) | static_cast<std::size_t>(payload[3]);
    if (payload.size() < 4U + handshake_len)
    {
        return server_hello_status::kUnknown;
    }

    const auto body = payload.subspan(4, handshake_len);
    std::size_t pos = 0;
    if (body.size() < 2U + 32U + 1U)
    {
        return server_hello_status::kNotTls13;
    }
    pos += 2U + 32U;

    const auto session_id_len = body[pos++];
    if (body.size() < pos + session_id_len + 2U + 1U)
    {
        return server_hello_status::kNotTls13;
    }
    pos += session_id_len;

    const auto cipher_suite = read_u16(body, pos);
    pos += 2U;
    if (cipher_suite == kTlsAes128Ccm8Sha256)
    {
        return server_hello_status::kNotTls13;
    }

    pos += 1U;
    if (body.size() < pos + 2U)
    {
        return server_hello_status::kNotTls13;
    }
    const auto extensions_len = read_u16(body, pos);
    pos += 2U;
    if (body.size() < pos + extensions_len)
    {
        return server_hello_status::kNotTls13;
    }

    const auto extensions_end = pos + extensions_len;
    while (pos < extensions_end)
    {
        if (extensions_end - pos < 4U)
        {
            return server_hello_status::kNotTls13;
        }
        const auto ext_type = read_u16(body, pos);
        const auto ext_len = read_u16(body, pos + 2U);
        pos += 4U;
        if (extensions_end - pos < ext_len)
        {
            return server_hello_status::kNotTls13;
        }
        if (ext_type == tls::consts::ext::kSupportedVersions)
        {
            if (ext_len == 2U && read_u16(body, pos) == tls::consts::kVer13)
            {
                return server_hello_status::kTls13;
            }
            return server_hello_status::kNotTls13;
        }
        pos += ext_len;
    }

    return server_hello_status::kNotTls13;
}

[[nodiscard]] write_segment make_segment(const command cmd,
                                         const std::span<const uint8_t> data,
                                         const bool switch_to_raw,
                                         const bool switch_to_outer_plain)
{
    return write_segment{
        .cmd = cmd,
        .content = std::vector<uint8_t>(data.begin(), data.end()),
        .switch_to_raw_after = switch_to_raw,
        .switch_to_outer_plain_after = switch_to_outer_plain,
    };
}

}    // namespace

bool encode_block_with_padding(const command cmd,
                               const std::span<const uint8_t> content,
                               const std::span<const uint8_t> padding,
                               std::vector<uint8_t>& out)
{
    out.clear();
    if (!valid_command(cmd) || !block_size_valid(content.size(), padding.size()))
    {
        return false;
    }

    out.reserve(kBlockHeaderSize + content.size() + padding.size());
    out.push_back(static_cast<uint8_t>(cmd));
    append_u16(out, content.size());
    append_u16(out, padding.size());
    out.insert(out.end(), content.begin(), content.end());
    out.insert(out.end(), padding.begin(), padding.end());
    return true;
}

bool encode_block(const command cmd,
                  const std::span<const uint8_t> content,
                  const padding_mode mode,
                  std::vector<uint8_t>& out,
                  boost::system::error_code& ec)
{
    out.clear();
    if (!valid_command(cmd) || content.size() + kBlockHeaderSize > tls::kMaxTlsApplicationDataPayloadLen)
    {
        ec = boost::asio::error::message_size;
        return false;
    }

    const auto padding_len = choose_padding_len(mode, content.size(), ec);
    if (ec)
    {
        return false;
    }

    std::vector<uint8_t> padding;
    if (!fill_random(padding, padding_len, ec))
    {
        return false;
    }
    if (!encode_block_with_padding(cmd, content, padding, out))
    {
        ec = boost::asio::error::message_size;
        return false;
    }
    ec.clear();
    return true;
}

void block_parser::append(const std::span<const uint8_t> data) { pending_.insert(pending_.end(), data.begin(), data.end()); }

parse_status block_parser::next(block& out, boost::system::error_code& ec)
{
    ec.clear();
    if (pending_.size() < kBlockHeaderSize)
    {
        return parse_status::kNeedMore;
    }

    const auto raw_cmd = pending_[0];
    const auto cmd = static_cast<command>(raw_cmd);
    if (!valid_command(cmd))
    {
        ec = boost::asio::error::invalid_argument;
        return parse_status::kError;
    }

    const std::span<const uint8_t> header(pending_.data(), kBlockHeaderSize);
    const auto content_len = read_u16(header, 1);
    const auto padding_len = read_u16(header, 3);
    if (!block_size_valid(content_len, padding_len))
    {
        ec = boost::asio::error::message_size;
        return parse_status::kError;
    }

    const auto total_size = kBlockHeaderSize + static_cast<std::size_t>(content_len) + static_cast<std::size_t>(padding_len);
    if (pending_.size() < total_size)
    {
        return parse_status::kNeedMore;
    }

    out.cmd = cmd;
    out.content.assign(pending_.begin() + static_cast<std::ptrdiff_t>(kBlockHeaderSize),
                       pending_.begin() + static_cast<std::ptrdiff_t>(kBlockHeaderSize + content_len));
    pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(total_size));
    return parse_status::kBlock;
}

std::vector<write_segment> tls_tracker::process(const direction dir, const std::span<const uint8_t> data)
{
    std::vector<write_segment> segments;
    if (data.empty() || direct_write_mode(dir) || outer_plain_mode(dir))
    {
        return segments;
    }

    observe(dir, data);

    const auto idx = dir_index(dir);
    if (!tls13_confirmed_ && !direct_disabled_ && budget_exceeded())
    {
        disable_direct();
    }
    if (direct_disabled_)
    {
        outer_plain_mode_[idx] = true;
        buffers_[idx].clear();
        handshake_buffers_[idx].clear();
        segments.push_back(make_segment(command::kEnd, data, false, true));
        return segments;
    }

    const auto direct_offset = find_direct_offset(data, tls13_confirmed_);
    if (direct_offset.has_value())
    {
        direct_write_mode_[idx] = true;
        buffers_[idx].clear();
        handshake_buffers_[idx].clear();
        if (*direct_offset != 0)
        {
            segments.push_back(make_segment(command::kContinue, data.subspan(0, *direct_offset), false, false));
        }
        segments.push_back(make_segment(command::kDirect, data.subspan(*direct_offset), true, false));
        return segments;
    }

    segments.push_back(make_segment(command::kContinue, data, false, false));
    return segments;
}

void tls_tracker::observe(const direction dir, const std::span<const uint8_t> data)
{
    if (data.empty() || direct_write_mode(dir) || outer_plain_mode(dir))
    {
        return;
    }

    if (!tls13_confirmed_ && !direct_disabled_)
    {
        inspected_chunks_++;
        inspected_bytes_ += data.size();
    }

    auto& buffer = buffers_[dir_index(dir)];
    buffer.insert(buffer.end(), data.begin(), data.end());
    analyze_buffer(dir);
}

bool tls_tracker::direct_write_mode(const direction dir) const { return direct_write_mode_[dir_index(dir)]; }

bool tls_tracker::outer_plain_mode(const direction dir) const { return outer_plain_mode_[dir_index(dir)]; }

void tls_tracker::analyze_buffer(const direction dir)
{
    auto& buffer = buffers_[dir_index(dir)];
    for (;;)
    {
        if (buffer.size() < tls::kTlsRecordHeaderSize)
        {
            return;
        }

        const std::span<const uint8_t> header(buffer.data(), tls::kTlsRecordHeaderSize);
        if (!looks_like_tls_record_header(header))
        {
            disable_direct();
            buffer.clear();
            return;
        }

        const auto record_len = read_u16(header, 3);
        const auto record_size = tls::kTlsRecordHeaderSize + static_cast<std::size_t>(record_len);
        if (buffer.size() < record_size)
        {
            return;
        }

        const std::span<const uint8_t> record(buffer.data(), record_size);
        const auto payload = record.subspan(tls::kTlsRecordHeaderSize);
        if (record[0] == tls::kContentTypeHandshake)
        {
            analyze_handshake_payload(dir, payload);
        }

        buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(record_size));
        if (direct_disabled_)
        {
            buffer.clear();
            return;
        }
    }
}

void tls_tracker::analyze_handshake_payload(const direction dir, const std::span<const uint8_t> payload)
{
    auto& handshake_buffer = handshake_buffers_[dir_index(dir)];
    if (payload.size() > constants::tls_limits::kMaxHandshakeReassembleBuffer - handshake_buffer.size())
    {
        disable_direct();
        handshake_buffer.clear();
        return;
    }
    handshake_buffer.insert(handshake_buffer.end(), payload.begin(), payload.end());
    analyze_handshake_messages(dir);
}

void tls_tracker::analyze_handshake_messages(const direction dir)
{
    auto& handshake_buffer = handshake_buffers_[dir_index(dir)];
    for (;;)
    {
        if (handshake_buffer.size() < 4U)
        {
            return;
        }

        const auto handshake_len = (static_cast<std::size_t>(handshake_buffer[1]) << 16U) |
                                   (static_cast<std::size_t>(handshake_buffer[2]) << 8U) |
                                   static_cast<std::size_t>(handshake_buffer[3]);
        if (handshake_len > constants::tls_limits::kMaxHandshakeMessageSize)
        {
            disable_direct();
            handshake_buffer.clear();
            return;
        }
        const auto message_size = 4U + handshake_len;
        if (handshake_buffer.size() < message_size)
        {
            return;
        }

        const std::span<const uint8_t> message(handshake_buffer.data(), message_size);
        if (dir == direction::kClientToServer && message[0] == 0x01)
        {
            client_hello_seen_ = true;
        }
        else if (dir == direction::kServerToClient && message[0] == 0x02)
        {
            if (!client_hello_seen_)
            {
                disable_direct();
            }
            else
            {
                const auto status = parse_server_hello(message);
                if (status == server_hello_status::kTls13)
                {
                    tls13_confirmed_ = true;
                }
                else if (status == server_hello_status::kNotTls13)
                {
                    disable_direct();
                }
            }
        }

        handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + static_cast<std::ptrdiff_t>(message_size));
        if (direct_disabled_)
        {
            handshake_buffer.clear();
            return;
        }
    }
}

void tls_tracker::disable_direct() { direct_disabled_ = true; }

bool tls_tracker::budget_exceeded() const { return inspected_chunks_ > kTlsFilterMaxChunks || inspected_bytes_ > kTlsFilterMaxBytes; }

}    // namespace relay::vision
