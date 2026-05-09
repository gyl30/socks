#ifndef VISION_TCP_H
#define VISION_TCP_H

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/system/error_code.hpp>

namespace relay::vision
{

constexpr std::size_t kBlockHeaderSize = 5;
constexpr std::size_t kTlsFilterMaxChunks = 8;
constexpr std::size_t kTlsFilterMaxBytes = 64U * 1024U;

enum class command : uint8_t
{
    kContinue = 0x00,
    kEnd = 0x01,
    kDirect = 0x02,
};

enum class padding_mode : uint8_t
{
    kNone,
    kShort,
    kLong,
};

enum class parse_status : uint8_t
{
    kNeedMore,
    kBlock,
    kError,
};

struct block
{
    command cmd = command::kContinue;
    std::vector<uint8_t> content;
};

[[nodiscard]] bool encode_block_with_padding(command cmd,
                                             std::span<const uint8_t> content,
                                             std::span<const uint8_t> padding,
                                             std::vector<uint8_t>& out);
[[nodiscard]] padding_mode next_continue_padding_mode(bool& first_continue);

[[nodiscard]] bool encode_block(command cmd,
                                std::span<const uint8_t> content,
                                padding_mode mode,
                                std::vector<uint8_t>& out,
                                boost::system::error_code& ec);

class block_parser
{
   public:
    void append(std::span<const uint8_t> data);
    [[nodiscard]] parse_status next(block& out, boost::system::error_code& ec);
    [[nodiscard]] bool empty() const { return pending_.empty(); }
    [[nodiscard]] std::size_t pending_size() const { return pending_.size(); }

   private:
    std::vector<uint8_t> pending_;
};

enum class direction : uint8_t
{
    kClientToServer = 0,
    kServerToClient = 1,
};

struct write_segment
{
    command cmd = command::kContinue;
    std::vector<uint8_t> content;
    bool switch_to_raw_after = false;
    bool switch_to_outer_plain_after = false;
};

class tls_tracker
{
   public:
    [[nodiscard]] std::vector<write_segment> process(direction dir, std::span<const uint8_t> data);
    void observe(direction dir, std::span<const uint8_t> data);

    [[nodiscard]] bool tls13_confirmed() const { return tls13_confirmed_; }
    [[nodiscard]] bool direct_disabled() const { return direct_disabled_; }
    [[nodiscard]] bool direct_write_mode(direction dir) const;
    [[nodiscard]] bool outer_plain_mode(direction dir) const;

   private:
    void analyze_buffer(direction dir);
    void analyze_handshake_payload(direction dir, std::span<const uint8_t> payload);
    void analyze_handshake_messages(direction dir);
    void disable_direct();
    [[nodiscard]] bool budget_exceeded() const;

    std::array<std::vector<uint8_t>, 2> buffers_;
    std::array<std::vector<uint8_t>, 2> handshake_buffers_;
    std::array<bool, 2> direct_write_mode_{false, false};
    std::array<bool, 2> outer_plain_mode_{false, false};
    bool client_hello_seen_ = false;
    bool tls13_confirmed_ = false;
    bool direct_disabled_ = false;
    std::size_t inspected_chunks_ = 0;
    std::size_t inspected_bytes_ = 0;
};

}    // namespace relay::vision

#endif
