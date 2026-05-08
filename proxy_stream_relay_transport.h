#ifndef PROXY_STREAM_RELAY_TRANSPORT_H
#define PROXY_STREAM_RELAY_TRANSPORT_H

#include <span>
#include <mutex>
#include <memory>
#include <vector>
#include <cstdint>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "vision_tcp.h"
#include "proxy_protocol.h"
#include "stream_relay_transport.h"
#include "proxy_reality_connection.h"

namespace relay
{

class proxy_connection_tcp_stream
{
   public:
    explicit proxy_connection_tcp_stream(std::shared_ptr<proxy_reality_connection> connection = nullptr);

    void reset(std::shared_ptr<proxy_reality_connection> connection = nullptr);
    [[nodiscard]] bool has_connection() const { return connection_ != nullptr; }
    [[nodiscard]] std::shared_ptr<proxy_reality_connection> connection() const { return connection_; }
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(
        std::span<uint8_t> buffer, uint32_t read_timeout, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec);
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);
    boost::asio::awaitable<void> close();

   private:
    std::shared_ptr<proxy_reality_connection> connection_;
    std::vector<uint8_t> pending_read_data_;
    std::size_t pending_read_offset_ = 0;
    relay::proxy::tcp_stream_recv_state recv_state_;
    relay::proxy::tcp_stream_send_state send_state_;
};

class proxy_connection_stream_relay_transport final : public stream_relay_transport
{
   public:
    proxy_connection_stream_relay_transport(std::shared_ptr<proxy_reality_connection> connection, const config::timeout_t& timeout);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<uint8_t> buffer, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> close() override;

   private:
    proxy_connection_tcp_stream stream_;
    const config::timeout_t& timeout_;
};

class vision_connection_tcp_stream
{
   public:
    vision_connection_tcp_stream(std::shared_ptr<proxy_reality_connection> connection = nullptr,
                                 vision::direction write_direction = vision::direction::kClientToServer,
                                 vision::direction read_direction = vision::direction::kServerToClient);

    void reset(std::shared_ptr<proxy_reality_connection> connection = nullptr,
               vision::direction write_direction = vision::direction::kClientToServer,
               vision::direction read_direction = vision::direction::kServerToClient);
    [[nodiscard]] bool has_connection() const;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(
        std::span<uint8_t> buffer, uint32_t read_timeout, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec);
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);
    boost::asio::awaitable<void> close();

   private:
    enum class pending_read_switch : uint8_t
    {
        kNone,
        kRaw,
        kOuterPlain,
    };

    enum class read_mode : uint8_t
    {
        kVision,
        kRaw,
        kOuterPlain,
    };

    enum class write_mode : uint8_t
    {
        kVision,
        kRaw,
        kOuterPlain,
    };

    enum class read_action : uint8_t
    {
        kReturn,
        kReadRaw,
        kReadOuter,
        kReadOuterBlock,
        kEnterRawThenReadRaw,
        kEnterRawThenReturn,
    };

    enum class write_action : uint8_t
    {
        kSegments,
        kRaw,
        kOuter,
    };

    struct read_step
    {
        read_action action = read_action::kReturn;
        std::shared_ptr<proxy_reality_connection> connection;
        uint64_t generation = 0;
        std::size_t bytes = 0;
    };

    struct encoded_segment
    {
        vision::write_segment segment;
        vision::padding_mode mode = vision::padding_mode::kNone;
    };

    [[nodiscard]] boost::asio::awaitable<std::size_t> read_outer_plain(std::shared_ptr<proxy_reality_connection> connection,
                                                                       std::span<uint8_t> buffer,
                                                                       uint32_t read_timeout,
                                                                       boost::system::error_code& ec);
    void clear_state_locked();
    [[nodiscard]] read_step plan_read_step_locked(std::span<uint8_t> buffer, boost::system::error_code& ec);
    void plan_pending_read_step_locked(read_step& step, std::span<uint8_t> buffer, boost::system::error_code& ec);
    void plan_parsed_read_step_locked(vision::block parsed, read_step& step, std::span<uint8_t> buffer, boost::system::error_code& ec);
    void finalize_pending_read_step_locked(read_step& step, boost::system::error_code& ec);
    [[nodiscard]] bool validate_generation_locked(
        const std::shared_ptr<proxy_reality_connection>& connection, uint64_t generation, boost::system::error_code& ec) const;
    void capture_write_plan_locked(std::span<const uint8_t> data,
                                   std::shared_ptr<proxy_reality_connection>& connection,
                                   uint64_t& generation,
                                   write_action& action,
                                   std::vector<encoded_segment>& segments,
                                   boost::system::error_code& ec);

    mutable std::mutex mutex_;
    std::shared_ptr<proxy_reality_connection> connection_;
    vision::block_parser parser_;
    vision::tls_tracker tracker_;
    std::vector<uint8_t> pending_read_data_;
    std::size_t pending_read_offset_ = 0;
    pending_read_switch pending_read_switch_ = pending_read_switch::kNone;
    read_mode read_mode_ = read_mode::kVision;
    write_mode write_mode_ = write_mode::kVision;
    vision::direction write_direction_ = vision::direction::kClientToServer;
    vision::direction read_direction_ = vision::direction::kServerToClient;
    uint64_t generation_ = 0;
};

class vision_connection_stream_relay_transport final : public stream_relay_transport
{
   public:
    vision_connection_stream_relay_transport(std::shared_ptr<proxy_reality_connection> connection,
                                             const config::timeout_t& timeout,
                                             vision::direction write_direction,
                                             vision::direction read_direction);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<uint8_t> buffer, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> write(std::span<const uint8_t> data, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> close() override;

   private:
    vision_connection_tcp_stream stream_;
    const config::timeout_t& timeout_;
};

}    // namespace relay

#endif
