#include <span>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <ranges>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
extern "C"
{
#include <openssl/rand.h>
}
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "tls/core.h"
#include "constants.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "run_loop_spawner.h"
#include "reality/session/engine.h"
#include "reality/session/session.h"
namespace mux
{

namespace
{

constexpr char kHeartbeatProbeMagic[] = "hbt1";
constexpr uint8_t kHeartbeatProbeRequest = 1;
constexpr uint8_t kHeartbeatProbeResponse = 2;
constexpr std::size_t kHeartbeatProbeMagicSize = 4;
constexpr std::size_t kHeartbeatProbeTypeOffset = kHeartbeatProbeMagicSize;
constexpr std::size_t kHeartbeatProbeTimestampOffset = kHeartbeatProbeTypeOffset + 1;
constexpr std::size_t kHeartbeatProbeHeaderSize = kHeartbeatProbeTimestampOffset + 8;

void encode_u64_be(const uint64_t value, uint8_t* out)
{
    out[0] = static_cast<uint8_t>((value >> 56) & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
    out[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
    out[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
    out[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[7] = static_cast<uint8_t>(value & 0xFF);
}

[[nodiscard]] uint64_t decode_u64_be(const uint8_t* data)
{
    return (static_cast<uint64_t>(data[0]) << 56) | (static_cast<uint64_t>(data[1]) << 48) | (static_cast<uint64_t>(data[2]) << 40) |
           (static_cast<uint64_t>(data[3]) << 32) | (static_cast<uint64_t>(data[4]) << 24) | (static_cast<uint64_t>(data[5]) << 16) |
           (static_cast<uint64_t>(data[6]) << 8) | static_cast<uint64_t>(data[7]);
}

void write_heartbeat_probe_prefix(std::vector<uint8_t>& payload, uint8_t type, uint64_t send_ms)
{
    payload[0] = static_cast<uint8_t>(kHeartbeatProbeMagic[0]);
    payload[1] = static_cast<uint8_t>(kHeartbeatProbeMagic[1]);
    payload[2] = static_cast<uint8_t>(kHeartbeatProbeMagic[2]);
    payload[3] = static_cast<uint8_t>(kHeartbeatProbeMagic[3]);
    payload[kHeartbeatProbeTypeOffset] = type;
    encode_u64_be(send_ms, payload.data() + static_cast<std::ptrdiff_t>(kHeartbeatProbeTimestampOffset));
}

[[nodiscard]] bool decode_heartbeat_probe(const std::span<const uint8_t> payload, uint8_t& type, uint64_t& send_ms)
{
    if (payload.size() < kHeartbeatProbeHeaderSize)
    {
        return false;
    }
    if (payload[0] != static_cast<uint8_t>(kHeartbeatProbeMagic[0]) || payload[1] != static_cast<uint8_t>(kHeartbeatProbeMagic[1]) ||
        payload[2] != static_cast<uint8_t>(kHeartbeatProbeMagic[2]) || payload[3] != static_cast<uint8_t>(kHeartbeatProbeMagic[3]))
    {
        return false;
    }
    type = payload[kHeartbeatProbeTypeOffset];
    if (type != kHeartbeatProbeRequest && type != kHeartbeatProbeResponse)
    {
        return false;
    }
    send_ms = decode_u64_be(payload.data() + static_cast<std::ptrdiff_t>(kHeartbeatProbeTimestampOffset));
    return true;
}

[[nodiscard]] uint64_t next_heartbeat_interval_ms(const config& cfg)
{
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> interval_dist(cfg.heartbeat.min_interval, cfg.heartbeat.max_interval);
    return static_cast<uint64_t>(interval_dist(rng)) * 1000ULL;
}

[[nodiscard]] std::size_t next_heartbeat_payload_size(const config& cfg, bool with_probe_prefix)
{
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> padding_dist(cfg.heartbeat.min_padding, cfg.heartbeat.max_padding);
    const auto padding_len = padding_dist(rng);
    const auto payload_len = std::min<std::size_t>(padding_len, mux::kMaxPayload);
    if (!with_probe_prefix)
    {
        return payload_len;
    }
    return std::max<std::size_t>(payload_len, kHeartbeatProbeHeaderSize);
}

[[nodiscard]] bool fill_random_bytes(std::vector<uint8_t>& payload, std::size_t offset)
{
    if (payload.size() <= offset)
    {
        return true;
    }
    return RAND_bytes(payload.data() + static_cast<std::ptrdiff_t>(offset), static_cast<int>(payload.size() - offset)) == 1;
}

[[nodiscard]] bool is_expected_mux_shutdown(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor || ec == boost::asio::error::eof;
}

[[nodiscard]] bool is_expected_mux_channel_shutdown(const boost::system::error_code& ec)
{
    return is_expected_mux_shutdown(ec) || ec == boost::asio::experimental::error::channel_errors::channel_closed ||
           ec == boost::asio::experimental::error::channel_errors::channel_cancelled;
}

void handle_post_handshake_record(uint32_t cid,
                                  std::string_view local_host,
                                  uint16_t local_port,
                                  std::string_view remote_host,
                                  uint16_t remote_port,
                                  const std::span<const uint8_t> plaintext,
                                  boost::system::error_code& ec)
{
    if (plaintext.empty())
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage post_handshake empty record",
                 log_event::kHandshake,
                 cid,
                 local_host,
                 local_port,
                 remote_host,
                 remote_port);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    const auto handshake_type = plaintext.front();
    if (handshake_type == tls::kHandshakeTypeNewSessionTicket)
    {
        LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage post_handshake ignore handshake_type {}",
                  log_event::kHandshake,
                  cid,
                  local_host,
                  local_port,
                  remote_host,
                  remote_port,
                  handshake_type);
        return;
    }
    if (handshake_type == tls::kHandshakeTypeKeyUpdate)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage post_handshake unsupported handshake_type {}",
                 log_event::kHandshake,
                 cid,
                 local_host,
                 local_port,
                 remote_host,
                 remote_port,
                 handshake_type);
        ec = boost::asio::error::operation_not_supported;
        return;
    }

    LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage post_handshake unsupported handshake_type {}",
             log_event::kHandshake,
             cid,
             local_host,
             local_port,
             remote_host,
             remote_port,
             handshake_type);
    ec = boost::asio::error::invalid_argument;
}

}    // namespace

mux_connection::mux_connection(boost::asio::ip::tcp::socket socket,
                               io_worker& worker,
                               reality::reality_record_context record_context,
                               const config& cfg,
                               uint32_t conn_id)
    : cfg_(cfg),
      cid_(conn_id),
      worker_(worker),
      reality_engine_(std::move(record_context)),
      socket_(std::move(socket)),
      write_channel_(std::make_unique<channel_type>(worker.io_context, constants::mux::kWriteChannelCapacity)),
      stop_channel_(std::make_unique<stop_channel_type>(worker.io_context, constants::mux::kStopChannelCapacity))
{
    boost::system::error_code local_ep_ec;
    const auto local_ep = socket_.local_endpoint(local_ep_ec);
    if (!local_ep_ec)
    {
        local_addr_ = local_ep.address().to_string();
        local_port_ = local_ep.port();
    }

    boost::system::error_code remote_ep_ec;
    const auto remote_ep = socket_.remote_endpoint(remote_ep_ec);
    if (!remote_ep_ec)
    {
        remote_addr_ = remote_ep.address().to_string();
        remote_port_ = remote_ep.port();
    }
    LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} mux initialized",
             log_event::kConnInit,
             cid_,
             local_addr_.empty() ? "unknown" : local_addr_,
             local_port_,
             remote_addr_.empty() ? "unknown" : remote_addr_,
             remote_port_);
}

mux_connection::~mux_connection() = default;

std::string_view mux_connection::local_host() const
{
    if (local_addr_.empty())
    {
        return "unknown";
    }
    return local_addr_;
}

std::string_view mux_connection::remote_host() const
{
    if (remote_addr_.empty())
    {
        return "unknown";
    }
    return remote_addr_;
}

std::size_t mux_connection::stream_count()
{
    const std::scoped_lock<std::mutex> lock(mutex_);
    return streams_.size();
}

std::shared_ptr<mux_stream> mux_connection::find_stream(uint32_t stream_id)
{
    const std::scoped_lock<std::mutex> lock(mutex_);
    const auto it = streams_.find(stream_id);
    if (it != streams_.end())
    {
        return it->second;
    }
    return nullptr;
}

void mux_connection::start_accepting_streams()
{
    if (incoming_syn_channel_ != nullptr)
    {
        return;
    }
    incoming_syn_channel_ = std::make_unique<channel_type>(worker_.io_context, 1);
}

boost::asio::awaitable<void> mux_connection::handle_unknown_stream(mux::frame_header header, std::vector<uint8_t> payload)
{
    if (header.command == mux::kCmdSyn)
    {
        if (is_stream_limit_reached())
        {
            LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage handle_unknown_stream drop incoming_syn max_streams {} active_streams {}",
                     log_event::kMux,
                     cid_,
                     local_host(),
                     local_port_,
                     remote_host(),
                     remote_port_,
                     header.stream_id,
                     cfg_.limits.max_streams,
                     stream_count());
            co_return;
        }
        if (incoming_syn_channel_ == nullptr)
        {
            LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage handle_unknown_stream drop incoming_syn no_accept_loop",
                      log_event::kMux,
                      cid_,
                      local_host(),
                      local_port_,
                      remote_host(),
                      remote_port_,
                      header.stream_id);
            co_return;
        }

        co_await queue_incoming_syn(header, std::move(payload));
        co_return;
    }

    if (header.command == mux::kCmdDat)
    {
        LOG_TRACE("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage handle_unknown_stream drop late_dat_frame",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  header.stream_id);
        co_return;
    }

    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage handle_unknown_stream drop frame cmd {}",
              log_event::kMux,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_,
              header.stream_id,
              header.command);
}

boost::asio::awaitable<void> mux_connection::handle_stream_frame(const mux::frame_header& header, std::vector<uint8_t> payload)
{
    auto stream = find_stream(header.stream_id);
    if (stream == nullptr)
    {
        co_return co_await handle_unknown_stream(header, std::move(payload));
    }
    mux_frame frame;
    frame.h = header;
    frame.payload = std::move(payload);
    boost::system::error_code ec;
    co_await stream->on_frame(std::move(frame), ec);
    if (ec)
    {
        if (ec == boost::asio::error::timed_out)
        {
            LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage deliver_frame backpressure timeout reset_stream",
                     log_event::kMux,
                     cid_,
                     local_host(),
                     local_port_,
                     remote_host(),
                     remote_port_,
                     header.stream_id);
            close_and_remove_stream(stream);

            mux_frame rst_frame;
            rst_frame.h.stream_id = header.stream_id;
            rst_frame.h.command = mux::kCmdRst;
            boost::system::error_code rst_ec;
            co_await send_async_with_timeout(std::move(rst_frame), constants::mux::kControlFrameSendTimeoutSec, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage deliver_frame send_rst error {}",
                         log_event::kMux,
                         cid_,
                         local_host(),
                         local_port_,
                         remote_host(),
                         remote_port_,
                         header.stream_id,
                         rst_ec.message());
            }
            co_return;
        }

        if (ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor ||
            ec == boost::asio::experimental::error::channel_errors::channel_closed)
        {
            LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage deliver_frame drop late_frame channel_closed",
                      log_event::kMux,
                      cid_,
                      local_host(),
                      local_port_,
                      remote_host(),
                      remote_port_,
                      header.stream_id);
            close_and_remove_stream(stream);
            co_return;
        }

        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage deliver_frame error {}",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  header.stream_id,
                  ec.message());
        stop();
    }
}

boost::asio::awaitable<void> mux_connection::queue_incoming_syn(mux::frame_header header, std::vector<uint8_t> payload)
{
    mux_frame frame;
    frame.h = header;
    frame.payload = std::move(payload);
    const auto [send_ec] =
        co_await incoming_syn_channel_->async_send(boost::system::error_code{}, std::move(frame), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (!send_ec || send_ec == boost::asio::error::operation_aborted || send_ec == boost::asio::experimental::error::channel_errors::channel_closed ||
        send_ec == boost::asio::experimental::error::channel_errors::channel_cancelled)
    {
        co_return;
    }

    LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage queue_incoming_syn error {}",
             log_event::kMux,
             cid_,
             local_host(),
             local_port_,
             remote_host(),
             remote_port_,
             header.stream_id,
             send_ec.message());
}

void mux_connection::remove_stream(const std::shared_ptr<mux_stream>& stream)
{
    const auto stream_id = stream->id();
    const std::scoped_lock<std::mutex> lock(mutex_);
    streams_.erase(stream_id);
}

void mux_connection::close_and_remove_stream(const std::shared_ptr<mux_stream>& stream)
{
    if (stream == nullptr)
    {
        return;
    }

    stream->close();
    remove_stream(stream);
}

void mux_connection::start()
{
    const auto now_ms = net::now_ms();
    last_read_time_ms_ = now_ms;
    last_write_time_ms_ = now_ms;
    last_non_heartbeat_read_time_ms_ = now_ms;
    last_non_heartbeat_write_time_ms_ = now_ms;
    run_loop_spawner::spawn(worker_, shared_from_this());
}

boost::asio::awaitable<void> mux_connection::run_loop()
{
    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} active_streams {} mux loops started",
              log_event::kConnInit,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_,
              stream_count());
    using boost::asio::experimental::awaitable_operators::operator||;
    co_await (read_loop() || write_loop() || timeout_loop() || heartbeat_loop());
    stop();
    LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} active_streams {} mux loops finished stopped",
             log_event::kConnClose,
             cid_,
             local_host(),
             local_port_,
             remote_host(),
             remote_port_,
             stream_count());
}

void mux_connection::stop()
{
    if (stopped_.exchange(true))
    {
        return;
    }

    auto self = shared_from_this();
    boost::asio::dispatch(socket_.get_executor(), [self]() { self->stop_on_executor(); });
}

void mux_connection::stop_on_executor()
{
    std::vector<std::shared_ptr<mux_stream>> streams_to_close;
    {
        const std::scoped_lock<std::mutex> lock(mutex_);
        streams_to_close.reserve(streams_.size());
        for (const auto& stream : streams_ | std::views::values)
        {
            if (stream != nullptr)
            {
                streams_to_close.push_back(stream);
            }
        }
    }

    for (const auto& stream : streams_to_close)
    {
        stream->close();
    }

    if (write_channel_ != nullptr)
    {
        write_channel_->close();
    }
    if (incoming_syn_channel_ != nullptr)
    {
        incoming_syn_channel_->close();
    }

    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage stop close failed {}",
                 log_event::kConnClose,
                 cid_,
                 local_host(),
                 local_port_,
                 remote_host(),
                 remote_port_,
                 ec.message());
    }
    if (stop_channel_ != nullptr)
    {
        stop_channel_->close();
    }
}

boost::asio::awaitable<void> mux_connection::async_wait_stopped()
{
    if (stop_channel_ == nullptr)
    {
        co_return;
    }
    boost::system::error_code ec;
    co_await stop_channel_->async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec && !is_expected_mux_channel_shutdown(ec))
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage wait_stopped error {}",
                 log_event::kConnClose,
                 cid_,
                 local_host(),
                 local_port_,
                 remote_host(),
                 remote_port_,
                 ec.message());
    }
}

boost::asio::awaitable<mux_frame> mux_connection::async_receive_syn(boost::system::error_code& ec) const
{
    if (incoming_syn_channel_ == nullptr)
    {
        ec = boost::asio::error::operation_not_supported;
        co_return mux_frame{};
    }

    auto [recv_ec, frame] = co_await incoming_syn_channel_->async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    ec = recv_ec;
    co_return frame;
}

boost::asio::awaitable<void> mux_connection::read_loop()
{
    boost::system::error_code ec;
    while (true)
    {
        const auto buf = reality_engine_.read_buffer(8192, ec);
        if (ec)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage read_loop read_buffer error {}",
                      log_event::kMux,
                      cid_,
                      local_host(),
                      local_port_,
                      remote_host(),
                      remote_port_,
                      ec.message());
            break;
        }
        const auto n = co_await socket_.async_read_some(buf, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (is_expected_mux_shutdown(ec))
            {
                LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} stage read_loop socket_read stopped {}",
                         log_event::kConnClose,
                         cid_,
                         local_host(),
                         local_port_,
                         remote_host(),
                         remote_port_,
                         ec.message());
            }
            else
            {
                LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage read_loop socket_read error {}",
                          log_event::kMux,
                          cid_,
                          local_host(),
                          local_port_,
                          remote_host(),
                          remote_port_,
                          ec.message());
            }
            break;
        }

        read_bytes_ += n;
        last_read_time_ms_ = net::now_ms();
        reality_engine_.commit_read(n);

        while (true)
        {
            const auto record = reality_engine_.decrypt_record(ec);
            if (ec)
            {
                break;
            }
            if (!record.has_value())
            {
                break;
            }

            const auto content_type = record->content_type;
            co_await on_tls_record(content_type, record->payload, ec);
            if (ec)
            {
                break;
            }
            if (content_type == tls::kContentTypeAlert)
            {
                ec = boost::asio::error::eof;
                break;
            }
        }
        if (ec)
        {
            if (is_expected_mux_shutdown(ec))
            {
                LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} stage read_loop decrypt_record stopped {}",
                         log_event::kConnClose,
                         cid_,
                         local_host(),
                         local_port_,
                         remote_host(),
                         remote_port_,
                         ec.message());
            }
            else
            {
                LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage read_loop decrypt_record error {}",
                          log_event::kMux,
                          cid_,
                          local_host(),
                          local_port_,
                          remote_host(),
                          remote_port_,
                          ec.message());
            }
            break;
        }
    }
    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage read_loop finished",
              log_event::kConnClose,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_);
}

boost::asio::awaitable<void> mux_connection::on_tls_record(uint8_t type,
                                                           const std::span<const uint8_t> plaintext,
                                                           boost::system::error_code& ec)
{
    if (type == tls::kContentTypeApplicationData)
    {
        std::vector<mux_frame> frames;
        mux_codec::decode_frames(pending_plaintext_, plaintext, cfg_.limits.max_buffer, frames, ec);
        if (ec)
        {
            LOG_ERROR("event {} conn_id {} mux decode failed {}", log_event::kMux, cid_, ec.message());
            co_return;
        }
        for (auto& [h, payload] : frames)
        {
            co_await on_mux_frame(h, std::move(payload));
        }
        co_return;
    }

    if (type == tls::kContentTypeAlert)
    {
        co_return;
    }
    if (type == tls::kContentTypeHandshake)
    {
        handle_post_handshake_record(cid_, local_host(), local_port_, remote_host(), remote_port_, plaintext, ec);
        co_return;
    }

    LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage on_tls_record unsupported content_type {}",
             log_event::kMux,
             cid_,
             local_host(),
             local_port_,
             remote_host(),
             remote_port_,
             type);
    ec = boost::asio::error::invalid_argument;
}

boost::asio::awaitable<void> mux_connection::write_loop()
{
    boost::system::error_code ec;
    while (true)
    {
        const auto msg = co_await write_channel_->async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }
        frame_header header = msg.h;
        header.length = static_cast<uint16_t>(msg.payload.size());
        const auto mux_frame = mux_codec::encode_frame(header, msg.payload);

        const auto ct = reality_engine_.encrypt_record(mux_frame, ec);
        if (ec)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage write_loop encrypt error {}",
                      log_event::kMux,
                      cid_,
                      local_host(),
                      local_port_,
                      remote_host(),
                      remote_port_,
                      ec.message());
            break;
        }

        const auto n = co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(ct.data(), ct.size()), cfg_.timeout.write, ec);

        if (ec)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage write_loop socket_write error {}",
                      log_event::kMux,
                      cid_,
                      local_host(),
                      local_port_,
                      remote_host(),
                      remote_port_,
                      ec.message());
            break;
        }
        if (n != ct.size())
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage write_loop short_write wrote {} expected {}",
                      log_event::kMux,
                      cid_,
                      local_host(),
                      local_port_,
                      remote_host(),
                      remote_port_,
                      n,
                      ct.size());
        }
        write_bytes_ += n;
        last_write_time_ms_ = net::now_ms();
        if (msg.h.stream_id != mux::kStreamIdHeartbeat)
        {
            last_non_heartbeat_write_time_ms_ = last_write_time_ms_;
        }
    }
    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage write_loop finished",
              log_event::kConnClose,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_);
}

boost::asio::awaitable<void> mux_connection::timeout_loop()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

    const auto idle_timeout_ms = static_cast<uint64_t>(cfg_.timeout.idle) * 1000ULL;
    boost::system::error_code ec;
    while (true)
    {
        ec = co_await net::wait_for(worker_.io_context, std::chrono::seconds(1));
        if (ec)
        {
            break;
        }
        const auto now_ms = net::now_ms();
        const auto read_diff = now_ms - last_non_heartbeat_read_time_ms_;
        const auto write_diff = now_ms - last_non_heartbeat_write_time_ms_;
        if (read_diff > idle_timeout_ms && write_diff > idle_timeout_ms)
        {
            break;
        }
    }

    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage timeout_loop finished",
              log_event::kConnClose,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_);
    stop();
}

boost::asio::awaitable<void> mux_connection::send_heartbeat_frame(boost::system::error_code& ec)
{
    std::vector<uint8_t> payload(next_heartbeat_payload_size(cfg_, true));
    write_heartbeat_probe_prefix(payload, kHeartbeatProbeRequest, net::now_ms());
    if (!fill_random_bytes(payload, kHeartbeatProbeHeaderSize))
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat rand error",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_);
        ec = boost::asio::error::fault;
        co_return;
    }
    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat send payload_size {}",
              log_event::kMux,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_,
              payload.size());

    mux_frame msg;
    msg.h.stream_id = mux::kStreamIdHeartbeat;
    msg.h.command = mux::kCmdDat;
    msg.payload = std::move(payload);
    co_await send_async(std::move(msg), ec);
}

boost::asio::awaitable<void> mux_connection::heartbeat_loop()
{
    while (true)
    {
        auto ec = co_await net::wait_for(worker_.io_context, std::chrono::milliseconds(next_heartbeat_interval_ms(cfg_)));
        if (ec)
        {
            break;
        }

        co_await send_heartbeat_frame(ec);
        if (ec)
        {
            break;
        }
    }

    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat finished",
              log_event::kConnClose,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_);
}

boost::asio::awaitable<void> mux_connection::handle_heartbeat_frame(std::vector<uint8_t> payload)
{
    uint8_t type = 0;
    uint64_t send_ms = 0;
    if (!decode_heartbeat_probe(payload, type, send_ms))
    {
        LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat recv_unknown payload_size {}",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  payload.size());
        co_return;
    }

    if (type == kHeartbeatProbeRequest)
    {
        payload[kHeartbeatProbeTypeOffset] = kHeartbeatProbeResponse;
        mux_frame response;
        response.h.stream_id = mux::kStreamIdHeartbeat;
        response.h.command = mux::kCmdDat;
        response.payload = std::move(payload);

        boost::system::error_code ec;
        co_await send_async(std::move(response), ec);
        if (ec)
        {
            LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat send_response error {}",
                     log_event::kMux,
                     cid_,
                     local_host(),
                     local_port_,
                     remote_host(),
                     remote_port_,
                     ec.message());
        }
        co_return;
    }

    const auto now_ms = net::now_ms();
    if (send_ms > now_ms)
    {
        LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat ignore_response send_ms {} now_ms {}",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  send_ms,
                  now_ms);
        co_return;
    }

    last_heartbeat_rtt_ms_ = now_ms - send_ms;
    heartbeat_rtt_valid_ = true;
    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} stage heartbeat rtt_ms {}",
              log_event::kMux,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_,
              last_heartbeat_rtt_ms_);
}

boost::asio::awaitable<void> mux_connection::on_mux_frame(const mux::frame_header header, std::vector<uint8_t> payload)
{
    LOG_TRACE("event {} conn_id {} local {}:{} remote {}:{} stream_id {} cmd {} len {} payload_size {} recv frame",
              log_event::kMuxFrame,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_,
              header.stream_id,
              header.command,
              header.length,
              payload.size());

    if (header.stream_id == mux::kStreamIdHeartbeat)
    {
        co_return co_await handle_heartbeat_frame(std::move(payload));
    }
    last_non_heartbeat_read_time_ms_ = net::now_ms();

    co_return co_await handle_stream_frame(header, std::move(payload));
}

std::shared_ptr<mux_stream> mux_connection::create_stream()
{
    std::shared_ptr<mux_stream> stream;
    uint32_t stream_id = mux::kStreamIdHeartbeat;
    {
        const std::scoped_lock<std::mutex> lock(mutex_);
        if (stopped_.load(std::memory_order_relaxed))
        {
            LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage create_stream rejected stopped",
                     log_event::kMux,
                     cid_,
                     local_host(),
                     local_port_,
                     remote_host(),
                     remote_port_);
            return nullptr;
        }
        if (cfg_.limits.max_streams > 0 && streams_.size() >= cfg_.limits.max_streams)
        {
            LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage create_stream rejected max_streams {} active_streams {}",
                     log_event::kMux,
                     cid_,
                     local_host(),
                     local_port_,
                     remote_host(),
                     remote_port_,
                     cfg_.limits.max_streams,
                     streams_.size());
            return nullptr;
        }
        stream_id = acquire_next_id();
        if (stream_id != mux::kStreamIdHeartbeat)
        {
            stream = std::make_shared<mux_stream>(stream_id, cfg_, worker_.io_context, shared_from_this());
            streams_.emplace(stream_id, stream);
        }
    }
    if (stream_id == mux::kStreamIdHeartbeat)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage create_stream stream_id exhausted closing connection",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_);
        stop();
        return nullptr;
    }
    return stream;
}

std::shared_ptr<mux_stream> mux_connection::create_incoming_stream(uint32_t stream_id)
{
    if (stream_id == mux::kStreamIdHeartbeat)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage create_incoming_stream reject heartbeat stream_id",
                 log_event::kMux,
                 cid_,
                 local_host(),
                 local_port_,
                 remote_host(),
                 remote_port_);
        return nullptr;
    }

    const std::scoped_lock<std::mutex> lock(mutex_);
    const auto it = streams_.find(stream_id);
    if (it != streams_.end())
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stream_id {} stage create_incoming_stream already_registered",
                 log_event::kMux,
                 cid_,
                 local_host(),
                 local_port_,
                 remote_host(),
                 remote_port_,
                 stream_id);
        return nullptr;
    }

    auto stream = std::make_shared<mux_stream>(stream_id, cfg_, worker_.io_context, shared_from_this());
    streams_.emplace(stream_id, stream);
    return stream;
}

bool mux_connection::is_stream_limit_reached()
{
    if (cfg_.limits.max_streams == 0)
    {
        return false;
    }

    const std::scoped_lock<std::mutex> lock(mutex_);
    return streams_.size() >= cfg_.limits.max_streams;
}

boost::asio::awaitable<void> mux_connection::send_async(mux_frame msg, boost::system::error_code& ec)
{
    co_return co_await send_async_with_timeout(std::move(msg), 0, ec);
}

boost::asio::awaitable<void> mux_connection::send_async_with_timeout(mux_frame msg, uint32_t timeout_sec, boost::system::error_code& ec)
{
    if (msg.payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stream_id {} cmd {} stage send payload_too_large {}",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  msg.h.stream_id,
                  msg.h.command,
                  msg.payload.size());
        ec = boost::asio::error::message_size;
        co_return;
    }

    if (msg.h.command != mux::kCmdDat || msg.payload.size() < 128)
    {
        LOG_TRACE("event {} conn_id {} local {}:{} remote {}:{} stream_id {} cmd {} payload_size {} send frame",
                  log_event::kMuxFrame,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  msg.h.stream_id,
                  msg.h.command,
                  msg.payload.size());
    }

    co_await net::wait_send_with_timeout<mux_frame>(*write_channel_, std::move(msg), timeout_sec, ec);
    if (ec)
    {
        if (is_expected_mux_channel_shutdown(ec))
        {
            co_return;
        }
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stream_id {} cmd {} stage send error {}",
                  log_event::kMux,
                  cid_,
                  local_host(),
                  local_port_,
                  remote_host(),
                  remote_port_,
                  msg.h.stream_id,
                  msg.h.command,
                  ec.message());
        co_return;
    }
    co_return;
}

uint32_t mux_connection::acquire_next_id()
{
    const std::size_t max_attempts = (((cfg_.limits.max_streams > 0) ? cfg_.limits.max_streams : (streams_.size() + 1)) * 2) + 2;

    for (std::size_t i = 0; i < max_attempts; ++i)
    {
        next_stream_id_ += 2;
        if (next_stream_id_ == mux::kStreamIdHeartbeat)
        {
            continue;
        }
        if (!streams_.contains(next_stream_id_))
        {
            return next_stream_id_;
        }
    }

    LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} stage acquire_stream_id exhausted",
              log_event::kMux,
              cid_,
              local_host(),
              local_port_,
              remote_host(),
              remote_port_);
    return mux::kStreamIdHeartbeat;
}

}    // namespace mux
