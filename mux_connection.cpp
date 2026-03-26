#include <span>
#include <algorithm>
#include <chrono>
#include <memory>
#include <random>
#include <ranges>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/rand.h>
}

#include "log.h"
#include "config.h"
#include "mux_stream.h"
#include "timeout_io.h"
#include "connection_context.h"
#include "mux_protocol.h"
#include "mux_codec.h"
#include "mux_connection.h"
#include "reality/session/engine.h"
#include "reality/session/session_internal.h"

namespace mux
{

namespace
{

constexpr std::uint32_t kControlFrameSendTimeoutSec = 1;
constexpr std::uint8_t kHandshakeTypeNewSessionTicket = 0x04;
constexpr std::uint8_t kHandshakeTypeKeyUpdate = 0x18;

[[nodiscard]] bool track_stream_write_budget(const std::uint32_t stream_id, const std::uint8_t command)
{
    return command == mux::kCmdDat && stream_id != mux::kStreamIdHeartbeat;
}

void handle_post_handshake_record(const std::uint32_t cid,
                                  const std::span<const std::uint8_t> plaintext,
                                  boost::system::error_code& ec)
{
    ec.clear();
    if (plaintext.empty())
    {
        LOG_WARN("mux {} empty post handshake record", cid);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    const auto handshake_type = plaintext.front();
    if (handshake_type == kHandshakeTypeNewSessionTicket)
    {
        LOG_DEBUG("mux {} ignore new session ticket", cid);
        return;
    }
    if (handshake_type == kHandshakeTypeKeyUpdate)
    {
        LOG_WARN("mux {} key update unsupported", cid);
        ec = boost::asio::error::operation_not_supported;
        return;
    }

    LOG_WARN("mux {} unsupported post handshake type {}", cid, handshake_type);
    ec = boost::asio::error::invalid_argument;
}

}    // namespace

mux_connection::mux_connection(boost::asio::ip::tcp::socket socket,
                               boost::asio::io_context& io_context,
                               reality::reality_session session,
                               const config& cfg,
                               task_group& group,
                               const std::uint32_t conn_id,
                               const std::string& trace_id)
    : cfg_(cfg),
      cid_(conn_id),
      group_(group),
      reality_engine_(reality::session_internal::engine_access::take_engine(std::move(session))),
      io_context_(io_context),
      socket_(std::move(socket)),
      write_channel_(std::make_unique<channel_type>(io_context_, 1024)),
      stop_channel_(std::make_unique<stop_channel_type>(io_context_, 1))
{
    ctx_.trace_id(trace_id);
    ctx_.conn_id(conn_id);

    boost::system::error_code local_ep_ec;
    const auto local_ep = socket_.local_endpoint(local_ep_ec);
    if (!local_ep_ec)
    {
        ctx_.local_addr(local_ep.address().to_string());
        ctx_.local_port(local_ep.port());
    }

    boost::system::error_code remote_ep_ec;
    const auto remote_ep = socket_.remote_endpoint(remote_ep_ec);
    if (!remote_ep_ec)
    {
        ctx_.remote_addr(remote_ep.address().to_string());
        ctx_.remote_port(remote_ep.port());
    }
    LOG_CTX_INFO(ctx_, "{} mux initialized {}", log_event::kConnInit, ctx_.connection_info());
}

mux_connection::~mux_connection() = default;

std::uint64_t mux_connection::reserve_pending(const std::uint64_t bytes)
{
    if (bytes == 0)
    {
        return 0;
    }
    const auto limit = cfg_.limits.max_buffer;
    if (limit == 0)
    {
        pending_bytes_total_.fetch_add(bytes, std::memory_order_relaxed);
        return bytes;
    }
    auto cur = pending_bytes_total_.load(std::memory_order_relaxed);
    while (true)
    {
        if (cur >= limit)
        {
            return 0;
        }
        const auto avail = limit - cur;
        const auto grant = (bytes < avail) ? bytes : avail;
        if (grant == 0)
        {
            return 0;
        }
        if (pending_bytes_total_.compare_exchange_weak(cur, cur + grant, std::memory_order_relaxed))
        {
            return grant;
        }
    }
}

void mux_connection::release_pending(const std::uint64_t bytes)
{
    if (bytes == 0)
    {
        return;
    }
    auto cur = pending_bytes_total_.load(std::memory_order_relaxed);
    while (true)
    {
        const auto next = (cur > bytes) ? (cur - bytes) : 0;
        if (pending_bytes_total_.compare_exchange_weak(cur, next, std::memory_order_relaxed))
        {
            return;
        }
    }
}

std::uint64_t mux_connection::reserve_write_bytes(const std::uint64_t bytes)
{
    if (bytes == 0)
    {
        return 0;
    }
    const auto limit = cfg_.limits.max_buffer;
    if (limit == 0)
    {
        write_pending_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        return bytes;
    }
    auto cur = write_pending_bytes_.load(std::memory_order_relaxed);
    while (true)
    {
        if (cur >= limit)
        {
            return 0;
        }
        const auto avail = limit - cur;
        const auto grant = (bytes < avail) ? bytes : avail;
        if (grant == 0)
        {
            return 0;
        }
        if (write_pending_bytes_.compare_exchange_weak(cur, cur + grant, std::memory_order_relaxed))
        {
            return grant;
        }
    }
}

void mux_connection::release_write_bytes(const std::uint64_t bytes)
{
    if (bytes == 0)
    {
        return;
    }
    auto cur = write_pending_bytes_.load(std::memory_order_relaxed);
    while (true)
    {
        const auto next = (cur > bytes) ? (cur - bytes) : 0;
        if (write_pending_bytes_.compare_exchange_weak(cur, next, std::memory_order_relaxed))
        {
            return;
        }
    }
}

std::uint64_t mux_connection::reserve_write_bytes(const std::uint32_t stream_id, const std::uint8_t command, const std::uint64_t bytes)
{
    if (bytes == 0 || !track_stream_write_budget(stream_id, command))
    {
        return bytes;
    }

    const auto limit = std::max<std::uint64_t>(1ULL, cfg_.limits.max_buffer);
    std::lock_guard<std::mutex> lock(write_limit_mutex_);
    auto& used = write_pending_bytes_by_stream_[stream_id];
    if (used >= limit || limit - used < bytes)
    {
        return 0;
    }

    used += bytes;
    return bytes;
}

void mux_connection::release_write_bytes(const std::uint32_t stream_id, const std::uint8_t command, const std::uint64_t bytes)
{
    if (bytes == 0 || !track_stream_write_budget(stream_id, command))
    {
        return;
    }

    std::lock_guard<std::mutex> lock(write_limit_mutex_);
    const auto it = write_pending_bytes_by_stream_.find(stream_id);
    if (it == write_pending_bytes_by_stream_.end())
    {
        return;
    }

    if (it->second > bytes)
    {
        it->second -= bytes;
    }
    else
    {
        it->second = 0;
    }

    if (it->second == 0)
    {
        write_pending_bytes_by_stream_.erase(it);
    }
}

std::shared_ptr<mux_stream> mux_connection::find_stream(const std::uint32_t stream_id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = streams_.find(stream_id);
    if (it != streams_.end())
    {
        return it->second;
    }
    return nullptr;
}

boost::asio::awaitable<void> mux_connection::handle_unknown_stream(mux::frame_header header, std::vector<std::uint8_t> payload)
{
    if (header.command == mux::kCmdRst)
    {
        co_return;
    }

    if (header.command == mux::kCmdSyn)
    {
        bool stream_limit_reached = false;
        if (cfg_.limits.max_streams > 0)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stream_limit_reached = streams_.size() >= cfg_.limits.max_streams;
        }
        if (stream_limit_reached)
        {
            LOG_WARN("mux {} reject stream {} max_streams {}", cid_, header.stream_id, cfg_.limits.max_streams);
            mux_frame rst;
            rst.h.command = mux::kCmdRst;
            rst.h.stream_id = header.stream_id;
            boost::system::error_code rst_ec;
            co_await send_async_with_timeout(std::move(rst), kControlFrameSendTimeoutSec, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("mux {} reject stream {} send rst failed {}", cid_, header.stream_id, rst_ec.message());
            }
            co_return;
        }
        if (cb_)
        {
            mux_frame frame;
            frame.h = header;
            frame.payload = std::move(payload);
            co_return co_await cb_(std::move(frame));
        }
        co_return;
    }

    LOG_DEBUG("mux {} recv frame for unknown stream {}", cid_, header.stream_id);
    mux_frame frame;
    frame.h.command = mux::kCmdRst;
    frame.h.stream_id = header.stream_id;
    boost::system::error_code rst_ec;
    co_await send_async_with_timeout(std::move(frame), kControlFrameSendTimeoutSec, rst_ec);
    if (rst_ec)
    {
        LOG_WARN("mux {} unknown stream {} send rst failed {}", cid_, header.stream_id, rst_ec.message());
    }
}

boost::asio::awaitable<void> mux_connection::handle_stream_frame(const mux::frame_header& header, std::vector<std::uint8_t> payload)
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
            LOG_WARN("mux {} stream {} backpressure timeout reset only this stream", cid_, header.stream_id);
            close_and_remove_stream(stream);

            constexpr std::uint32_t kRstSendTimeoutSec = 1;
            mux_frame rst_frame;
            rst_frame.h.stream_id = header.stream_id;
            rst_frame.h.command = mux::kCmdRst;
            boost::system::error_code rst_ec;
            co_await send_async_with_timeout(std::move(rst_frame), kRstSendTimeoutSec, rst_ec);
            if (rst_ec)
            {
                LOG_WARN("mux {} stream {} send rst failed {}", cid_, header.stream_id, rst_ec.message());
            }
            co_return;
        }

        if (ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor ||
            ec == boost::asio::experimental::error::channel_errors::channel_closed)
        {
            LOG_WARN("mux {} stream {} channel closed drop frame", cid_, header.stream_id);
            close_and_remove_stream(stream);
            co_return;
        }

        LOG_ERROR("mux {} deliver frame to stream {} failed {}", cid_, header.stream_id, ec.message());
        stop();
    }
}

void mux_connection::remove_stream(const std::shared_ptr<mux_stream>& stream)
{
    const auto stream_id = stream->id();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        streams_.erase(stream_id);
    }
    {
        std::lock_guard<std::mutex> lock(write_limit_mutex_);
        write_pending_bytes_by_stream_.erase(stream_id);
    }
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
    auto self = shared_from_this();
    const auto now_ms = timeout_io::now_ms();
    last_read_time_ms_ = now_ms;
    last_write_time_ms_ = now_ms;
    last_non_heartbeat_read_time_ms_ = now_ms;
    last_non_heartbeat_write_time_ms_ = now_ms;
    boost::asio::co_spawn(io_context_, [this, self]() -> boost::asio::awaitable<void> { co_await run_loop(); }, group_.adapt(boost::asio::detached));
}

boost::asio::awaitable<void> mux_connection::run_loop()
{
    LOG_DEBUG("mux {} started loops", cid_);
    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.heartbeat.enabled)
    {
        if (cfg_.timeout.idle == 0)
        {
            co_await (read_loop() || write_loop() || heartbeat_loop());
        }
        else
        {
            co_await (read_loop() || write_loop() || timeout_loop() || heartbeat_loop());
        }
    }
    else
    {
        if (cfg_.timeout.idle == 0)
        {
            co_await (read_loop() || write_loop());
        }
        else
        {
            co_await (read_loop() || write_loop() || timeout_loop());
        }
    }
    stop();
    LOG_INFO("mux {} loops finished stopped", cid_);
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
        std::lock_guard<std::mutex> lock(mutex_);
        streams_to_close.reserve(streams_.size());
        for (const auto& [_, stream] : streams_)
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

    {
        std::lock_guard<std::mutex> lock(write_limit_mutex_);
        write_pending_bytes_by_stream_.clear();
    }
    write_pending_bytes_.store(0, std::memory_order_relaxed);

    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = socket_.close(ec);

    if (stop_channel_ != nullptr)
    {
        stop_channel_->close();
    }
}

bool mux_connection::is_active() const { return !stopped_.load(std::memory_order_relaxed); }

boost::asio::awaitable<void> mux_connection::async_wait_stopped()
{
    if (stop_channel_ == nullptr)
    {
        co_return;
    }

    const auto [ec] = co_await stop_channel_->async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec && ec != boost::asio::experimental::error::channel_errors::channel_closed &&
        ec != boost::asio::experimental::error::channel_errors::channel_cancelled &&
        ec != boost::asio::error::operation_aborted)
    {
        LOG_WARN("mux {} wait stopped error {}", cid_, ec.message());
    }
}

boost::asio::awaitable<void> mux_connection::read_loop()
{
    boost::system::error_code ec;
    while (true)
    {
        const auto buf = reality_engine_.read_buffer(8192, ec);
        if (ec)
        {
            LOG_ERROR("mux {} read buffer error {}", cid_, ec.message());
            break;
        }
        const auto n = co_await socket_.async_read_some(buf, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("mux {} read error {}", cid_, ec.message());
            break;
        }

        read_bytes_ += n;
        last_read_time_ms_ = timeout_io::now_ms();
        reality_engine_.commit_read(n);

        co_await reality_engine_.process_available_records(
            [this](
                const std::uint8_t type, const std::span<const std::uint8_t> plaintext, boost::system::error_code& ec) -> boost::asio::awaitable<void>
            {
                if (type == ::tls::kContentTypeApplicationData)
                {
                    std::vector<mux_frame> frames;
                    mux_codec::decode_frames(pending_plaintext_, plaintext, cfg_.limits.max_buffer, frames, ec);
                    if (ec)
                    {
                        LOG_CTX_ERROR(ctx_, "{} mux decode failed {}", log_event::kMux, ec.message());
                        co_return;
                    }
                    for (auto& frame : frames)
                    {
                        co_await on_mux_frame(frame.h, std::move(frame.payload));
                    }
                    co_return;
                }
                if (type == ::tls::kContentTypeAlert)
                {
                    co_return;
                }
                if (type == ::tls::kContentTypeHandshake)
                {
                    handle_post_handshake_record(cid_, plaintext, ec);
                    co_return;
                }

                LOG_WARN("mux {} unsupported record type {}", cid_, type);
                ec = boost::asio::error::invalid_argument;
            },
            ec);
        if (ec)
        {
            LOG_ERROR("mux {} process_decrypted_records error {}", cid_, ec.message());
            break;
        }
    }
    LOG_DEBUG("mux {} read loop finished", cid_);
}

boost::asio::awaitable<void> mux_connection::write_loop()
{
    while (true)
    {
        const auto [re, msg] = co_await write_channel_->async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re)
        {
            break;
        }
        if (!msg.payload.empty())
        {
            release_write_bytes(msg.payload.size());
            release_write_bytes(msg.h.stream_id, msg.h.command, msg.payload.size());
        }

        frame_header header = msg.h;
        header.length = static_cast<std::uint16_t>(msg.payload.size());
        const auto mux_frame = mux_codec::encode_frame(header, msg.payload);

        boost::system::error_code encrypt_ec;
        const auto ct = reality_engine_.encrypt(mux_frame, encrypt_ec);
        if (encrypt_ec)
        {
            LOG_ERROR("mux {} encrypt error {}", cid_, encrypt_ec.message());
            break;
        }

        boost::system::error_code write_ec;
        const auto n =
            co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(ct.data(), ct.size()), cfg_.timeout.write, write_ec);
        if (!write_ec && n != ct.size())
        {
            write_ec = boost::asio::error::fault;
        }
        const auto& we = write_ec;
        if (we)
        {
            LOG_ERROR("mux {} write error {}", cid_, we.message());
            break;
        }
        write_bytes_ += n;
        last_write_time_ms_ = timeout_io::now_ms();
        if (msg.h.stream_id != mux::kStreamIdHeartbeat)
        {
            last_non_heartbeat_write_time_ms_ = last_write_time_ms_;
        }
    }
    LOG_DEBUG("mux {} write loop finished", cid_);
}

boost::asio::awaitable<void> mux_connection::timeout_loop()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

    auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;
    if (cfg_.heartbeat.enabled && cfg_.heartbeat.idle_timeout > 0 && cfg_.heartbeat.max_interval > 0)
    {
        const auto heartbeat_guard_ms =
            (static_cast<std::uint64_t>(cfg_.heartbeat.idle_timeout) + static_cast<std::uint64_t>(cfg_.heartbeat.max_interval)) * 1000ULL;
        if (heartbeat_guard_ms > idle_timeout_ms)
        {
            idle_timeout_ms = heartbeat_guard_ms;
        }
    }
    boost::system::error_code ec;
    boost::asio::steady_timer timer{io_context_};
    while (true)
    {
        timer.expires_after(std::chrono::seconds(1));
        co_await timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }
        const auto now_ms = timeout_io::now_ms();
        const auto read_diff = now_ms - last_non_heartbeat_read_time_ms_;
        const auto write_diff = now_ms - last_non_heartbeat_write_time_ms_;
        if (read_diff > idle_timeout_ms && write_diff > idle_timeout_ms)
        {
            break;
        }
    }

    LOG_DEBUG("mux {} timeout loop finished", cid_);
    stop();
}

boost::asio::awaitable<void> mux_connection::heartbeat_loop()
{
    static thread_local std::mt19937 rng(std::random_device{}());
    boost::asio::steady_timer heartbeat_timer(io_context_);

    while (true)
    {
        std::uniform_int_distribution<std::uint32_t> interval_dist(cfg_.heartbeat.min_interval, cfg_.heartbeat.max_interval);
        const auto interval = interval_dist(rng);
        heartbeat_timer.expires_after(std::chrono::seconds(interval));
        const auto [ec] = co_await heartbeat_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            break;
        }

        const auto write_elapsed_ms = timeout_io::now_ms() - last_write_time_ms_;
        const auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.heartbeat.idle_timeout) * 1000ULL;
        if (write_elapsed_ms < idle_timeout_ms)
        {
            continue;
        }

        std::uniform_int_distribution<std::uint32_t> padding_dist(cfg_.heartbeat.min_padding, cfg_.heartbeat.max_padding);
        const auto padding_len = padding_dist(rng);
        const auto heartbeat_padding_len = std::min<std::size_t>(padding_len, mux::kMaxPayload);
        std::vector<std::uint8_t> padding(heartbeat_padding_len);
        if (heartbeat_padding_len > 0 &&
            RAND_bytes(padding.data(), static_cast<int>(heartbeat_padding_len)) != 1)
        {
            LOG_ERROR("mux {} heartbeat rand failed", cid_);
            break;
        }

        LOG_DEBUG("mux {} sending heartbeat size {}", cid_, heartbeat_padding_len);
        {
            mux_frame msg;
            msg.h.stream_id = mux::kStreamIdHeartbeat;
            msg.h.command = mux::kCmdDat;
            msg.payload = std::move(padding);
            boost::system::error_code ec;
            co_await send_async(std::move(msg), ec);
        }
    }

    LOG_DEBUG("mux {} heartbeat loop finished", cid_);
}

boost::asio::awaitable<void> mux_connection::on_mux_frame(const mux::frame_header header, std::vector<std::uint8_t> payload)
{
    LOG_TRACE("mux {} recv frame stream {} cmd {} len {} payload size {}", cid_, header.stream_id, header.command, header.length, payload.size());

    if (header.stream_id == mux::kStreamIdHeartbeat)
    {
        LOG_DEBUG("mux {} heartbeat received size {}", cid_, payload.size());
        co_return;
    }
    last_non_heartbeat_read_time_ms_ = timeout_io::now_ms();

    co_return co_await handle_stream_frame(header, std::move(payload));
}

std::shared_ptr<mux_stream> mux_connection::create_stream()
{
    std::shared_ptr<mux_stream> stream;
    std::uint32_t stream_id = mux::kStreamIdHeartbeat;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cfg_.limits.max_streams > 0 && streams_.size() >= cfg_.limits.max_streams)
        {
            LOG_WARN("mux {} create stream rejected max_streams {}", cid_, cfg_.limits.max_streams);
            return nullptr;
        }
        stream_id = acquire_next_id();
        if (stream_id != mux::kStreamIdHeartbeat)
        {
            stream = std::make_shared<mux_stream>(stream_id, cfg_, io_context_, shared_from_this());
            streams_.emplace(stream_id, stream);
        }
    }
    if (stream_id == mux::kStreamIdHeartbeat)
    {
        LOG_ERROR("mux {} stream id exhausted closing connection", cid_);
        stop();
        return nullptr;
    }
    return stream;
}

void mux_connection::register_stream(const std::shared_ptr<mux_stream>& stream)
{
    if (stream == nullptr)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    streams_[stream->id()] = stream;
}

boost::asio::awaitable<void> mux_connection::send_async(mux_frame msg, boost::system::error_code& ec)
{
    co_return co_await send_async_with_timeout(std::move(msg), 0, ec);
}

boost::asio::awaitable<void> mux_connection::send_async_with_timeout(mux_frame msg, const std::uint32_t timeout_sec, boost::system::error_code& ec)
{
    if (msg.payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("mux {} payload too large {}", cid_, msg.payload.size());
        ec = boost::asio::error::message_size;
        co_return;
    }

    const auto payload_len = msg.payload.size();
    std::uint64_t stream_reserved = 0;
    if (payload_len > 0)
    {
        stream_reserved = reserve_write_bytes(msg.h.stream_id, msg.h.command, payload_len);
        if (stream_reserved != payload_len)
        {
            ec = boost::asio::error::no_buffer_space;
            co_return;
        }
    }

    std::uint64_t reserved = 0;
    if (payload_len > 0)
    {
        reserved = reserve_write_bytes(payload_len);
        if (reserved != payload_len)
        {
            if (reserved > 0)
            {
                release_write_bytes(reserved);
            }
            if (stream_reserved > 0)
            {
                release_write_bytes(msg.h.stream_id, msg.h.command, stream_reserved);
            }
            ec = boost::asio::error::no_buffer_space;
            co_return;
        }
    }

    if (msg.h.command != mux::kCmdDat || msg.payload.size() < 128)
    {
        LOG_TRACE("mux {} send frame stream {} cmd {} size {}", cid_, msg.h.stream_id, msg.h.command, msg.payload.size());
    }

    const auto saved_stream_id = msg.h.stream_id;
    const auto saved_command = msg.h.command;
    co_await timeout_io::wait_send_with_timeout<mux_frame>(*write_channel_, std::move(msg), timeout_sec, ec);
    if (ec)
    {
        if (reserved > 0)
        {
            release_write_bytes(reserved);
        }
        if (stream_reserved > 0)
        {
            release_write_bytes(saved_stream_id, saved_command, stream_reserved);
        }
        LOG_ERROR("mux {} send failed error {}", cid_, ec.message());
        co_return;
    }
    co_return;
}

std::uint32_t mux_connection::acquire_next_id()
{
    const std::size_t max_attempts =
        (cfg_.limits.max_streams > 0 ? cfg_.limits.max_streams : (streams_.size() + 1)) * 2 + 2;

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

    LOG_ERROR("mux {} stream id exhausted", cid_);
    return mux::kStreamIdHeartbeat;
}

}    // namespace mux
