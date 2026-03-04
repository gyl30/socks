#include <span>
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
#include <boost/asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/rand.h>
}

#include "log.h"
#include "config.h"
#include "mux_stream.h"
#include "timeout_io.h"
#include "statistics.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "reality_core.h"
#include "mux_connection.h"
#include "reality_engine.h"

namespace mux
{

mux_connection::mux_connection(boost::asio::ip::tcp::socket socket,
                               boost::asio::io_context& io_context,
                               reality_engine engine,
                               const config& cfg,
                               task_group& group,
                               const std::uint32_t conn_id,
                               const std::string& trace_id)
    : cfg_(cfg),
      cid_(conn_id),
      group_(group),
      reality_engine_(std::move(engine)),
      io_context_(io_context),
      socket_(std::move(socket)),
      write_channel_(std::make_unique<channel_type>(io_context_, 1024))
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
    mux_dispatcher_.set_context(ctx_);
    mux_dispatcher_.set_max_buffer(cfg_.limits.max_buffer);
    mux_dispatcher_.set_callback([this](const auto h, auto p) -> boost::asio::awaitable<void> { co_return co_await on_mux_frame(h, std::move(p)); });
    statistics::instance().inc_active_mux_sessions();
    LOG_CTX_INFO(ctx_, "{} mux initialized {}", log_event::kConnInit, ctx_.connection_info());
}

mux_connection::~mux_connection() { statistics::instance().dec_active_mux_sessions(); }

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
            co_await write_channel_->async_send({}, rst, boost::asio::as_tuple(boost::asio::use_awaitable));
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
    co_await write_channel_->async_send({}, frame, boost::asio::as_tuple(boost::asio::use_awaitable));
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
        LOG_ERROR("mux {} deliver frame to stream {} failed {}", cid_, header.stream_id, ec.message());
        stop();
    }
}

void mux_connection::remove_stream(const std::shared_ptr<mux_stream>& stream)
{
    std::lock_guard<std::mutex> lock(mutex_);
    streams_.erase(stream->id());
}

void mux_connection::start()
{
    auto self = shared_from_this();
    last_read_time_ms_ = timeout_io::now_ms();
    last_write_time_ms_ = timeout_io::now_ms();
    boost::asio::co_spawn(io_context_, [this, self]() -> boost::asio::awaitable<void> { co_await run_loop(); }, group_.adapt(boost::asio::detached));
}

boost::asio::awaitable<void> mux_connection::run_loop()
{
    LOG_DEBUG("mux {} started loops", cid_);
    using boost::asio::experimental::awaitable_operators::operator||;
    co_await (read_loop() || write_loop() || timeout_loop() || heartbeat_loop());
    stop();
    LOG_INFO("mux {} loops finished stopped", cid_);
}

void mux_connection::stop()
{
    if (write_channel_ != nullptr)
    {
        write_channel_->close();
    }

    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = socket_.close(ec);
}

bool mux_connection::is_active() const { return socket_.is_open(); }

boost::asio::awaitable<void> mux_connection::read_loop()
{
    boost::system::error_code ec;
    while (true)
    {
        const auto buf = reality_engine_.read_buffer(8192);
        const auto n = co_await socket_.async_read_some(buf, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("mux {} read error {}", cid_, ec.message());
            break;
        }

        read_bytes_ += n;
        statistics::instance().add_bytes_read(n);
        last_read_time_ms_ = timeout_io::now_ms();
        reality_engine_.commit_read(n);

        co_await reality_engine_.process_available_records(
            [this](
                const std::uint8_t type, const std::span<const std::uint8_t> plaintext, boost::system::error_code& ec) -> boost::asio::awaitable<void>
            {
                if (type == reality::kContentTypeApplicationData)
                {
                    co_await mux_dispatcher_.on_plaintext_data(plaintext, ec);
                    if (ec)
                    {
                        co_return;
                    }
                }
                if (type == reality::kContentTypeAlert)
                {
                    co_return;
                }
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

        const auto mux_frame = mux_dispatcher::pack(msg.h.stream_id, msg.h.command, msg.payload);

        boost::system::error_code encrypt_ec;
        const auto ct = reality_engine_.encrypt(mux_frame, encrypt_ec);
        if (encrypt_ec)
        {
            LOG_ERROR("mux {} encrypt error {}", cid_, encrypt_ec.message());
            break;
        }

        const auto [we, n] = co_await boost::asio::async_write(socket_, boost::asio::buffer(ct), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            LOG_ERROR("mux {} write error {}", cid_, we.message());
            break;
        }
        write_bytes_ += n;
        statistics::instance().add_bytes_written(n);
        last_write_time_ms_ = timeout_io::now_ms();
    }
    LOG_DEBUG("mux {} write loop finished", cid_);
}

boost::asio::awaitable<void> mux_connection::timeout_loop()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

    const auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;
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
        const auto read_diff = now_ms - last_read_time_ms_;
        const auto write_diff = now_ms - last_write_time_ms_;
        if (read_diff > idle_timeout_ms || write_diff > idle_timeout_ms)
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
        std::vector<std::uint8_t> padding(padding_len);
        if (padding_len > 0 && RAND_bytes(padding.data(), static_cast<int>(padding_len)) != 1)
        {
            LOG_ERROR("mux {} heartbeat rand failed", cid_);
            break;
        }

        LOG_DEBUG("mux {} sending heartbeat size {}", cid_, padding_len);
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

    co_return co_await handle_stream_frame(header, std::move(payload));
}

std::shared_ptr<mux_stream> mux_connection::create_stream()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (cfg_.limits.max_streams > 0 && streams_.size() >= cfg_.limits.max_streams)
    {
        LOG_WARN("mux {} create stream rejected max_streams {}", cid_, cfg_.limits.max_streams);
        return nullptr;
    }
    const std::uint32_t stream_id = acquire_next_id();
    auto stream = std::make_shared<mux_stream>(stream_id, cfg_, io_context_, shared_from_this());
    streams_.emplace(stream_id, stream);
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
    if (msg.payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("mux {} payload too large {}", cid_, msg.payload.size());
        ec = boost::asio::error::message_size;
        co_return;
    }
    if (msg.payload.size() > mux::kMaxPayloadPerRecord)
    {
        LOG_ERROR("mux {} payload too large for single record {} max {}", cid_, msg.payload.size(), mux::kMaxPayloadPerRecord);
        ec = boost::asio::error::message_size;
        co_return;
    }

    if (msg.h.command != mux::kCmdDat || msg.payload.size() < 128)
    {
        LOG_TRACE("mux {} send frame stream {} cmd {} size {}", cid_, msg.h.stream_id, msg.h.command, msg.payload.size());
    }

    co_await write_channel_->async_send(boost::system::error_code{}, std::move(msg), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        LOG_ERROR("mux {} send failed error {}", cid_, ec.message());
        co_return;
    }
    co_return;
}

std::uint32_t mux_connection::acquire_next_id()
{
    for (;;)
    {
        next_stream_id_ += 2;
        if (next_stream_id_ != mux::kStreamIdHeartbeat)
        {
            return next_stream_id_;
        }
    }
}

}    // namespace mux
