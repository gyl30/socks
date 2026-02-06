#include <span>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <ranges>
#include <string>
#include <vector>
#include <random>
#include <cstdint>
#include <utility>
#include <system_error>

extern "C"
{
#include <openssl/rand.h>
}

#include <asio/write.hpp>
#include <asio/error.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "mux_protocol.h"
#include "reality_core.h"
#include "mux_connection.h"

namespace mux
{

mux_connection::mux_connection(asio::ip::tcp::socket socket,
                               reality_engine engine,
                               const bool is_client,
                               const std::uint32_t conn_id,
                               const std::string& trace_id,
                               const config::timeout_t& timeout_cfg,
                               const config::limits_t& limits_cfg,
                               const config::heartbeat_t& heartbeat_cfg)
    : cid_(conn_id),
      timer_(socket.get_executor()),
      socket_(std::move(socket)),
      reality_engine_(std::move(engine)),
      next_stream_id_(is_client ? 1 : 2),
      connection_state_(mux_connection_state::connected),
      write_channel_(socket_.get_executor(), 1024),
      timeout_config_(timeout_cfg),
      limits_config_(limits_cfg),
      heartbeat_config_(heartbeat_cfg)
{
    ctx_.trace_id(trace_id);
    ctx_.conn_id(conn_id);
    std::error_code ec;
    const auto local_ep = socket_.local_endpoint(ec);
    const auto remote_ep = socket_.remote_endpoint(ec);
    if (!ec)
    {
        ctx_.local_addr(local_ep.address().to_string());
        ctx_.local_port(local_ep.port());
        ctx_.remote_addr(remote_ep.address().to_string());
        ctx_.remote_port(remote_ep.port());
    }
    mux_dispatcher_.set_callback([this](const mux::frame_header h, std::vector<std::uint8_t> p) { this->on_mux_frame(h, std::move(p)); });
    mux_dispatcher_.set_context(ctx_);
    LOG_CTX_INFO(ctx_, "{} mux initialized {}", log_event::kConnInit, ctx_.connection_info());
}

void mux_connection::register_stream(const std::uint32_t id, std::shared_ptr<mux_stream_interface> stream)
{
    const std::scoped_lock lock(streams_mutex_);
    streams_[id] = std::move(stream);
    LOG_DEBUG("mux {} stream {} registered", cid_, id);
}

void mux_connection::remove_stream(const std::uint32_t id)
{
    const std::scoped_lock lock(streams_mutex_);
    streams_.erase(id);
    LOG_DEBUG("mux {} stream {} removed", cid_, id);
}

asio::awaitable<void> mux_connection::start()
{
    const auto self = shared_from_this();
    LOG_DEBUG("mux {} started loops", cid_);
    using asio::experimental::awaitable_operators::operator||;
    last_read_time_ = std::chrono::steady_clock::now();
    last_write_time_ = std::chrono::steady_clock::now();
    co_await (read_loop() || write_loop() || timeout_loop() || heartbeat_loop());
    LOG_INFO("mux {} loops finished stopped", cid_);
    stop();
}

asio::awaitable<std::error_code> mux_connection::send_async(const std::uint32_t stream_id, const std::uint8_t cmd, std::vector<std::uint8_t> payload)
{
    if (connection_state_.load(std::memory_order_acquire) != mux_connection_state::connected)
    {
        co_return asio::error::operation_aborted;
    }

    if (cmd != mux::kCmdDat || payload.size() < 128)
    {
        LOG_TRACE("mux {} send frame stream {} cmd {} size {}", cid_, stream_id, cmd, payload.size());
    }

    mux_write_msg msg{.command = cmd, .stream_id = stream_id, .payload = std::move(payload)};
    const auto [ec] = co_await write_channel_.async_send(std::error_code{}, std::move(msg), asio::as_tuple(asio::use_awaitable));

    if (ec)
    {
        LOG_ERROR("mux {} send failed error {}", cid_, ec.message());
        co_return ec;
    }
    co_return std::error_code();
}

void mux_connection::stop()
{
    mux_connection_state expected = mux_connection_state::connected;
    if (!connection_state_.compare_exchange_strong(expected, mux_connection_state::closing, std::memory_order_acq_rel))
    {
        return;
    }

    LOG_INFO("mux {} stopping", cid_);

    stream_map_t streams_to_clear;
    {
        const std::scoped_lock lock(streams_mutex_);
        streams_to_clear = std::move(streams_);
    }

    for (auto& stream : streams_to_clear | std::views::values)
    {
        if (stream != nullptr)
        {
            stream->on_close();
        }
    }

    streams_to_clear.clear();

    if (socket_.is_open())
    {
        std::error_code ec;
        ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec)
        {
            LOG_WARN("mux {} shutdown failed error {}", cid_, ec.message());
        }
        ec = socket_.close(ec);
        if (ec)
        {
            LOG_WARN("mux {} close failed error {}", cid_, ec.message());
        }
    }
    LOG_INFO("mux write channel {} close", cid_);
    write_channel_.close();
    LOG_INFO("mux timer {} cancel", cid_);
    timer_.cancel();
    connection_state_.store(mux_connection_state::closed, std::memory_order_release);
}

asio::awaitable<void> mux_connection::read_loop()
{
    while (is_open())
    {
        const auto buf = reality_engine_.read_buffer(8192);

        const auto [read_ec, n] = co_await socket_.async_read_some(buf, asio::as_tuple(asio::use_awaitable));

        if (read_ec || n == 0)
        {
            if (read_ec != asio::error::eof && read_ec != asio::error::operation_aborted)
            {
                LOG_ERROR("mux {} read error {}", cid_, read_ec.message());
            }
            break;
        }
        read_bytes_ += n;
        last_read_time_ = std::chrono::steady_clock::now();

        reality_engine_.commit_read(n);

        std::error_code decrypt_ec;

        reality_engine_.process_available_records(decrypt_ec,
                                                  [this](const std::uint8_t type, const std::span<const std::uint8_t> pt)
                                                  {
                                                      if (type == reality::kContentTypeApplicationData && !pt.empty())
                                                      {
                                                          mux_dispatcher_.on_plaintext_data(pt);
                                                      }
                                                  });

        if (decrypt_ec)
        {
            LOG_ERROR("mux {} decrypt protocol error {}", cid_, decrypt_ec.message());
            break;
        }
    }
    LOG_DEBUG("mux {} read loop finished", cid_);
    stop();
}

asio::awaitable<void> mux_connection::write_loop()
{
    while (is_open())
    {
        const auto [ec, msg] = co_await write_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            break;
        }

        const auto mux_frame = mux_dispatcher::pack(msg.stream_id, msg.command, msg.payload);
        std::error_code enc_ec;

        const auto ciphertext_span = reality_engine_.encrypt(mux_frame, enc_ec);

        if (enc_ec)
        {
            LOG_ERROR("mux {} encrypt error {}", cid_, enc_ec.message());
            break;
        }

        const auto [wec, n] =
            co_await asio::async_write(socket_, asio::buffer(ciphertext_span.data(), ciphertext_span.size()), asio::as_tuple(asio::use_awaitable));

        if (wec)
        {
            LOG_ERROR("mux {} write error {}", cid_, wec.message());
            break;
        }
        write_bytes_ += n;
        last_write_time_ = std::chrono::steady_clock::now();
    }
    LOG_DEBUG("mux {} write loop finished", cid_);
    stop();
}

asio::awaitable<void> mux_connection::timeout_loop()
{
    static thread_local std::mt19937 rng(std::random_device{}());

    while (is_open())
    {
        timer_.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            if (ec == asio::error::operation_aborted)
            {
                LOG_DEBUG("mux {} timeout timer cancelled", cid_);
            }
            else
            {
                LOG_WARN("mux {} timeout error {}", cid_, ec.message());
            }
            break;
        }

        const auto state = connection_state_.load(std::memory_order_acquire);
        if (state == mux_connection_state::draining)
        {
            continue;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto read_elapsed = now - last_read_time_;
        const auto write_elapsed = now - last_write_time_;

        if (read_elapsed > std::chrono::seconds(timeout_config_.read) || write_elapsed > std::chrono::seconds(timeout_config_.write))
        {
            LOG_DEBUG("mux {} entering draining mode", cid_);
            connection_state_.store(mux_connection_state::draining, std::memory_order_release);

            std::uniform_int_distribution<std::uint32_t> delay_dist(5, 30);
            const auto delay = delay_dist(rng);
            timer_.expires_after(std::chrono::seconds(delay));

            const auto [wait_ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
            if (!wait_ec)
            {
                LOG_DEBUG("mux {} draining complete after {}s", cid_, delay);
            }
            break;
        }
    }

    LOG_DEBUG("mux {} timeout loop finished", cid_);
    stop();
}

asio::awaitable<void> mux_connection::heartbeat_loop()
{
    if (!heartbeat_config_.enabled)
    {
        co_return;
    }

    static thread_local std::mt19937 rng(std::random_device{}());
    asio::steady_timer heartbeat_timer(socket_.get_executor());

    while (is_open())
    {
        std::uniform_int_distribution<std::uint32_t> interval_dist(heartbeat_config_.min_interval, heartbeat_config_.max_interval);
        const auto interval = interval_dist(rng);
        heartbeat_timer.expires_after(std::chrono::seconds(interval));

        const auto [ec] = co_await heartbeat_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now - last_write_time_ < std::chrono::seconds(10))
        {
            continue;
        }

        std::uniform_int_distribution<std::uint32_t> padding_dist(heartbeat_config_.min_padding, heartbeat_config_.max_padding);
        const auto padding_len = padding_dist(rng);
        std::vector<std::uint8_t> padding(padding_len);
        RAND_bytes(padding.data(), static_cast<int>(padding_len));

        LOG_TRACE("mux {} sending heartbeat size {}", cid_, padding_len);
        (void)co_await send_async(mux::kStreamIdHeartbeat, mux::kCmdDat, std::move(padding));
    }

    LOG_DEBUG("mux {} heartbeat loop finished", cid_);
}

void mux_connection::on_mux_frame(const mux::frame_header header, std::vector<std::uint8_t> payload)
{
    LOG_TRACE("mux {} recv frame stream {} cmd {} len {} payload size {}", cid_, header.stream_id, header.command, header.length, payload.size());

    if (header.stream_id == mux::kStreamIdHeartbeat)
    {
        LOG_TRACE("mux {} heartbeat received size {}", cid_, payload.size());
        return;
    }

    if (header.command == mux::kCmdSyn)
    {
        if (syn_callback_ != nullptr)
        {
            syn_callback_(header.stream_id, std::move(payload));
        }
        return;
    }

    std::shared_ptr<mux_stream_interface> stream = nullptr;
    {
        const std::scoped_lock lock(streams_mutex_);
        const auto it = streams_.find(header.stream_id);
        if (it != streams_.end())
        {
            stream = it->second;
        }
    }

    if (stream != nullptr)
    {
        if (header.command == mux::kCmdFin)
        {
            stream->on_close();
        }
        else if (header.command == mux::kCmdRst)
        {
            stream->on_reset();
        }
        else if (header.command == mux::kCmdDat || header.command == mux::kCmdAck)
        {
            stream->on_data(std::move(payload));
        }
    }
    else
    {
        if (header.command != mux::kCmdRst)
        {
            LOG_DEBUG("mux {} recv frame for unknown stream {}", cid_, header.stream_id);
        }
    }
}

}    // namespace mux
