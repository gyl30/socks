#include <span>
#include <atomic>
#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <random>
#include <ranges>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/dispatch.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>
#include <asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/rand.h>
}

#include "log.h"
#include "statistics.h"
#include "mux_protocol.h"
#include "reality_core.h"
#include "mux_stream.h"
#include "mux_connection.h"

namespace mux
{

namespace
{

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct timeout_snapshot
{
    std::uint64_t read_elapsed_ms = 0;
    std::uint64_t write_elapsed_ms = 0;
    std::uint64_t read_timeout_ms = 0;
    std::uint64_t write_timeout_ms = 0;
};

bool handle_timeout_wait_error(const std::error_code& ec, const std::uint32_t cid)
{
    if (!ec)
    {
        return false;
    }
    if (ec == asio::error::operation_aborted)
    {
        LOG_DEBUG("mux {} timeout timer cancelled", cid);
    }
    else
    {
        LOG_WARN("mux {} timeout error {}", cid, ec.message());
    }
    return true;
}

timeout_snapshot collect_timeout_snapshot(const std::atomic<std::uint64_t>& last_read_time_ms,
                                          const std::atomic<std::uint64_t>& last_write_time_ms,
                                          const config::timeout_t& timeout_config)
{
    const auto current_ms = now_ms();
    return timeout_snapshot{
        .read_elapsed_ms = current_ms - last_read_time_ms.load(std::memory_order_acquire),
        .write_elapsed_ms = current_ms - last_write_time_ms.load(std::memory_order_acquire),
        .read_timeout_ms = static_cast<std::uint64_t>(timeout_config.read) * 1000ULL,
        .write_timeout_ms = static_cast<std::uint64_t>(timeout_config.write) * 1000ULL,
    };
}

[[nodiscard]] bool is_timeout_exceeded(const timeout_snapshot& snapshot)
{
    return snapshot.read_elapsed_ms > snapshot.read_timeout_ms || snapshot.write_elapsed_ms > snapshot.write_timeout_ms;
}

[[nodiscard]] std::uint32_t pick_draining_delay_seconds(std::mt19937& rng)
{
    std::uniform_int_distribution<std::uint32_t> delay_dist(5, 30);
    return delay_dist(rng);
}

template <typename Fn>
bool run_sync_bool_query(asio::io_context& io_context, Fn&& fn)
{
    if (io_context.stopped())
    {
        return false;
    }
    if (io_context.get_executor().running_in_this_thread())
    {
        return std::forward<Fn>(fn)();
    }

    std::promise<bool> promise;
    auto future = promise.get_future();
    asio::post(
        io_context,
        [promise = std::move(promise), fn = std::forward<Fn>(fn)]() mutable
        {
            try
            {
                promise.set_value(fn());
            }
            catch (...)
            {
                promise.set_exception(std::current_exception());
            }
        });
    return future.get();
}

template <typename Fn>
void run_sync_void_query(asio::io_context& io_context, Fn&& fn)
{
    if (io_context.stopped())
    {
        return;
    }
    if (io_context.get_executor().running_in_this_thread())
    {
        std::forward<Fn>(fn)();
        return;
    }

    std::promise<void> promise;
    auto future = promise.get_future();
    asio::post(
        io_context,
        [promise = std::move(promise), fn = std::forward<Fn>(fn)]() mutable
        {
            try
            {
                fn();
                promise.set_value();
            }
            catch (...)
            {
                promise.set_exception(std::current_exception());
            }
        });
    future.get();
}

asio::awaitable<void> wait_draining_delay(asio::steady_timer& timer, const std::uint32_t delay_seconds, const std::uint32_t cid)
{
    timer.expires_after(std::chrono::seconds(delay_seconds));
    const auto [wait_ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (!wait_ec)
    {
        LOG_DEBUG("mux {} draining complete after {}s", cid, delay_seconds);
    }
}

}    // namespace

mux_connection::mux_connection(asio::ip::tcp::socket socket,
                               asio::io_context& io_context,
                               reality_engine engine,
                               const bool is_client,
                               const std::uint32_t conn_id,
                               const std::string& trace_id,
                               const config::timeout_t& timeout_cfg,
                               const config::limits_t& limits_cfg,
                               const config::heartbeat_t& heartbeat_cfg)
    : cid_(conn_id),
      io_context_(io_context),
      timer_(io_context_),
      socket_(std::move(socket)),
      reality_engine_(std::move(engine)),
      next_stream_id_(is_client ? 1 : 2),
      connection_state_(mux_connection_state::kConnected),
      timeout_config_(timeout_cfg),
      limits_config_(limits_cfg),
      heartbeat_config_(heartbeat_cfg),
      write_channel_(std::make_unique<channel_type>(io_context_, 1024))
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
    mux_dispatcher_.set_max_buffer(limits_config_.max_buffer);
    statistics::instance().inc_active_mux_sessions();
    LOG_CTX_INFO(ctx_, "{} mux initialized {}", log_event::kConnInit, ctx_.connection_info());
}

mux_connection::~mux_connection() { statistics::instance().dec_active_mux_sessions(); }

bool mux_connection::run_inline() const
{
    return !started_.load(std::memory_order_acquire) || io_context_.get_executor().running_in_this_thread();
}

void mux_connection::register_stream_local(const std::uint32_t id, std::shared_ptr<mux_stream_interface> stream)
{
    streams_[id] = std::move(stream);
    LOG_DEBUG("mux {} stream {} registered", cid_, id);
}

bool mux_connection::try_register_stream_local(const std::uint32_t id, std::shared_ptr<mux_stream_interface> stream)
{
    const auto [it, inserted] = streams_.try_emplace(id, std::move(stream));
    if (!inserted)
    {
        return false;
    }
    LOG_DEBUG("mux {} stream {} registered", cid_, id);
    return true;
}

void mux_connection::remove_stream_local(const std::uint32_t id)
{
    streams_.erase(id);
    LOG_DEBUG("mux {} stream {} removed", cid_, id);
}

bool mux_connection::can_accept_stream_local() const
{
    return streams_.size() < limits_config_.max_streams;
}

bool mux_connection::has_stream_local(const std::uint32_t id) const
{
    return streams_.find(id) != streams_.end();
}

std::shared_ptr<mux_stream_interface> mux_connection::find_stream(const std::uint32_t stream_id) const
{
    const auto it = streams_.find(stream_id);
    if (it != streams_.end())
    {
        return it->second;
    }
    return nullptr;
}

void mux_connection::handle_unknown_stream(const std::uint32_t stream_id, const std::uint8_t command)
{
    if (command == mux::kCmdRst)
    {
        return;
    }

    LOG_DEBUG("mux {} recv frame for unknown stream {}", cid_, stream_id);
    const auto self = shared_from_this();
    asio::co_spawn(io_context_,
                   [self, stream_id]() -> asio::awaitable<void>
                   {
                       (void)co_await self->send_async(stream_id, kCmdRst, {});
                   },
                   asio::detached);
}

void mux_connection::handle_stream_frame(const mux::frame_header& header, std::vector<std::uint8_t> payload)
{
    auto stream = find_stream(header.stream_id);
    if (stream == nullptr)
    {
        handle_unknown_stream(header.stream_id, header.command);
        return;
    }

    if (header.command == mux::kCmdFin)
    {
        stream->on_close();
        remove_stream(header.stream_id);
        return;
    }
    if (header.command == mux::kCmdRst)
    {
        stream->on_reset();
        remove_stream(header.stream_id);
        return;
    }
    if (header.command == mux::kCmdDat || header.command == mux::kCmdAck)
    {
        stream->on_data(std::move(payload));
    }
}

void mux_connection::register_stream(const std::uint32_t id, std::shared_ptr<mux_stream_interface> stream)
{
    if (stream == nullptr)
    {
        return;
    }
    if (!is_open())
    {
        return;
    }

    if (run_inline())
    {
        register_stream_local(id, std::move(stream));
        return;
    }
    run_sync_void_query(
        io_context_,
        [self = shared_from_this(), id, stream = std::move(stream)]() mutable
        {
            self->register_stream_local(id, std::move(stream));
        });
}

bool mux_connection::try_register_stream(const std::uint32_t id, std::shared_ptr<mux_stream_interface> stream)
{
    if (stream == nullptr)
    {
        return false;
    }
    if (!is_open())
    {
        return false;
    }

    if (run_inline())
    {
        return try_register_stream_local(id, std::move(stream));
    }
    return run_sync_bool_query(
        io_context_,
        [self = shared_from_this(), id, stream = std::move(stream)]() mutable
        {
            return self->try_register_stream_local(id, std::move(stream));
        });
}

void mux_connection::remove_stream(const std::uint32_t id)
{
    if (run_inline())
    {
        remove_stream_local(id);
        return;
    }

    asio::post(io_context_,
               [self = shared_from_this(), id]()
               {
                   self->remove_stream_local(id);
               });
}

asio::awaitable<void> mux_connection::start()
{
    co_await asio::dispatch(io_context_, asio::use_awaitable);
    co_await start_impl();
}

asio::awaitable<void> mux_connection::start_impl()
{
    started_.store(true, std::memory_order_release);
    LOG_DEBUG("mux {} started loops", cid_);
    using asio::experimental::awaitable_operators::operator||;
    const auto ts = now_ms();
    last_read_time_ms_.store(ts, std::memory_order_release);
    last_write_time_ms_.store(ts, std::memory_order_release);
    co_await (read_loop() || write_loop() || timeout_loop() || heartbeat_loop());
    LOG_INFO("mux {} loops finished stopped", cid_);
    stop();
}

asio::awaitable<std::error_code> mux_connection::send_async(const std::uint32_t stream_id, const std::uint8_t cmd, std::vector<std::uint8_t> payload)
{
    if (connection_state_.load(std::memory_order_acquire) != mux_connection_state::kConnected)
    {
        co_return asio::error::operation_aborted;
    }

    if (payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("mux {} payload too large {}", cid_, payload.size());
        co_return asio::error::message_size;
    }

    if (cmd != mux::kCmdDat || payload.size() < 128)
    {
        LOG_TRACE("mux {} send frame stream {} cmd {} size {}", cid_, stream_id, cmd, payload.size());
    }

    mux_write_msg msg{.command = cmd, .stream_id = stream_id, .payload = std::move(payload)};
    const auto [ec] = co_await write_channel_->async_send(std::error_code{}, std::move(msg), asio::as_tuple(asio::use_awaitable));

    if (ec)
    {
        LOG_ERROR("mux {} send failed error {}", cid_, ec.message());
        stop();
        co_return ec;
    }
    co_return std::error_code();
}

void mux_connection::stop()
{
    mux_connection_state expected = mux_connection_state::kConnected;
    if (!connection_state_.compare_exchange_strong(expected, mux_connection_state::kClosing, std::memory_order_acq_rel))
    {
        if (expected != mux_connection_state::kDraining)
        {
            return;
        }
        expected = mux_connection_state::kDraining;
        if (!connection_state_.compare_exchange_strong(expected, mux_connection_state::kClosing, std::memory_order_acq_rel))
        {
            return;
        }
    }

    asio::dispatch(io_context_, [self = shared_from_this()]() { self->stop_impl(); });
}

void mux_connection::stop_impl()
{
    if (connection_state_.load(std::memory_order_acquire) == mux_connection_state::kClosed)
    {
        return;
    }
    LOG_INFO("mux {} stopping", cid_);
    stream_map_t streams_to_clear = std::move(streams_);
    reset_streams_on_stop(streams_to_clear);
    close_socket_on_stop();
    finalize_stop_state();
}

void mux_connection::release_resources()
{
    stop();
}

void mux_connection::reset_streams_on_stop(stream_map_t& streams_to_clear)
{
    for (auto& stream : streams_to_clear | std::views::values)
    {
        if (stream != nullptr)
        {
            stream->on_reset();
        }
    }
    streams_to_clear.clear();
}

void mux_connection::close_socket_on_stop()
{
    if (!socket_.is_open())
    {
        return;
    }

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

void mux_connection::finalize_stop_state()
{
    LOG_INFO("mux write channel {} close", cid_);
    if (write_channel_)
    {
        write_channel_->close();
    }
    LOG_INFO("mux timer {} cancel", cid_);
    timer_.cancel();
    connection_state_.store(mux_connection_state::kClosed, std::memory_order_release);
}

bool mux_connection::should_stop_read(const std::error_code& read_ec, const std::size_t n) const
{
    if (!read_ec && n != 0)
    {
        return false;
    }
    if (read_ec != asio::error::eof && read_ec != asio::error::operation_aborted)
    {
        LOG_ERROR("mux {} read error {}", cid_, read_ec.message());
    }
    return true;
}

void mux_connection::update_read_statistics(const std::size_t n)
{
    read_bytes_ += n;
    statistics::instance().add_bytes_read(n);
    last_read_time_ms_.store(now_ms(), std::memory_order_release);
    reality_engine_.commit_read(n);
}

std::expected<void, std::error_code> mux_connection::process_decrypted_records()
{
    std::error_code decrypt_ec;
    reality_engine_.process_available_records(decrypt_ec,
                                              [this](const std::uint8_t type, const std::span<const std::uint8_t> plaintext)
                                              {
                                                  if (type == reality::kContentTypeApplicationData && !plaintext.empty())
                                                  {
                                                      mux_dispatcher_.on_plaintext_data(plaintext);
                                                  }
                                              });
    if (decrypt_ec)
    {
        return std::unexpected(decrypt_ec);
    }
    return {};
}

bool mux_connection::has_dispatch_failure(const std::error_code& decrypt_ec) const
{
    if (mux_dispatcher_.overflowed())
    {
        LOG_ERROR("mux {} dispatcher overflow stopping", cid_);
        return true;
    }
    if (decrypt_ec)
    {
        LOG_ERROR("mux {} decrypt protocol error {}", cid_, decrypt_ec.message());
        return true;
    }
    return false;
}

asio::awaitable<bool> mux_connection::read_and_dispatch_once()
{
    const auto buf = reality_engine_.read_buffer(8192);
    const auto [read_ec, n] = co_await socket_.async_read_some(buf, asio::as_tuple(asio::use_awaitable));
    if (should_stop_read(read_ec, n))
    {
        co_return false;
    }
    update_read_statistics(n);

    auto decrypt_res = process_decrypted_records();
    std::error_code decrypt_ec;
    if (!decrypt_res)
    {
        decrypt_ec = decrypt_res.error();
    }
    if (has_dispatch_failure(decrypt_ec))
    {
        co_return false;
    }
    co_return true;
}

asio::awaitable<void> mux_connection::read_loop()
{
    while (is_open())
    {
        if (!co_await read_and_dispatch_once())
        {
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
        const auto [ec, msg] = co_await write_channel_->async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            break;
        }

        const auto mux_frame = mux_dispatcher::pack(msg.stream_id, msg.command, msg.payload);
        const auto encrypt_result = reality_engine_.encrypt(mux_frame);

        if (!encrypt_result)
        {
            LOG_ERROR("mux {} encrypt error {}", cid_, encrypt_result.error().message());
            break;
        }

        const auto ciphertext_span = *encrypt_result;

        const auto [wec, n] =
            co_await asio::async_write(socket_, asio::buffer(ciphertext_span.data(), ciphertext_span.size()), asio::as_tuple(asio::use_awaitable));

        if (wec)
        {
            LOG_ERROR("mux {} write error {}", cid_, wec.message());
            break;
        }
        write_bytes_ += n;
        statistics::instance().add_bytes_written(n);
        last_write_time_ms_.store(now_ms(), std::memory_order_release);
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
        if (handle_timeout_wait_error(ec, cid_))
        {
            break;
        }

        const auto state = connection_state_.load(std::memory_order_acquire);
        if (state == mux_connection_state::kDraining)
        {
            continue;
        }

        const auto snapshot = collect_timeout_snapshot(last_read_time_ms_, last_write_time_ms_, timeout_config_);
        if (is_timeout_exceeded(snapshot))
        {
            if (streams_.empty())
            {
                LOG_DEBUG("mux {} timeout without streams, closing", cid_);
                break;
            }

            LOG_DEBUG("mux {} entering draining mode", cid_);
            connection_state_.store(mux_connection_state::kDraining, std::memory_order_release);
            const auto delay_seconds = pick_draining_delay_seconds(rng);
            co_await wait_draining_delay(timer_, delay_seconds, cid_);
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
        asio::steady_timer timer(io_context_);
        timer.expires_at(std::chrono::steady_clock::time_point::max());
        std::error_code ec;
        co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        co_return;
    }

    static thread_local std::mt19937 rng(std::random_device{}());
    asio::steady_timer heartbeat_timer(io_context_);

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

        const auto current_ms = now_ms();
        const auto write_elapsed_ms = current_ms - last_write_time_ms_.load(std::memory_order_acquire);
        const auto idle_timeout_ms = static_cast<std::uint64_t>(heartbeat_config_.idle_timeout) * 1000ULL;
        if (write_elapsed_ms < idle_timeout_ms)
        {
            continue;
        }

        std::uniform_int_distribution<std::uint32_t> padding_dist(heartbeat_config_.min_padding, heartbeat_config_.max_padding);
        const auto padding_len = padding_dist(rng);
        std::vector<std::uint8_t> padding(padding_len);
        RAND_bytes(padding.data(), static_cast<int>(padding_len));

        LOG_DEBUG("mux {} sending heartbeat size {}", cid_, padding_len);
        (void)co_await send_async(mux::kStreamIdHeartbeat, mux::kCmdDat, std::move(padding));
    }

    LOG_DEBUG("mux {} heartbeat loop finished", cid_);
}

void mux_connection::on_mux_frame(const mux::frame_header header, std::vector<std::uint8_t> payload)
{
    LOG_TRACE("mux {} recv frame stream {} cmd {} len {} payload size {}", cid_, header.stream_id, header.command, header.length, payload.size());

    if (header.stream_id == mux::kStreamIdHeartbeat)
    {
        LOG_DEBUG("mux {} heartbeat received size {}", cid_, payload.size());
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

    handle_stream_frame(header, std::move(payload));
}

bool mux_connection::can_accept_stream()
{
    if (limits_config_.max_streams == 0)
    {
        return true;
    }
    if (!is_open())
    {
        return false;
    }

    if (run_inline())
    {
        return can_accept_stream_local();
    }
    return run_sync_bool_query(
        io_context_,
        [self = shared_from_this()]()
        {
            return self->can_accept_stream_local();
        });
}

bool mux_connection::has_stream(const std::uint32_t id)
{
    if (!is_open())
    {
        return false;
    }

    if (run_inline())
    {
        return has_stream_local(id);
    }
    return run_sync_bool_query(
        io_context_,
        [self = shared_from_this(), id]()
        {
            return self->has_stream_local(id);
        });
}

std::shared_ptr<mux_stream> mux_connection::create_stream(const std::string& trace_id)
{
    if (!is_open())
    {
        return nullptr;
    }
    if (!can_accept_stream())
    {
        return nullptr;
    }

    std::string stream_trace_id = trace_id;
    if (stream_trace_id.empty())
    {
        stream_trace_id = this->trace_id();
    }

    const std::uint32_t stream_id = acquire_next_id();
    auto stream = std::make_shared<mux_stream>(stream_id, id(), std::move(stream_trace_id), shared_from_this(), io_context_);
    register_stream(stream_id, stream);
    return stream;
}

}    // namespace mux
