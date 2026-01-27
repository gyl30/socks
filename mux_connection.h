#ifndef MUX_CONNECTION_H
#define MUX_CONNECTION_H

#include <memory>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <atomic>
#include <mutex>

#include <asio.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "mux_protocol.h"
#include "mux_dispatcher.h"
#include "reality_engine.h"
#include "mux_stream_interface.h"

enum class mux_connection_state : uint8_t
{
    connected,
    closing,
    closed
};

struct mux_write_msg
{
    uint8_t command_ = 0;
    uint32_t stream_id = 0;
    std::vector<uint8_t> payload;
};

class mux_connection : public std::enable_shared_from_this<mux_connection>
{
   public:
    using stream_map_t = std::unordered_map<uint32_t, std::shared_ptr<mux_stream_interface>>;
    using syn_callback_t = std::function<void(uint32_t, std::vector<uint8_t>)>;

    mux_connection(asio::ip::tcp::socket socket, reality_engine engine, bool is_client, uint32_t conn_id)
        : cid_(conn_id),
          timer_(socket.get_executor()),
          socket_(std::move(socket)),
          reality_engine_(std::move(engine)),
          next_stream_id_(is_client ? 1 : 2),
          connection_state_(mux_connection_state::connected),
          write_channel_(socket_.get_executor(), 1024)
    {
        mux_dispatcher_.set_callback([this](mux::frame_header h, std::vector<uint8_t> p) { this->on_mux_frame(h, std::move(p)); });
        LOG_INFO("mux {} initialized", cid_);
    }

    auto get_executor() { return socket_.get_executor(); }

    void set_syn_callback(syn_callback_t cb) { syn_callback_ = std::move(cb); }

    void register_stream(uint32_t id, std::shared_ptr<mux_stream_interface> stream)
    {
        const std::scoped_lock lock(streams_mutex_);
        streams_[id] = std::move(stream);
        LOG_DEBUG("mux {} stream {} registered", cid_, id);
    }

    void remove_stream(uint32_t id)
    {
        const std::scoped_lock lock(streams_mutex_);
        streams_.erase(id);
        LOG_DEBUG("mux {} stream {} removed", cid_, id);
    }

    [[nodiscard]] uint32_t acquire_next_id() { return next_stream_id_.fetch_add(2, std::memory_order_relaxed); }
    [[nodiscard]] uint32_t id() const { return cid_; }

    [[nodiscard]] asio::awaitable<void> start()
    {
        auto self = shared_from_this();
        LOG_DEBUG("mux {} started loops", cid_);
        using asio::experimental::awaitable_operators::operator||;
        last_read_time = std::chrono::steady_clock::now();
        last_write_time = std::chrono::steady_clock::now();
        co_await (read_loop() || write_loop() || timeout_loop());
        LOG_INFO("mux {} loops finished stopped", cid_);
        stop();
    }

    [[nodiscard]] asio::awaitable<std::error_code> send_async(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload)
    {
        if (connection_state_.load(std::memory_order_acquire) != mux_connection_state::connected)
        {
            co_return asio::error::operation_aborted;
        }

        if (cmd != mux::CMD_DAT || payload.size() < 128)
        {
            LOG_TRACE("mux {} send frame stream {} cmd {} size {}", cid_, stream_id, cmd, payload.size());
        }

        mux_write_msg msg{.command_ = cmd, .stream_id = stream_id, .payload = std::move(payload)};
        auto [ec] = co_await write_channel_.async_send(std::error_code{}, std::move(msg), asio::as_tuple(asio::use_awaitable));

        if (ec)
        {
            LOG_ERROR("mux {} send failed error {}", cid_, ec.message());
            co_return ec;
        }
        co_return std::error_code();
    }

    void stop()
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

    [[nodiscard]] bool is_open() const { return connection_state_.load(std::memory_order_acquire) == mux_connection_state::connected; }

   private:
    asio::awaitable<void> read_loop()
    {
        while (is_open())
        {
            auto buf = reality_engine_.get_read_buffer(8192);

            auto [read_ec, n] = co_await socket_.async_read_some(buf, asio::as_tuple(asio::use_awaitable));

            if (read_ec || n == 0)
            {
                if (read_ec != asio::error::eof && read_ec != asio::error::operation_aborted)
                {
                    LOG_ERROR("mux {} read error {}", cid_, read_ec.message());
                }
                break;
            }
            read_bytes += n;
            last_read_time = std::chrono::steady_clock::now();

            reality_engine_.commit_read(n);

            std::error_code decrypt_ec;

            reality_engine_.process_available_records(decrypt_ec,
                                                      [this](uint8_t type, std::span<const uint8_t> pt)
                                                      {
                                                          if (type == reality::CONTENT_TYPE_APPLICATION_DATA && !pt.empty())
                                                          {
                                                              mux_dispatcher_.on_plaintext_data(pt);
                                                          }
                                                      });

            if (decrypt_ec)
            {
                LOG_ERROR("mux {} decrypt/protocol error {}", cid_, decrypt_ec.message());
                break;
            }
        }
        LOG_DEBUG("mux {} read loop finished", cid_);
        stop();
    }

    asio::awaitable<void> write_loop()
    {
        while (is_open())
        {
            auto [ec, msg] = co_await write_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                break;
            }

            auto mux_frame = mux_dispatcher::pack(msg.stream_id, msg.command_, msg.payload);
            std::error_code enc_ec;

            auto ciphertext_span = reality_engine_.encrypt(mux_frame, enc_ec);

            if (enc_ec)
            {
                LOG_ERROR("mux {} encrypt error {}", cid_, enc_ec.message());
                break;
            }

            auto [wec, n] = co_await asio::async_write(
                socket_, asio::buffer(ciphertext_span.data(), ciphertext_span.size()), asio::as_tuple(asio::use_awaitable));

            if (wec)
            {
                LOG_ERROR("mux {} write error {}", cid_, wec.message());
                break;
            }
            write_bytes += n;
            last_write_time = std::chrono::steady_clock::now();
        }
        LOG_DEBUG("mux {} write loop finished", cid_);
        stop();
    }

    asio::awaitable<void> timeout_loop()
    {
        while (is_open())
        {
            timer_.expires_after(std::chrono::seconds(1));
            auto [ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                LOG_WARN("mux {} timeout error {}", cid_, ec.message());
                break;
            }
            auto now = std::chrono::steady_clock::now();
            auto read_elapsed = now - last_read_time;
            auto write_elapsed = now - last_write_time;
            if (read_elapsed > std::chrono::seconds(100))
            {
                LOG_WARN("mux {} timeout read", cid_);
            }
            if (write_elapsed > std::chrono::seconds(100))
            {
                LOG_WARN("mux {} timeout write", cid_);
            }
        }

        LOG_DEBUG("mux {} timeout loop finished", cid_);
        stop();
    }

    void on_mux_frame(mux::frame_header header, std::vector<uint8_t> payload)
    {
        LOG_TRACE("mux {} recv frame stream {} cmd {} len {}", cid_, header.stream_id, header.command, header.length);

        if (header.command == mux::CMD_SYN)
        {
            if (syn_callback_)
            {
                syn_callback_(header.stream_id, std::move(payload));
            }
            return;
        }

        std::shared_ptr<mux_stream_interface> stream;
        {
            const std::scoped_lock lock(streams_mutex_);
            auto it = streams_.find(header.stream_id);
            if (it != streams_.end())
            {
                stream = it->second;
            }
        }

        if (stream != nullptr)
        {
            if (header.command == mux::CMD_FIN)
            {
                stream->on_close();
            }
            else if (header.command == mux::CMD_RST)
            {
                stream->on_reset();
            }
            else if (header.command == mux::CMD_DAT || header.command == mux::CMD_ACK)
            {
                stream->on_data(std::move(payload));
            }
        }
        else
        {
            if (header.command != mux::CMD_RST)
            {
                LOG_DEBUG("mux {} recv frame for unknown stream {}", cid_, header.stream_id);
            }
        }
    }

   private:
    uint64_t read_bytes = 0;
    uint64_t write_bytes = 0;
    std::chrono::steady_clock::time_point last_read_time;
    std::chrono::steady_clock::time_point last_write_time;
    uint32_t cid_;
    stream_map_t streams_;
    asio::steady_timer timer_;
    std::mutex streams_mutex_;
    syn_callback_t syn_callback_;
    asio::ip::tcp::socket socket_;
    reality_engine reality_engine_;
    mux_dispatcher mux_dispatcher_;
    std::atomic<uint32_t> next_stream_id_;
    std::atomic<mux_connection_state> connection_state_;
    asio::experimental::concurrent_channel<void(std::error_code, mux_write_msg)> write_channel_;
};

#endif
