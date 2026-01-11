#ifndef MUX_CONNECTION_H
#define MUX_CONNECTION_H

#include <memory>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <atomic>
#include <mutex>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/system/error_code.hpp>

#include "reality_engine.h"
#include "mux_dispatcher.h"
#include "mux_protocol.h"
#include "log.h"

using boost::asio::ip::tcp;
using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
namespace this_coro = boost::asio::this_coro;
using namespace boost::asio::experimental::awaitable_operators;

enum class mux_connection_state
{
    connected,
    closing,
    closed
};

struct mux_write_msg
{
    uint32_t stream_id_ = 0;
    uint8_t command_ = 0;
    std::vector<uint8_t> payload_;
};

class mux_stream_interface
{
   public:
    virtual ~mux_stream_interface() = default;
    virtual void on_data(std::vector<uint8_t> data) = 0;
    virtual void on_close() = 0;
    virtual void on_reset() = 0;
};

class mux_connection : public std::enable_shared_from_this<mux_connection>
{
   public:
    using stream_map_t = std::unordered_map<uint32_t, std::shared_ptr<mux_stream_interface>>;
    using syn_callback_t = std::function<void(uint32_t, std::vector<uint8_t>)>;

    mux_connection(tcp::socket socket, reality_engine engine, bool is_client, uint32_t conn_id)
        : socket_(std::move(socket)),
          reality_engine_(std::move(engine)),
          write_channel_(socket_.get_executor(), 1024),
          timer_(socket_.get_executor()),
          connection_state_(mux_connection_state::connected),
          next_stream_id_(is_client ? 1 : 2),
          cid_(conn_id)
    {
        mux_dispatcher_.set_callback([this](mux::frame_header h, std::vector<uint8_t> p) { this->on_mux_frame(h, std::move(p)); });
        LOG_INFO("mux {} initialized", cid_);
    }

    auto get_executor() { return socket_.get_executor(); }

    void set_syn_callback(syn_callback_t cb) { syn_callback_ = std::move(cb); }

    void register_stream(uint32_t id, std::shared_ptr<mux_stream_interface> stream)
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_[id] = std::move(stream);
    }

    void remove_stream(uint32_t id)
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.erase(id);
    }

    [[nodiscard]] uint32_t acquire_next_id() { return next_stream_id_.fetch_add(2, std::memory_order_relaxed); }
    [[nodiscard]] uint32_t id() const { return cid_; }

    [[nodiscard]] awaitable<void> start()
    {
        auto self = shared_from_this();
        LOG_DEBUG("mux {} started loops", cid_);
        co_await (read_loop() || write_loop() || timeout_loop());
        LOG_INFO("mux {} loops finished stopped", cid_);
    }

    [[nodiscard]] awaitable<boost::system::error_code> send_async(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload)
    {
        if (connection_state_.load(std::memory_order_acquire) != mux_connection_state::connected)
        {
            co_return boost::asio::error::operation_aborted;
        }

        mux_write_msg msg{stream_id, cmd, std::move(payload)};
        auto [ec] =
            co_await write_channel_.async_send(boost::system::error_code{}, std::move(msg), boost::asio::as_tuple(boost::asio::use_awaitable));

        if (ec)
        {
            LOG_ERROR("mux {} send failed error {}", cid_, ec.message());
            co_return ec;
        }
        co_return boost::system::error_code();
    }

    void stop()
    {
        mux_connection_state expected = mux_connection_state::connected;
        if (!connection_state_.compare_exchange_strong(expected, mux_connection_state::closing, std::memory_order_acq_rel))
        {
            return;
        }

        LOG_INFO("mux {} stopping", cid_);

        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            streams_.clear();
        }

        if (socket_.is_open())
        {
            boost::system::error_code ec;
            socket_.shutdown(tcp::socket::shutdown_both, ec);
            socket_.close(ec);
        }
        write_channel_.close();
        timer_.cancel();
        connection_state_.store(mux_connection_state::closed, std::memory_order_release);
    }

    [[nodiscard]] bool is_open() const { return connection_state_.load(std::memory_order_acquire) == mux_connection_state::connected; }

   private:
    awaitable<void> read_loop()
    {
        while (is_open())
        {
            std::span<uint8_t> tls_write_buf = reality_engine_.get_write_buffer();
            if (tls_write_buf.empty())
            {
                LOG_ERROR("mux {} buffer full", cid_);
                break;
            }

            auto [read_ec, n] = co_await socket_.async_read_some(boost::asio::buffer(tls_write_buf.data(), tls_write_buf.size()),
                                                                 boost::asio::as_tuple(boost::asio::use_awaitable));

            if (read_ec || n == 0)
            {
                if (read_ec != boost::asio::error::eof && read_ec != boost::asio::error::operation_aborted)
                {
                    LOG_ERROR("mux {} read error {}", cid_, read_ec.message());
                }
                break;
            }

            reality_engine_.commit_written(n);
            update_activity();

            boost::system::error_code decrypt_ec;
            auto plaintexts = reality_engine_.decrypt_available_records(decrypt_ec);
            if (decrypt_ec)
            {
                LOG_ERROR("mux {} decrypt error {}", cid_, decrypt_ec.message());
                break;
            }

            for (const auto& pt : plaintexts)
            {
                mux_dispatcher_.on_plaintext_data(pt);
            }
        }
        stop();
        LOG_DEBUG("mux {} read loop finished", cid_);
    }

    awaitable<void> write_loop()
    {
        while (is_open())
        {
            auto [ec, msg] = co_await write_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                break;
            }

            auto mux_frame = mux_dispatcher::pack(msg.stream_id_, msg.command_, std::move(msg.payload_));
            boost::system::error_code enc_ec;
            auto ciphertext = reality_engine_.encrypt(mux_frame, enc_ec);
            if (enc_ec)
            {
                LOG_ERROR("mux {} encrypt error {}", cid_, enc_ec.message());
                break;
            }

            auto [wec, n] =
                co_await boost::asio::async_write(socket_, boost::asio::buffer(ciphertext), boost::asio::as_tuple(boost::asio::use_awaitable));

            if (wec)
            {
                LOG_ERROR("mux {} write error {}", cid_, wec.message());
                break;
            }
            update_activity();
        }
        stop();
        LOG_DEBUG("mux {} write loop finished", cid_);
    }

    awaitable<void> timeout_loop()
    {
        while (is_open())
        {
            timer_.expires_after(std::chrono::seconds(300));
            auto [ec] = co_await timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec)
            {
                LOG_WARN("mux {} timeout", cid_);
                break;
            }
        }
        stop();
    }

    void update_activity()
    {
        if (is_open())
        {
            timer_.cancel_one();
        }
    }

    void on_mux_frame(mux::frame_header header, std::vector<uint8_t> payload)
    {
        if (header.command_ == mux::CMD_SYN)
        {
            if (syn_callback_)
            {
                syn_callback_(header.stream_id_, std::move(payload));
            }
            return;
        }

        std::shared_ptr<mux_stream_interface> stream;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = streams_.find(header.stream_id_);
            if (it != streams_.end())
            {
                stream = it->second;
            }
        }

        if (stream != nullptr)
        {
            if (header.command_ == mux::CMD_FIN)
            {
                stream->on_close();
            }
            else if (header.command_ == mux::CMD_RST)
            {
                stream->on_reset();
            }
            else if (header.command_ == mux::CMD_DAT || header.command_ == mux::CMD_ACK)
            {
                stream->on_data(std::move(payload));
            }
        }
    }

    tcp::socket socket_;
    reality_engine reality_engine_;
    mux_dispatcher mux_dispatcher_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_write_msg)> write_channel_;
    boost::asio::steady_timer timer_;
    std::atomic<mux_connection_state> connection_state_;

    stream_map_t streams_;
    std::mutex streams_mutex_;
    std::atomic<uint32_t> next_stream_id_;
    uint32_t cid_;
    syn_callback_t syn_callback_;
};

#endif
