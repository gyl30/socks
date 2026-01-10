#ifndef MUX_CONNECTION_H
#define MUX_CONNECTION_H

#include <memory>
#include <vector>
#include <array>
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

enum class MuxConnectionState
{
    CONNECTED,
    CLOSING,
    CLOSED
};

struct mux_write_msg
{
    uint32_t stream_id;
    uint8_t command;
    std::vector<uint8_t> payload;
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

    mux_connection(tcp::socket socket, reality_engine engine, stream_map_t& streams_ref, std::mutex& streams_mutex)
        : socket_(std::move(socket)),
          reality_engine_(std::move(engine)),
          write_channel_(socket_.get_executor(), 1024),
          timer_(socket_.get_executor()),
          streams_ref_(streams_ref),
          streams_mutex_(streams_mutex)
    {
        mux_dispatcher_.set_callback([this](mux::frame_header h, std::vector<uint8_t> p) { this->on_mux_frame(h, std::move(p)); });
        connection_state_.store(MuxConnectionState::CONNECTED, std::memory_order_release);
        LOG_INFO("mux_connection initialized");
    }

    auto get_executor() { return socket_.get_executor(); }

    void set_syn_callback(syn_callback_t cb) { syn_callback_ = std::move(cb); }

    [[nodiscard]] awaitable<void> start()
    {
        auto self = shared_from_this();
        LOG_DEBUG("mux_connection started loops");

        co_await (read_loop() || write_loop() || timeout_loop());

        LOG_INFO("mux_connection loops finished stopped");
    }

    [[nodiscard]] awaitable<boost::system::error_code> send_async(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload)
    {
        if (connection_state_.load(std::memory_order_acquire) != MuxConnectionState::CONNECTED)
        {
            co_return boost::asio::error::operation_aborted;
        }
        mux_write_msg msg{stream_id, cmd, std::move(payload)};
        auto [ec] =
            co_await write_channel_.async_send(boost::system::error_code{}, std::move(msg), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("mux_connection send failed error {}", ec.message());
            co_return ec;
        }
        co_return boost::system::error_code();
    }

    void stop()
    {
        MuxConnectionState expected = MuxConnectionState::CONNECTED;
        if (!connection_state_.compare_exchange_strong(expected, MuxConnectionState::CLOSING, std::memory_order_acq_rel))
        {
            return;
        }

        LOG_INFO("mux_connection stopping");
        boost::system::error_code ec;
        if (socket_.is_open())
        {
            socket_.shutdown(tcp::socket::shutdown_both, ec);
            socket_.close(ec);
        }
        write_channel_.close();
        timer_.cancel();
        connection_state_.store(MuxConnectionState::CLOSED, std::memory_order_release);
    }

    [[nodiscard]] bool is_open() const { return connection_state_.load(std::memory_order_acquire) == MuxConnectionState::CONNECTED; }

   private:
    std::string get_remote_endpoint_string()
    {
        boost::system::error_code ec;
        auto ep = socket_.remote_endpoint(ec);
        return ec ? "unknown" : ep.address().to_string();
    }

    awaitable<void> read_loop()
    {
        while (is_open())
        {
            std::span<uint8_t> tls_write_buf = reality_engine_.get_write_buffer();
            if (tls_write_buf.empty())
            {
                LOG_ERROR("mux_connection buffer full");
                break;
            }

            auto [read_ec, n] = co_await socket_.async_read_some(boost::asio::buffer(tls_write_buf.data(), tls_write_buf.size()),
                                                                 boost::asio::as_tuple(boost::asio::use_awaitable));
            if (read_ec || n == 0)
            {
                if (read_ec != boost::asio::error::eof && read_ec != boost::asio::error::operation_aborted)
                {
                    LOG_ERROR("mux_connection read error {}", read_ec.message());
                }
                break;
            }
            reality_engine_.commit_written(n);
            update_activity();

            boost::system::error_code decrypt_ec;
            auto plaintexts = reality_engine_.decrypt_available_records(decrypt_ec);
            if (decrypt_ec)
            {
                LOG_ERROR("mux_connection tls decrypt error {}", decrypt_ec.message());
                break;
            }
            for (const auto& pt : plaintexts)
            {
                mux_dispatcher_.on_plaintext_data(pt);
            }
        }
        stop();
        LOG_DEBUG("mux_connection read_loop finished");
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

            auto mux_frame = MuxDispatcher::pack(msg.stream_id, msg.command, std::move(msg.payload));
            boost::system::error_code enc_ec;
            auto ciphertext = reality_engine_.encrypt(mux_frame, enc_ec);
            if (enc_ec)
            {
                LOG_ERROR("mux_connection encrypt error {}", enc_ec.message());
                break;
            }

            auto [wec, n] =
                co_await boost::asio::async_write(socket_, boost::asio::buffer(ciphertext), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (wec)
            {
                LOG_ERROR("mux_connection write error {}", wec.message());
                break;
            }
            update_activity();
        }
        stop();
        LOG_DEBUG("mux_connection write_loop finished");
    }

    awaitable<void> timeout_loop()
    {
        while (is_open())
        {
            timer_.expires_after(std::chrono::seconds(300));
            auto [ec] = co_await timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec)
            {
                LOG_WARN("mux_connection timeout");
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
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = streams_ref_.find(header.stream_id);
            if (it != streams_ref_.end())
            {
                stream = it->second;
            }
        }

        if (stream)
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
    }

    tcp::socket socket_;
    reality_engine reality_engine_;
    MuxDispatcher mux_dispatcher_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_write_msg)> write_channel_;
    boost::asio::steady_timer timer_;
    std::atomic<MuxConnectionState> connection_state_;
    stream_map_t& streams_ref_;
    std::mutex& streams_mutex_;
    syn_callback_t syn_callback_;
};

#endif
