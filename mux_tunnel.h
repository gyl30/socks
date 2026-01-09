#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <memory>
#include <vector>
#include <array>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/as_tuple.hpp>
#include "mux_protocol.h"
#include "log.h"

namespace mux
{

class mux_stream;

class mux_tunnel_interface : public std::enable_shared_from_this<mux_tunnel_interface>
{
   public:
    virtual ~mux_tunnel_interface() = default;
    virtual boost::asio::awaitable<void> run() = 0;
    virtual boost::asio::awaitable<boost::system::error_code> send_frame(FrameHeader header, std::vector<std::uint8_t> payload) = 0;
    virtual std::shared_ptr<mux_stream> create_stream() = 0;
    virtual std::shared_ptr<mux_stream> accept_stream(std::uint32_t id) = 0;
    virtual void remove_stream(std::uint32_t id) = 0;
};

class mux_stream : public std::enable_shared_from_this<mux_stream>
{
   public:
    mux_stream(std::uint32_t id, const std::shared_ptr<mux_tunnel_interface>& tunnel, const boost::asio::any_io_executor& ex)
        : id_(id), tunnel_(tunnel), recv_channel_(ex, 1024)
    {
    }

    [[nodiscard]] std::uint32_t id() const { return id_; }

    [[nodiscard]] boost::asio::awaitable<std::tuple<boost::system::error_code, std::vector<std::uint8_t>>> async_read_some()
    {
        co_return co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    }

    [[nodiscard]] boost::asio::awaitable<boost::system::error_code> send_data(std::vector<std::uint8_t> payload);

    [[nodiscard]] boost::asio::awaitable<boost::system::error_code> async_write_some(const void* data, std::size_t len);

    [[nodiscard]] boost::asio::awaitable<void> close();

    [[nodiscard]] boost::asio::awaitable<void> push_data(std::vector<std::uint8_t> payload)
    {
        boost::system::error_code ec;
        co_await recv_channel_.async_send(ec, std::move(payload), boost::asio::use_awaitable);
        if (ec)
        {
            LOG_WARN("stream {} push_data channel error {}", id_, ec.message());
        }
    }

    void remote_close() { recv_channel_.close(); }

   private:
    std::uint32_t id_ = 0;
    std::weak_ptr<mux_tunnel_interface> tunnel_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
};

template <typename StreamLayer>
class mux_tunnel_impl : public mux_tunnel_interface
{
   public:
    using SynHandler = std::function<boost::asio::awaitable<void>(std::uint32_t, std::vector<std::uint8_t>)>;

    explicit mux_tunnel_impl(StreamLayer socket) : socket_(std::move(socket)), write_channel_(socket_.get_executor(), 4096)
    {
        boost::system::error_code ec;

        socket_.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true), ec);
        socket_.lowest_layer().set_option(boost::asio::socket_base::keep_alive(true), ec);
    }

    void set_syn_handler(SynHandler handler) { syn_handler_ = std::move(handler); }

    boost::asio::awaitable<void> run() override
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        LOG_INFO("mux tunnel started");
        co_await (read_loop() || write_loop());
        close_all_streams();
        LOG_INFO("mux tunnel stopped");
    }

    boost::asio::awaitable<boost::system::error_code> send_frame(FrameHeader header, std::vector<std::uint8_t> payload) override
    {
        if (!write_channel_.is_open())
        {
            co_return boost::asio::error::broken_pipe;
        }

        auto [ec] = co_await write_channel_.async_send(
            boost::system::error_code(), header, std::move(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
        co_return ec;
    }

    std::shared_ptr<mux_stream> create_stream() override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::uint32_t id = next_local_id_;
        next_local_id_ += 2;
        auto stream = std::make_shared<mux_stream>(id, shared_from_this(), socket_.get_executor());
        streams_[id] = stream;
        return stream;
    }

    std::shared_ptr<mux_stream> accept_stream(std::uint32_t id) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto stream = std::make_shared<mux_stream>(id, shared_from_this(), socket_.get_executor());
        streams_[id] = stream;
        return stream;
    }

    void remove_stream(std::uint32_t id) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        streams_.erase(id);
    }

   private:
    [[nodiscard]] boost::asio::awaitable<void> read_loop()
    {
        std::array<std::uint8_t, HEADER_SIZE> header_buf;
        while (true)
        {
            auto [ec, n] =
                co_await boost::asio::async_read(socket_, boost::asio::buffer(header_buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                break;
            }

            auto header = FrameHeader::decode(header_buf.data());
            std::vector<std::uint8_t> payload;
            if (header.length > 0)
            {
                payload.resize(header.length);
                auto [ec2, n2] =
                    co_await boost::asio::async_read(socket_, boost::asio::buffer(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (ec2)
                {
                    break;
                }
            }
            co_await dispatch(header, std::move(payload));
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> dispatch(const FrameHeader& header, std::vector<std::uint8_t> payload)
    {
        if (header.command == CMD_SYN)
        {
            if (syn_handler_)
            {
                boost::asio::co_spawn(socket_.get_executor(), syn_handler_(header.stream_id, std::move(payload)), boost::asio::detached);
            }
        }
        else
        {
            std::shared_ptr<mux_stream> stream;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = streams_.find(header.stream_id);
                if (it != streams_.end())
                {
                    stream = it->second;
                }
            }

            if (stream != nullptr)
            {
                if (header.command == CMD_DAT || header.command == CMD_ACK)
                {
                    co_await stream->push_data(std::move(payload));
                }
                else if (header.command == CMD_FIN || header.command == CMD_RST)
                {
                    stream->remote_close();
                    remove_stream(header.stream_id);
                }
            }
            else if (header.command != CMD_RST && header.command != CMD_FIN)
            {
                FrameHeader h_rst{.stream_id = header.stream_id, .length = 0, .command = CMD_RST};
                co_await send_frame(h_rst, {});
            }
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> write_loop()
    {
        std::array<std::uint8_t, HEADER_SIZE> header_buf;
        while (true)
        {
            auto [ec, header, payload] = co_await write_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                break;
            }

            header.encode(header_buf.data());
            std::array<boost::asio::const_buffer, 2> buffers = {boost::asio::buffer(header_buf), boost::asio::buffer(payload)};
            auto [ec2, n] = co_await boost::asio::async_write(socket_, buffers, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
            {
                break;
            }
        }
    }

    void close_all_streams()
    {
        write_channel_.close();
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, stream] : streams_)
        {
            stream->remote_close();
        }
        streams_.clear();
    }

    StreamLayer socket_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, FrameHeader, std::vector<std::uint8_t>)> write_channel_;
    std::mutex mutex_;
    std::unordered_map<std::uint32_t, std::shared_ptr<mux_stream>> streams_;
    std::uint32_t next_local_id_ = 1;
    SynHandler syn_handler_;
};

inline boost::asio::awaitable<boost::system::error_code> mux_stream::send_data(std::vector<std::uint8_t> payload)
{
    auto t = tunnel_.lock();
    if (t == nullptr)
    {
        co_return boost::asio::error::broken_pipe;
    }

    FrameHeader header;
    header.stream_id = id_;
    header.length = static_cast<std::uint16_t>(payload.size());
    header.command = CMD_DAT;

    co_return co_await t->send_frame(header, std::move(payload));
}

inline boost::asio::awaitable<boost::system::error_code> mux_stream::async_write_some(const void* data, std::size_t len)
{
    std::vector<std::uint8_t> payload(static_cast<const std::uint8_t*>(data), static_cast<const std::uint8_t*>(data) + len);
    co_return co_await send_data(std::move(payload));
}

inline boost::asio::awaitable<void> mux_stream::close()
{
    auto t = tunnel_.lock();
    if (t != nullptr)
    {
        FrameHeader header;
        header.stream_id = id_;
        header.length = 0;
        header.command = CMD_FIN;
        co_await t->send_frame(header, {});
        t->remove_stream(id_);
    }
    recv_channel_.close();
}

}    // namespace mux

#endif
