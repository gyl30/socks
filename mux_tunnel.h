#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/as_tuple.hpp>
#include <unordered_map>
#include <memory>
#include <vector>
#include <functional>
#include <array>
#include <mutex>
#include <system_error>
#include "mux_protocol.h"
#include "log.h"

namespace mux
{

class MuxTunnel;

class MuxStream : public std::enable_shared_from_this<MuxStream>
{
   public:
    MuxStream(std::uint32_t id, std::shared_ptr<MuxTunnel> tunnel, const boost::asio::any_io_executor& ex)
        : id_(id), tunnel_(tunnel), recv_channel_(ex, 1024)
    {
    }

    std::uint32_t get_id() const { return id_; }

    boost::asio::awaitable<std::vector<std::uint8_t>> async_read_some()
    {
        try
        {
            auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                if (ec == boost::asio::experimental::error::channel_closed)
                {
                    co_return std::vector<std::uint8_t>{};
                }

                if (ec != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("stream {} channel receive error: {}", id_, ec.message());
                }
                throw std::system_error(ec);
            }
            co_return data;
        }
        catch (...)
        {
            throw;
        }
    }

    boost::asio::awaitable<void> send_data(std::vector<std::uint8_t> payload);

    boost::asio::awaitable<void> async_write_some(const void* data, std::size_t len);

    boost::asio::awaitable<void> close();

    boost::asio::awaitable<void> push_data(std::vector<std::uint8_t> payload)
    {
        boost::system::error_code ec;
        co_await recv_channel_.async_send(ec, std::move(payload), boost::asio::use_awaitable);
    }

    void remote_close() { recv_channel_.close(); }

   private:
    std::uint32_t id_;
    std::weak_ptr<MuxTunnel> tunnel_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
};

class MuxTunnel : public std::enable_shared_from_this<MuxTunnel>
{
   public:
    using PhysicalSocket = boost::asio::ip::tcp::socket;
    using SynHandler = std::function<boost::asio::awaitable<void>(std::uint32_t, std::vector<std::uint8_t>)>;

    explicit MuxTunnel(PhysicalSocket socket) : socket_(std::move(socket)), write_channel_(socket_.get_executor(), 4096)
    {
        boost::system::error_code ec;
        socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        socket_.set_option(boost::asio::socket_base::keep_alive(true), ec);
    }

    boost::asio::any_io_executor get_executor() { return socket_.get_executor(); }

    void set_syn_handler(SynHandler handler) { syn_handler_ = std::move(handler); }

    boost::asio::awaitable<void> run()
    {
        using boost::asio::experimental::awaitable_operators::operator&&;
        LOG_INFO("mux tunnel started on socket fd={}", socket_.native_handle());

        try
        {
            co_await (read_loop() && write_loop());
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("mux tunnel fatal error: {}", e.what());
        }

        close_all_streams();
        LOG_INFO("mux tunnel stopped");
    }

    boost::asio::awaitable<void> send_frame(frame_header header, std::vector<std::uint8_t> payload)
    {
        if (!write_channel_.is_open())
            co_return;
        co_await write_channel_.async_send(boost::system::error_code(), header, std::move(payload), boost::asio::use_awaitable);
    }

    std::shared_ptr<MuxStream> create_stream()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::uint32_t id = next_local_id_;
        next_local_id_ += 2;
        auto stream = std::make_shared<MuxStream>(id, shared_from_this(), socket_.get_executor());
        streams_[id] = stream;
        return stream;
    }

    std::shared_ptr<MuxStream> accept_stream(std::uint32_t id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto stream = std::make_shared<MuxStream>(id, shared_from_this(), socket_.get_executor());
        streams_[id] = stream;
        return stream;
    }

    void remove_stream(std::uint32_t id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        streams_.erase(id);
    }

   private:
    boost::asio::awaitable<void> read_loop()
    {
        std::array<std::uint8_t, HEADER_SIZE> header_buf;
        while (true)
        {
            co_await boost::asio::async_read(socket_, boost::asio::buffer(header_buf), boost::asio::use_awaitable);
            auto header = frame_header::decode(header_buf.data());

            std::vector<std::uint8_t> payload;
            if (header.length > 0)
            {
                payload.resize(header.length);
                co_await boost::asio::async_read(socket_, boost::asio::buffer(payload), boost::asio::use_awaitable);
            }
            co_await dispatch(header, std::move(payload));
        }
    }

    boost::asio::awaitable<void> dispatch(const frame_header& header, std::vector<std::uint8_t> payload)
    {
        if (header.command == CMD_SYN)
        {
            LOG_INFO("recv SYN for stream {}", header.stream_id);
            if (syn_handler_)
            {
                boost::asio::co_spawn(socket_.get_executor(), syn_handler_(header.stream_id, std::move(payload)), boost::asio::detached);
            }
        }
        else
        {
            std::shared_ptr<MuxStream> stream;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = streams_.find(header.stream_id);
                if (it != streams_.end())
                    stream = it->second;
            }

            if (stream)
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
                frame_header h_rst{header.stream_id, 0, CMD_RST};
                co_await send_frame(h_rst, {});
            }
        }
    }

    boost::asio::awaitable<void> write_loop()
    {
        std::array<std::uint8_t, HEADER_SIZE> header_buf;
        while (true)
        {
            auto [ec, header, payload] = co_await write_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                break;

            header.encode(header_buf.data());
            std::array<boost::asio::const_buffer, 2> buffers = {boost::asio::buffer(header_buf), boost::asio::buffer(payload)};
            co_await boost::asio::async_write(socket_, buffers, boost::asio::use_awaitable);
        }
    }

    void close_all_streams()
    {
        write_channel_.close();
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, stream] : streams_) stream->remote_close();
        streams_.clear();
    }

    PhysicalSocket socket_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, frame_header, std::vector<std::uint8_t>)> write_channel_;
    std::mutex mutex_;
    std::unordered_map<std::uint32_t, std::shared_ptr<MuxStream>> streams_;
    std::uint32_t next_local_id_ = 1;
    SynHandler syn_handler_;
};

inline boost::asio::awaitable<void> MuxStream::send_data(std::vector<std::uint8_t> payload)
{
    auto self = shared_from_this();
    auto t = tunnel_.lock();
    if (!t)
        throw std::runtime_error("tunnel destroyed");

    frame_header header;
    header.stream_id = id_;
    header.length = static_cast<std::uint16_t>(payload.size());
    header.command = CMD_DAT;

    co_await t->send_frame(header, std::move(payload));
}

inline boost::asio::awaitable<void> MuxStream::async_write_some(const void* data, std::size_t len)
{
    std::vector<std::uint8_t> payload(static_cast<const std::uint8_t*>(data), static_cast<const std::uint8_t*>(data) + len);
    co_await send_data(std::move(payload));
}

inline boost::asio::awaitable<void> MuxStream::close()
{
    auto self = shared_from_this();
    auto t = tunnel_.lock();
    if (t)
    {
        frame_header header{.stream_id = id_, .length = 0, .command = CMD_FIN};
        co_await t->send_frame(header, {});
        t->remove_stream(id_);
    }
    recv_channel_.close();
}

}    // namespace mux

#endif
