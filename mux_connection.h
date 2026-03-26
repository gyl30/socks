#ifndef MUX_CONNECTION_H
#define MUX_CONNECTION_H

#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "task_group.h"
#include "connection_context.h"
#include "mux_protocol.h"
#include "mux_dispatcher.h"
#include "reality/session/session.h"
#include "reality/session/engine.h"

namespace mux
{

class mux_stream;

class mux_connection : public std::enable_shared_from_this<mux_connection>
{
   public:
    mux_connection(boost::asio::ip::tcp::socket socket,
                   boost::asio::io_context& io_context,
                   reality::reality_session session,
                   const config& cfg,
                   task_group& group,
                   std::uint32_t conn_id,
                   const std::string& trace_id = "");

    virtual ~mux_connection();

   public:
    void start();
    void stop();

   public:
    using new_stream_cb = std::function<boost::asio::awaitable<void>(mux_frame)>;
    void set_new_stream_cb(new_stream_cb cb) { cb_ = std::move(cb); }

   public:
    [[nodiscard]] bool is_active() const;
    [[nodiscard]] boost::asio::io_context& io_context() const { return io_context_; }
    boost::asio::awaitable<void> async_wait_stopped();
    std::shared_ptr<mux_stream> create_stream();
    void register_stream(const std::shared_ptr<mux_stream>& stream);
    void close_and_remove_stream(const std::shared_ptr<mux_stream>& stream);
    void remove_stream(const std::shared_ptr<mux_stream>&);
    [[nodiscard]] std::shared_ptr<mux_stream> find_stream(std::uint32_t stream_id);
    boost::asio::awaitable<void> send_async(mux_frame msg, boost::system::error_code& ec);
    boost::asio::awaitable<void> send_async_with_timeout(mux_frame msg, std::uint32_t timeout_sec, boost::system::error_code& ec);
    std::uint64_t reserve_pending(std::uint64_t bytes);
    void release_pending(std::uint64_t bytes);
    std::uint64_t reserve_write_bytes(std::uint64_t bytes);
    void release_write_bytes(std::uint64_t bytes);
    std::uint64_t reserve_write_bytes(std::uint32_t stream_id, std::uint8_t command, std::uint64_t bytes);
    void release_write_bytes(std::uint32_t stream_id, std::uint8_t command, std::uint64_t bytes);

   private:
    void stop_on_executor();
    boost::asio::awaitable<void> run_loop();
    boost::asio::awaitable<void> read_loop();
    boost::asio::awaitable<void> write_loop();
    boost::asio::awaitable<void> timeout_loop();
    boost::asio::awaitable<void> heartbeat_loop();

   private:
    boost::asio::awaitable<void> on_mux_frame(mux::frame_header header, std::vector<std::uint8_t> payload);
    boost::asio::awaitable<void> handle_unknown_stream(mux::frame_header header, std::vector<std::uint8_t> payload);
    boost::asio::awaitable<void> handle_stream_frame(const mux::frame_header& header, std::vector<std::uint8_t> payload);
    [[nodiscard]] std::uint32_t acquire_next_id();

   private:
    const config& cfg_;
    std::uint32_t cid_ = 0;
    connection_context ctx_;
    task_group& group_;
    std::mutex mutex_;
    new_stream_cb cb_;
    reality_engine reality_engine_;
    mux_dispatcher mux_dispatcher_;
    std::uint32_t next_stream_id_ = 0;
    std::uint64_t read_bytes_ = 0;
    std::uint64_t write_bytes_ = 0;
    std::uint64_t last_read_time_ms_{0};
    std::uint64_t last_write_time_ms_{0};
    std::uint64_t last_non_heartbeat_read_time_ms_{0};
    std::uint64_t last_non_heartbeat_write_time_ms_{0};
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::socket socket_;
    std::atomic<bool> stopped_{false};
    std::atomic<std::uint64_t> pending_bytes_total_{0};
    std::atomic<std::uint64_t> write_pending_bytes_{0};
    std::mutex write_limit_mutex_;
    std::unordered_map<std::uint32_t, std::uint64_t> write_pending_bytes_by_stream_;
    using channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_frame)>;
    using stop_channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code)>;
    std::unique_ptr<channel_type> write_channel_;
    std::unique_ptr<stop_channel_type> stop_channel_;
    std::unordered_map<uint32_t, std::shared_ptr<mux_stream>> streams_;
};

}    // namespace mux

#endif
