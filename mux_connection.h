#ifndef MUX_CONNECTION_H
#define MUX_CONNECTION_H

#include <span>
#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <string_view>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "constants.h"
#include "mux_protocol.h"
#include "reality/session/engine.h"
namespace reality
{

struct reality_record_context;

}    // namespace reality

namespace mux
{

struct config;
struct io_worker;
struct run_loop_spawner;
class mux_stream;

class mux_connection : public std::enable_shared_from_this<mux_connection>
{
   public:
    mux_connection(boost::asio::ip::tcp::socket socket,
                   io_worker& worker,
                   reality::reality_record_context record_context,
                   const config& cfg,
                   uint32_t conn_id);

    virtual ~mux_connection();

   public:
    void start();
    void stop();

   public:
    void start_accepting_streams();
    boost::asio::awaitable<void> async_wait_stopped();
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_receive_syn(boost::system::error_code& ec) const;
    std::shared_ptr<mux_stream> create_stream();
    std::shared_ptr<mux_stream> create_incoming_stream(uint32_t stream_id);
    void close_and_remove_stream(const std::shared_ptr<mux_stream>& stream);
    void remove_stream(const std::shared_ptr<mux_stream>& stream);
    [[nodiscard]] std::shared_ptr<mux_stream> find_stream(uint32_t stream_id);
    [[nodiscard]] uint32_t conn_id() const
    {
        return cid_;
    }
    boost::asio::awaitable<void> send_async(mux_frame msg, boost::system::error_code& ec);
    boost::asio::awaitable<void> send_async_with_timeout(mux_frame msg, uint32_t timeout_sec, boost::system::error_code& ec);

   private:
    void stop_on_executor();
    boost::asio::awaitable<void> run_loop();
    boost::asio::awaitable<void> read_loop();
    boost::asio::awaitable<void> write_loop();
    boost::asio::awaitable<void> timeout_loop();
    boost::asio::awaitable<void> heartbeat_loop();

   private:
    boost::asio::awaitable<void> handle_heartbeat_frame(std::vector<uint8_t> payload);
    boost::asio::awaitable<void> on_mux_frame(mux::frame_header header, std::vector<uint8_t> payload);
    boost::asio::awaitable<void> handle_unknown_stream(mux::frame_header header, std::vector<uint8_t> payload);
    boost::asio::awaitable<void> handle_stream_frame(const mux::frame_header& header, std::vector<uint8_t> payload);
    boost::asio::awaitable<void> queue_incoming_syn(mux::frame_header header, std::vector<uint8_t> payload);
    boost::asio::awaitable<void> on_tls_record(uint8_t type, std::span<const uint8_t> plaintext, boost::system::error_code& ec);
    boost::asio::awaitable<void> send_heartbeat_frame(boost::system::error_code& ec);
    [[nodiscard]] uint32_t acquire_next_id();
    [[nodiscard]] bool is_stream_limit_reached();
    [[nodiscard]] std::string_view local_host() const;
    [[nodiscard]] std::string_view remote_host() const;
    [[nodiscard]] std::size_t stream_count();

    friend struct run_loop_spawner;

    const config& cfg_;
    uint32_t cid_ = 0;
    std::string local_addr_;
    uint16_t local_port_ = 0;
    std::string remote_addr_;
    uint16_t remote_port_ = 0;
    io_worker& worker_;
    std::mutex mutex_;
    reality_engine reality_engine_;
    uint32_t next_stream_id_ = 0;
    uint64_t read_bytes_ = 0;
    uint64_t write_bytes_ = 0;
    uint64_t last_read_time_ms_{0};
    uint64_t last_write_time_ms_{0};
    uint64_t last_non_heartbeat_read_time_ms_{0};
    uint64_t last_non_heartbeat_write_time_ms_{0};
    uint64_t last_heartbeat_rtt_ms_{0};
    boost::asio::ip::tcp::socket socket_;
    std::atomic<bool> stopped_{false};
    bool heartbeat_rtt_valid_ = false;
    std::vector<uint8_t> pending_plaintext_;
    using channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_frame)>;
    using stop_channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code)>;
    std::unique_ptr<channel_type> write_channel_;
    std::unique_ptr<channel_type> incoming_syn_channel_;
    std::unique_ptr<stop_channel_type> stop_channel_;
    std::unordered_map<uint32_t, std::shared_ptr<mux_stream>> streams_;
};

}    // namespace mux

#endif
