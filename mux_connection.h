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
#include "config.h"
#include "log_context.h"
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

    mux_connection(asio::ip::tcp::socket socket,
                   reality_engine engine,
                   bool is_client,
                   uint32_t conn_id,
                   const std::string& trace_id = "",
                   const config::timeout_t& timeout_cfg = {});

    virtual ~mux_connection() = default;

    auto get_executor() { return socket_.get_executor(); }
    std::string trace_id() const { return ctx_.trace_id; }

    void set_syn_callback(syn_callback_t cb) { syn_callback_ = std::move(cb); }

    virtual void register_stream(uint32_t id, std::shared_ptr<mux_stream_interface> stream);

    virtual void remove_stream(uint32_t id);

    [[nodiscard]] uint32_t acquire_next_id() { return next_stream_id_.fetch_add(2, std::memory_order_relaxed); }
    [[nodiscard]] virtual uint32_t id() const { return cid_; }

    [[nodiscard]] asio::awaitable<void> start();

    [[nodiscard]] virtual asio::awaitable<std::error_code> send_async(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload);

    void stop();

    [[nodiscard]] bool is_open() const { return connection_state_.load(std::memory_order_acquire) == mux_connection_state::connected; }

   private:
    asio::awaitable<void> read_loop();

    asio::awaitable<void> write_loop();

    asio::awaitable<void> timeout_loop();

    void on_mux_frame(mux::frame_header header, std::vector<uint8_t> payload);

   private:
    connection_context ctx_;
    uint32_t cid_;
    uint64_t read_bytes = 0;
    uint64_t write_bytes = 0;
    stream_map_t streams_;
    asio::steady_timer timer_;
    std::mutex streams_mutex_;
    syn_callback_t syn_callback_;
    asio::ip::tcp::socket socket_;
    reality_engine reality_engine_;
    mux_dispatcher mux_dispatcher_;
    std::atomic<uint32_t> next_stream_id_;
    std::atomic<mux_connection_state> connection_state_;
    std::chrono::steady_clock::time_point last_read_time;
    std::chrono::steady_clock::time_point last_write_time;
    asio::experimental::concurrent_channel<void(std::error_code, mux_write_msg)> write_channel_;
    config::timeout_t timeout_config_;
};

#endif
