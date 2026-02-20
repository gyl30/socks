#ifndef MUX_CONNECTION_H
#define MUX_CONNECTION_H

#include <atomic>
#include <boost/system/error_code.hpp>
#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <functional>
#include <unordered_map>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_dispatcher.h"
#include "reality_engine.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;

enum class mux_connection_state : std::uint8_t
{
    kConnected,
    kDraining,
    kClosing,
    kClosed
};

struct mux_write_msg
{
    std::uint8_t command = 0;
    std::uint32_t stream_id = 0;
    std::vector<std::uint8_t> payload;
};

class mux_connection : public std::enable_shared_from_this<mux_connection>
{
   public:
    using stream_map_t = std::unordered_map<std::uint32_t, std::shared_ptr<mux_stream_interface>>;
    using syn_callback_t = std::function<void(std::uint32_t, std::vector<std::uint8_t>)>;

    mux_connection(boost::asio::ip::tcp::socket socket,
                   boost::asio::io_context& io_context,
                   reality_engine engine,
                   bool is_client,
                   std::uint32_t conn_id,
                   const std::string& trace_id = "",
                   const config::timeout_t& timeout_cfg = {},
                   const config::limits_t& limits_cfg = {},
                   const config::heartbeat_t& heartbeat_cfg = {});

    virtual ~mux_connection();

    [[nodiscard]] boost::asio::io_context& io_context() const { return io_context_; }
    [[nodiscard]] std::string trace_id() const { return ctx_.trace_id(); }

    void set_syn_callback(syn_callback_t cb) { syn_callback_ = std::move(cb); }

    virtual bool register_stream(std::uint32_t id, std::shared_ptr<mux_stream_interface> stream);
    [[nodiscard]] virtual bool register_stream_checked(std::uint32_t id, std::shared_ptr<mux_stream_interface> stream);
    [[nodiscard]] bool try_register_stream(std::uint32_t id, std::shared_ptr<mux_stream_interface> stream);

    virtual void remove_stream(std::uint32_t id);

    [[nodiscard]] std::uint32_t acquire_next_id() { return next_stream_id_.fetch_add(2, std::memory_order_relaxed); }
    [[nodiscard]] virtual std::uint32_t id() const { return cid_; }
    void mark_started_for_external_calls();

    [[nodiscard]] boost::asio::awaitable<void> start();

    [[nodiscard]] virtual boost::asio::awaitable<boost::system::error_code> send_async(std::uint32_t stream_id,
                                                                                       std::uint8_t cmd,
                                                                                       std::vector<std::uint8_t> payload);

    void stop();
    void release_resources();

    [[nodiscard]] bool is_open() const
    {
        const auto s = connection_state_.load(std::memory_order_acquire);
        return s == mux_connection_state::kConnected || s == mux_connection_state::kDraining;
    }

    [[nodiscard]] bool can_accept_stream();
    [[nodiscard]] bool has_stream(std::uint32_t id);
    [[nodiscard]] std::shared_ptr<mux_stream> create_stream(const std::string& trace_id = "");

   private:
    boost::asio::awaitable<void> start_impl();
    boost::asio::awaitable<void> read_loop();

    boost::asio::awaitable<void> write_loop();

    boost::asio::awaitable<void> timeout_loop();

    boost::asio::awaitable<void> heartbeat_loop();

    [[nodiscard]] bool run_inline() const;
    [[nodiscard]] std::shared_ptr<stream_map_t> snapshot_streams() const;
    [[nodiscard]] std::shared_ptr<stream_map_t> detach_streams();
    [[nodiscard]] bool register_stream_local(std::uint32_t id, const std::shared_ptr<mux_stream_interface>& stream);
    [[nodiscard]] bool try_register_stream_local(std::uint32_t id, const std::shared_ptr<mux_stream_interface>& stream);
    void remove_stream_local(std::uint32_t id);
    [[nodiscard]] bool can_accept_stream_local() const;
    [[nodiscard]] bool has_stream_local(std::uint32_t id) const;

    [[nodiscard]] std::shared_ptr<mux_stream_interface> find_stream(std::uint32_t stream_id) const;
    void handle_unknown_stream(std::uint32_t stream_id, std::uint8_t command);
    void handle_stream_frame(const mux::frame_header& header, std::vector<std::uint8_t> payload);
    void on_mux_frame(mux::frame_header header, std::vector<std::uint8_t> payload);
    void stop_impl();
    static void reset_streams_on_stop(const stream_map_t& streams_to_clear);
    void close_socket_on_stop();
    void finalize_stop_state();
    [[nodiscard]] bool should_stop_read(const boost::system::error_code& read_ec, std::size_t n) const;
    void update_read_statistics(std::size_t n);
    std::expected<void, boost::system::error_code> process_decrypted_records();
    [[nodiscard]] bool has_dispatch_failure(const boost::system::error_code& decrypt_ec) const;
    [[nodiscard]] boost::asio::awaitable<bool> read_and_dispatch_once();

   private:
    connection_context ctx_;
    std::uint32_t cid_;
    std::uint64_t read_bytes_ = 0;
    std::uint64_t write_bytes_ = 0;
    std::shared_ptr<stream_map_t> streams_ = std::make_shared<stream_map_t>();
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer timer_;
    syn_callback_t syn_callback_;
    boost::asio::ip::tcp::socket socket_;
    reality_engine reality_engine_;
    mux_dispatcher mux_dispatcher_;
    std::atomic<std::uint32_t> next_stream_id_;
    std::atomic<bool> started_{false};
    std::atomic<mux_connection_state> connection_state_;
    std::atomic<std::uint64_t> last_read_time_ms_{0};
    std::atomic<std::uint64_t> last_write_time_ms_{0};
    config::timeout_t timeout_config_;
    config::limits_t limits_config_;
    config::heartbeat_t heartbeat_config_;

    using channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_write_msg)>;
    std::unique_ptr<channel_type> write_channel_;
};

}    // namespace mux

#endif
