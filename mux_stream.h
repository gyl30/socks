#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include <boost/system/error_code.hpp>
#include <tuple>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_connection;

class mux_stream : public mux_stream_interface, public std::enable_shared_from_this<mux_stream>
{
   public:
    mux_stream(std::uint32_t id,
               std::uint32_t cid,
               const std::string& trace_id,
               const std::shared_ptr<mux_connection>& connection,
               boost::asio::io_context& io_context);

    ~mux_stream() override;

    [[nodiscard]] std::uint32_t id() const;

    [[nodiscard]] boost::asio::awaitable<std::tuple<boost::system::error_code, std::vector<std::uint8_t>>> async_read_some();

    [[nodiscard]] boost::asio::awaitable<boost::system::error_code> async_write_some(const void* data, std::size_t len);
    [[nodiscard]] boost::asio::awaitable<boost::system::error_code> async_write_some(std::vector<std::uint8_t> payload);

    boost::asio::awaitable<void> close();

    void on_data(std::vector<std::uint8_t> data) override;

    void on_close() override;

    void on_reset() override;

   private:
    void close_internal();

   private:
    std::uint32_t id_ = 0;
    connection_context ctx_;
    std::weak_ptr<mux_connection> connection_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::atomic<bool> is_closed_{false};
    std::atomic<bool> fin_sent_{false};
    std::atomic<bool> fin_received_{false};
    std::atomic<std::uint64_t> tx_bytes_{0};
    std::atomic<std::uint64_t> rx_bytes_{0};
};

}    // namespace mux

#endif
