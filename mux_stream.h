#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include <asio.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

#include "log_context.h"
#include "mux_connection.h"
#include "mux_protocol.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream : public mux_stream_interface, public std::enable_shared_from_this<mux_stream>
{
   public:
    mux_stream(std::uint32_t id,
               std::uint32_t cid,
               const std::string& trace_id,
               const std::shared_ptr<mux_connection>& connection,
               const asio::any_io_executor& ex);

    ~mux_stream() override;

    [[nodiscard]] std::uint32_t id() const;

    [[nodiscard]] asio::awaitable<std::tuple<std::error_code, std::vector<std::uint8_t>>> async_read_some();

    [[nodiscard]] asio::awaitable<std::error_code> async_write_some(const void* data, std::size_t len);

    asio::awaitable<void> close();

    void on_data(std::vector<uint8_t> data) override;

    void on_close() override;

    void on_reset() override;

   private:
    void close_internal();

   private:
    std::uint32_t id_ = 0;
    connection_context ctx_;
    std::weak_ptr<mux_connection> connection_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::atomic<bool> is_closed_{false};
    std::atomic<bool> fin_sent_{false};
    std::atomic<bool> fin_received_{false};
    std::atomic<uint64_t> tx_bytes_{0};
    std::atomic<uint64_t> rx_bytes_{0};
};

}    // namespace mux

#endif
