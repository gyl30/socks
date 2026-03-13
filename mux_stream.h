#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include <tuple>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "log_context.h"
#include "mux_protocol.h"

namespace mux
{

class mux_connection;

class mux_stream : public std::enable_shared_from_this<mux_stream>
{
   public:
    mux_stream(std::uint32_t id, const config& cfg, boost::asio::io_context& io_context, const std::shared_ptr<mux_connection>& connection);

    ~mux_stream();

    [[nodiscard]] std::uint32_t id() const;
    void close();
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_read(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_read(std::uint32_t timeout_sec, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> on_frame(mux_frame, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write(mux_frame, boost::system::error_code& ec);

   private:
    std::uint32_t id_ = 0;
    const config& cfg_;
   std::uint64_t tx_bytes_{0};
   std::uint64_t rx_bytes_{0};
    static constexpr std::size_t kMaxPendingBytes = 256 * 1024;
    std::size_t pending_bytes_{0};
    std::weak_ptr<mux_connection> connection_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_frame)> recv_channel_;
};

}    // namespace mux

#endif
