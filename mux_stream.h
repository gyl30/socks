#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include <memory>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "mux_protocol.h"
namespace mux
{

class mux_connection;
struct config;

class mux_stream
{
   public:
    mux_stream(uint32_t id, const config& cfg, boost::asio::io_context& io_context, const std::shared_ptr<mux_connection>& connection);

    ~mux_stream();

    [[nodiscard]] uint32_t id() const;
    void close();
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_read(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_read(uint32_t timeout_sec, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> on_frame(mux_frame, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write(mux_frame, boost::system::error_code& ec) const;

   private:
    uint32_t id_ = 0;
    const config& cfg_;
    std::weak_ptr<mux_connection> connection_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_frame)> recv_channel_;
};

}    // namespace mux

#endif
