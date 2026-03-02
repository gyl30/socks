#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include "config.h"
#include "mux_stream.h"
#include "mux_connection.h"
#include "reality_engine.h"

namespace mux
{

class mux_tunnel_impl : public std::enable_shared_from_this<mux_tunnel_impl>
{
   public:
    explicit mux_tunnel_impl(boost::asio::ip::tcp::socket socket,
                             boost::asio::io_context& io_context,
                             reality_engine engine,
                             const config& cfg,
                             task_group& group,
                             std::uint32_t conn_id,
                             const std::string& trace_id = "")
        : connection_(std::make_shared<mux_connection>(std::move(socket), io_context, std::move(engine), cfg, group, conn_id, trace_id))
    {
    }

    [[nodiscard]] std::shared_ptr<mux_connection> connection() const { return connection_; }

    void run()
    {
        if (connection_ == nullptr)
        {
            return;
        }
        connection_->start();
    }
    void set_new_stream_cb(std::function<boost::asio::awaitable<void>(mux_frame)> cb)
    {
        if (connection_ == nullptr)
        {
            return;
        }
        connection_->set_new_stream_cb(std::move(cb));
    }
    [[nodiscard]] std::shared_ptr<mux_stream> create_stream()
    {
        if (connection_ == nullptr)
        {
            return nullptr;
        }
        return connection_->create_stream();
    }

    void remove_stream(const std::shared_ptr<mux_stream>& stream) const
    {
        if (connection_ != nullptr)
        {
            connection_->remove_stream(stream);
        }
    }

   private:
    std::shared_ptr<mux_connection> connection_;
};

}    // namespace mux

#endif
