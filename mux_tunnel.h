#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <asio.hpp>

#include "config.h"
#include "mux_stream.h"
#include "mux_connection.h"
#include "reality_engine.h"

namespace mux
{

template <typename stream_layer>
class mux_tunnel_impl : public std::enable_shared_from_this<mux_tunnel_impl<stream_layer>>
{
   public:
    explicit mux_tunnel_impl(stream_layer socket,
                             asio::io_context& io_context,
                             reality_engine engine,
                             bool is_client,
                             std::uint32_t conn_id,
                             const std::string& trace_id = "",
                             const config::timeout_t& timeout_cfg = {},
                             const config::limits_t& limits_cfg = {},
                             const config::heartbeat_t& heartbeat_cfg = {})
        : connection_(std::make_shared<mux_connection>(
              std::move(socket), io_context, std::move(engine), is_client, conn_id, trace_id, timeout_cfg, limits_cfg, heartbeat_cfg))
    {
    }

    [[nodiscard]] std::shared_ptr<mux_connection> connection() const { return connection_; }

    void register_stream(std::uint32_t id, std::shared_ptr<mux_stream_interface> stream) const
    {
        if (connection_ != nullptr)
        {
            connection_->register_stream(id, std::move(stream));
        }
    }

    [[nodiscard]] bool try_register_stream(std::uint32_t id, std::shared_ptr<mux_stream_interface> stream) const
    {
        if (connection_ == nullptr)
        {
            return false;
        }
        if (connection_->try_register_stream(id, std::move(stream)))    // GCOVR_EXCL_LINE
        {
            return true;
        }
        return false;
    }

    asio::awaitable<void> run() const    // GCOVR_EXCL_LINE
    {
        if (connection_ == nullptr)
        {
            co_return;
        }
        co_await connection_->start();
    }

    [[nodiscard]] std::shared_ptr<mux_stream> create_stream(const std::string& trace_id = "")
    {
        if (connection_ == nullptr)
        {
            return nullptr;
        }
        return connection_->create_stream(trace_id);
    }

    void remove_stream(std::uint32_t id) const
    {
        if (connection_ != nullptr)
        {
            connection_->remove_stream(id);
        }
    }

   private:
    std::shared_ptr<mux_connection> connection_;
};

}    // namespace mux

#endif
