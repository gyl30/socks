#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <memory>
#include <string>
#include <utility>
#include <cstdint>
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
                             reality_engine engine,
                             bool is_client,
                             std::uint32_t conn_id,
                             const std::string& trace_id = "",
                             const config::timeout_t& timeout_cfg = {},
                             const config::limits_t& limits_cfg = {})
        : connection_(std::make_shared<mux_connection>(std::move(socket), std::move(engine), is_client, conn_id, trace_id, timeout_cfg, limits_cfg))
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

    asio::awaitable<void> run() const
    {
        if (connection_ != nullptr)
        {
            co_await connection_->start();
        }
    }

    [[nodiscard]] std::shared_ptr<mux_stream> create_stream(const std::string& trace_id = "")
    {
        if (connection_ == nullptr || !connection_->is_open())
        {
            return nullptr;
        }

        std::uint32_t id = connection_->acquire_next_id();
        auto stream = std::make_shared<mux_stream>(
            id, connection_->id(), trace_id.empty() ? connection_->trace_id() : trace_id, connection_, connection_->executor());
        connection_->register_stream(id, stream);
        return stream;
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
