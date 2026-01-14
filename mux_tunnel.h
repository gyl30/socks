#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <memory>

#include "mux_stream.h"
#include "mux_connection.h"

namespace mux
{

template <typename stream_layer>
class mux_tunnel_impl : public std::enable_shared_from_this<mux_tunnel_impl<stream_layer>>
{
   public:
    explicit mux_tunnel_impl(stream_layer socket, reality_engine engine, bool is_client, uint32_t conn_id)
        : connection_(std::make_shared<mux_connection>(std::move(socket), std::move(engine), is_client, conn_id))
    {
    }

    [[nodiscard]] std::shared_ptr<mux_connection> get_connection() const { return connection_; }

    void register_stream(uint32_t id, std::shared_ptr<mux_stream_interface> stream) const
    {
        if (connection_ != nullptr)
        {
            connection_->register_stream(id, std::move(stream));
        }
    }

    boost::asio::awaitable<void> run() const
    {
        if (connection_ != nullptr)
        {
            co_await connection_->start();
        }
    }

    [[nodiscard]] std::shared_ptr<mux_stream> create_stream()
    {
        if (connection_ == nullptr || !connection_->is_open())
        {
            return nullptr;
        }

        uint32_t id = connection_->acquire_next_id();
        auto stream = std::make_shared<mux_stream>(id, connection_->id(), connection_, connection_->get_executor());
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
