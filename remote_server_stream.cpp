// NOLINTBEGIN(misc-include-cleaner)
#include <boost/asio/co_spawn.hpp>    // NOLINT(misc-include-cleaner): required for co_spawn declarations.
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <boost/asio/io_context.hpp>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include <boost/asio/detached.hpp>

#include "log.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "protocol.h"
#include "statistics.h"
#include "mux_codec.h"
#include "remote_server.h"
#include "remote_session.h"
#include "remote_udp_session.h"

namespace mux
{

void remote_server::install_syn_callback(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel, const connection_context& ctx)
{
    const std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> weak_tunnel = tunnel;
    tunnel->connection()->set_syn_callback(
        [weak_self = std::weak_ptr<remote_server>(shared_from_this()), weak_tunnel, ctx](const std::uint32_t id, std::vector<std::uint8_t> p)
        {
            if (auto self = weak_self.lock())
            {
                if (auto tunnel = weak_tunnel.lock())
                {
                    auto* stream_io_context = &tunnel->connection()->io_context();
                    boost::asio::co_spawn(
                        *stream_io_context,
                        [self, tunnel, ctx, id, p = std::move(p), stream_io_context]() mutable
                        { return self->process_stream_request(tunnel, ctx, id, std::move(p), *stream_io_context); },
                        boost::asio::detached);
                }
            }
        });
}

connection_context remote_server::build_stream_context(const connection_context& ctx, const syn_payload& syn)
{
    connection_context stream_ctx = ctx;
    if (!syn.trace_id.empty())
    {
        stream_ctx.trace_id(syn.trace_id);
    }
    return stream_ctx;
}

boost::asio::awaitable<void> remote_server::send_stream_reset(const std::shared_ptr<mux_connection>& connection, const std::uint32_t stream_id)
{
    (void)co_await connection->send_async(stream_id, kCmdRst, {});
}

boost::asio::awaitable<void> remote_server::reject_stream_for_limit(const std::shared_ptr<mux_connection>& connection,
                                                             const connection_context& ctx,
                                                             const std::uint32_t stream_id)
{
    statistics::instance().inc_stream_limit_rejected();
    LOG_CTX_WARN(ctx, "{} stream limit reached", log_event::kMux);
    const ack_payload ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
    std::vector<std::uint8_t> ack_data;
    mux_codec::encode_ack(ack, ack_data);
    (void)co_await connection->send_async(stream_id, kCmdAck, std::move(ack_data));
    co_await send_stream_reset(connection, stream_id);
}

boost::asio::awaitable<void> remote_server::handle_tcp_connect_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                               const connection_context& stream_ctx,
                                                               const std::uint32_t stream_id,
                                                               const syn_payload& syn,
                                                               const std::size_t payload_size,
                                                               boost::asio::io_context& io_context)
{
    LOG_CTX_INFO(stream_ctx, "{} stream {} type tcp connect target {} {} payload size {}", log_event::kMux, stream_id, syn.addr, syn.port, payload_size);
    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_session>(connection, stream_id, io_context, stream_ctx);
    sess->set_manager(tunnel);
    if (!tunnel->try_register_stream(stream_id, sess))
    {
        LOG_CTX_WARN(stream_ctx, "{} stream id conflict {}", log_event::kMux, stream_id);
        co_await send_stream_reset(connection, stream_id);
        co_return;
    }
    co_await sess->start(syn);
}

boost::asio::awaitable<void> remote_server::handle_udp_associate_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                                 const connection_context& stream_ctx,
                                                                 const std::uint32_t stream_id,
                                                                 boost::asio::io_context& io_context) const
{
    LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, stream_id);
    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_udp_session>(
        connection, stream_id, io_context, stream_ctx, timeout_config_, queues_config_.udp_session_recv_channel_capacity);
    sess->set_manager(tunnel);
    if (!tunnel->try_register_stream(stream_id, sess))
    {
        LOG_CTX_WARN(stream_ctx, "{} stream id conflict {}", log_event::kMux, stream_id);
        co_await send_stream_reset(connection, stream_id);
        co_return;
    }
    co_await sess->start();
}

boost::asio::awaitable<void> remote_server::process_stream_request(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel,
                                                            const connection_context& ctx,
                                                            const std::uint32_t stream_id,
                                                            std::vector<std::uint8_t> payload,
                                                            boost::asio::io_context& io_context) const
{
    const auto connection = tunnel->connection();
    if (!connection->can_accept_stream())
    {
        co_await reject_stream_for_limit(connection, ctx, stream_id);
        co_return;
    }

    syn_payload syn;
    if (!mux_codec::decode_syn(payload.data(), payload.size(), syn))
    {
        LOG_CTX_WARN(ctx, "{} stream {} invalid syn", log_event::kMux, stream_id);
        co_await send_stream_reset(connection, stream_id);
        co_return;
    }

    auto stream_ctx = build_stream_context(ctx, syn);
    if (!syn.trace_id.empty())
    {
        LOG_CTX_DEBUG(stream_ctx, "{} linked client trace id {}", log_event::kMux, syn.trace_id);
    }

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        co_await handle_tcp_connect_stream(tunnel, stream_ctx, stream_id, syn, payload.size(), io_context);
        co_return;
    }
    if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        co_await handle_udp_associate_stream(tunnel, stream_ctx, stream_id, io_context);
        co_return;
    }

    LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, stream_id, syn.socks_cmd);
    co_await send_stream_reset(connection, stream_id);
}

}    // namespace mux
// NOLINTEND(misc-include-cleaner)
