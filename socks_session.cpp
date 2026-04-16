#include <memory>
#include <string>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "context_pool.h"
#include "log.h"
#include "net_utils.h"
#include "protocol.h"
#include "run_loop_spawner.h"
#include "socks_protocol_session.h"
#include "socks_session.h"
#include "socks_tcp_session.h"
#include "socks_udp_session.h"
#include "trace_id.h"
#include "trace_store.h"

namespace relay
{

socks_session::socks_session(boost::asio::ip::tcp::socket socket,
                             io_worker& worker,
                             std::shared_ptr<router> router,
                             const uint32_t sid,
                             std::string inbound_tag,
                             const config& cfg,
                             const config::socks_t& settings)
    : sid_(sid),
      trace_id_(generate_trace_id()),
      conn_id_(sid),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      settings_(settings),
      worker_(worker),
      socket_(std::move(socket)),
      router_(std::move(router))
{
    net::load_tcp_socket_endpoints(socket_, local_host_, local_port_, client_host_, client_port_);
}

socks_session::~socks_session() = default;

void socks_session::start() { run_loop_spawner::spawn(worker_, shared_from_this()); }

void socks_session::record_stage(const trace_stage stage, const trace_result result, const socks_protocol_request* request) const
{
    trace_event event;
    event.trace_id = trace_id_;
    event.conn_id = conn_id_;
    event.stage = stage;
    event.result = result;
    event.inbound_tag = inbound_tag_;
    event.inbound_type = "socks";
    event.local_host = local_host_;
    event.local_port = local_port_;
    event.remote_host = client_host_;
    event.remote_port = client_port_;
    if (request != nullptr)
    {
        event.target_host = request->host;
        event.target_port = request->port;
        event.extra = {{"cmd", std::to_string(request->cmd)}};
    }
    trace_store::instance().record_event(std::move(event));
}

void socks_session::stop()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} shutdown client failed {}",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_,
                 ec.message());
    }
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} close client failed {}",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_,
                 ec.message());
    }
}

boost::asio::awaitable<void> socks_session::run_loop()
{
    socks_protocol_session protocol(socket_,
                                    worker_,
                                    cfg_,
                                    settings_,
                                    trace_id_,
                                    conn_id_,
                                    local_host_,
                                    local_port_,
                                    client_host_,
                                    client_port_);

    LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} socks session started",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             local_host_,
             local_port_,
             client_host_,
             client_port_);
    record_stage(trace_stage::kConnAccepted, trace_result::kOk);
    record_stage(trace_stage::kHandshakeStart, trace_result::kOk);
    if (!co_await protocol.handshake())
    {
        record_stage(trace_stage::kHandshakeDone, trace_result::kFail);
        if (!protocol.peer_closed_before_greeting())
        {
            LOG_WARN("{} conn {} local {}:{} remote {}:{} handshake failed",
                     log_event::kSocks,
                     conn_id_,
                     local_host_,
                     local_port_,
                     client_host_,
                     client_port_);
        }
        stop();
        co_return;
    }
    record_stage(trace_stage::kHandshakeDone, trace_result::kOk);

    const auto request = co_await protocol.read_request();
    if (!request.ok)
    {
        record_stage(trace_stage::kRequestDone, trace_result::kFail);
        LOG_WARN("{} conn {} local {}:{} remote {}:{} request invalid",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_);
        stop();
        co_return;
    }
    record_stage(trace_stage::kRequestDone, trace_result::kOk, &request);

    if (request.cmd == socks::kCmdConnect)
    {
        const auto tcp_connect_session =
            std::make_shared<socks_tcp_session>(std::move(socket_), router_, sid_, trace_id_, inbound_tag_, cfg_);
        worker_.group.spawn(
            [tcp_connect_session, host = request.host, port = request.port]() -> boost::asio::awaitable<void>
            { co_await tcp_connect_session->start(host, port); });
        co_return;
    }
    if (request.cmd == socks::kCmdUdpAssociate)
    {
        const auto udp_associate_session =
            std::make_shared<socks_udp_session>(std::move(socket_), worker_, router_, sid_, trace_id_, inbound_tag_, cfg_);
        udp_associate_session->start(request.host, request.port);
        co_return;
    }

    LOG_WARN("{} conn {} local {}:{} remote {}:{} cmd {} unsupported",
             log_event::kSocks,
             conn_id_,
             local_host_,
             local_port_,
             client_host_,
             client_port_,
             request.cmd);
    co_await protocol.reply_error(socks::kRepCmdNotSupported);
}

}    // namespace relay
