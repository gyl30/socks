#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "constants.h"
#include "log.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "reality_protocol_session.h"
#include "reality_tcp_session.h"
#include "reality_udp_session.h"
#include "trace_store.h"

namespace relay
{

reality_protocol_session::reality_protocol_session(io_worker& worker,
                                                   std::shared_ptr<proxy_reality_connection> connection,
                                                   std::shared_ptr<router> router,
                                                   std::string inbound_tag,
                                                   const config& cfg,
                                                   reality_protocol_context context)
    : worker_(worker),
      connection_(std::move(connection)),
      router_(std::move(router)),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      context_(std::move(context))
{
}

boost::asio::awaitable<void> reality_protocol_session::start() { co_await start_impl(); }

boost::asio::awaitable<void> reality_protocol_session::start_impl()
{
    if (connection_ == nullptr)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} dropped without connection",
                 log_event::kRoute,
                 context_.conn_id,
                 context_.local_host,
                 context_.local_port,
                 context_.remote_host,
                 context_.remote_port,
                 context_.sni.empty() ? "unknown" : context_.sni);
        co_return;
    }

    boost::system::error_code ec;
    const auto packet = co_await connection_->read_packet(cfg_.timeout.connect == 0 ? cfg_.timeout.read : cfg_.timeout.connect + 1, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} read initial proxy packet failed {}",
                 log_event::kRoute,
                 context_.conn_id,
                 context_.local_host,
                 context_.local_port,
                 context_.remote_host,
                 context_.remote_port,
                 context_.sni.empty() ? "unknown" : context_.sni,
                 ec.message());
        co_return;
    }

    proxy::tcp_connect_request tcp_request;
    if (proxy::decode_tcp_connect_request(packet.data(), packet.size(), tcp_request))
    {
        co_await start_tcp_connect_session(tcp_request);
        co_return;
    }

    proxy::udp_associate_request udp_request;
    if (proxy::decode_udp_associate_request(packet.data(), packet.size(), udp_request))
    {
        co_await start_udp_associate_session(udp_request);
        co_return;
    }

    LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} invalid initial proxy request payload_size {}",
             log_event::kRoute,
             context_.conn_id,
             context_.local_host,
             context_.local_port,
             context_.remote_host,
             context_.remote_port,
             context_.sni.empty() ? "unknown" : context_.sni,
             packet.size());
}

boost::asio::awaitable<void> reality_protocol_session::start_tcp_connect_session(const proxy::tcp_connect_request& request)
{
    LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} sni {} type tcp connect target {}:{} payload_size {}",
             log_event::kRoute,
             request.trace_id,
             context_.conn_id,
             context_.local_host,
             context_.local_port,
             context_.remote_host,
             context_.remote_port,
             context_.sni.empty() ? "unknown" : context_.sni,
             request.target_host,
             request.target_port,
             0);
    auto request_done = make_base_event();
    request_done.trace_id = request.trace_id;
    request_done.stage = trace_stage::kRequestDone;
    request_done.result = trace_result::kOk;
    request_done.target_host = request.target_host;
    request_done.target_port = request.target_port;
    request_done.extra = {{"type", "tcp"}};
    trace_store::instance().record_event(std::move(request_done));
    const auto tcp_connect_session = std::make_shared<reality_tcp_session>(
        worker_.io_context, std::move(connection_), router_, context_.conn_id, request.trace_id, inbound_tag_, cfg_);
    co_await tcp_connect_session->start(request);
}

boost::asio::awaitable<void> reality_protocol_session::start_udp_associate_session(const proxy::udp_associate_request& request)
{
    LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} sni {} type udp associate payload_size {}",
             log_event::kRoute,
             request.trace_id,
             context_.conn_id,
             context_.local_host,
             context_.local_port,
             context_.remote_host,
             context_.remote_port,
             context_.sni.empty() ? "unknown" : context_.sni,
             0);
    auto request_done = make_base_event();
    request_done.trace_id = request.trace_id;
    request_done.stage = trace_stage::kRequestDone;
    request_done.result = trace_result::kOk;
    request_done.extra = {{"type", "udp"}};
    trace_store::instance().record_event(std::move(request_done));
    const auto udp_associate_session = std::make_shared<reality_udp_session>(
        worker_.io_context, std::move(connection_), router_, context_.conn_id, request.trace_id, inbound_tag_, cfg_);
    co_await udp_associate_session->start(request);
}

trace_event reality_protocol_session::make_base_event() const
{
    trace_event event;
    event.conn_id = context_.conn_id;
    event.inbound_tag = inbound_tag_;
    event.inbound_type = "reality";
    event.local_host = context_.local_host;
    event.local_port = context_.local_port;
    event.remote_host = context_.remote_host;
    event.remote_port = context_.remote_port;
    return event;
}

}    // namespace relay
