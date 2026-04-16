#ifndef REALITY_PROTOCOL_SESSION_H
#define REALITY_PROTOCOL_SESSION_H

#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "context_pool.h"
#include "proxy_reality_connection.h"
#include "router.h"
#include "trace_store.h"

namespace relay
{

namespace proxy
{
struct tcp_connect_request;
struct udp_associate_request;
}    // namespace proxy

struct reality_protocol_context
{
    uint32_t conn_id = 0;
    std::string local_host;
    uint16_t local_port = 0;
    std::string remote_host;
    uint16_t remote_port = 0;
    std::string sni;
};

class reality_protocol_session
{
   public:
    reality_protocol_session(io_worker& worker,
                             std::shared_ptr<proxy_reality_connection> connection,
                             std::shared_ptr<router> router,
                             std::string inbound_tag,
                             const config& cfg,
                             reality_protocol_context context);

    boost::asio::awaitable<void> start();

   private:
    boost::asio::awaitable<void> start_impl();
    boost::asio::awaitable<void> start_tcp_connect_session(const proxy::tcp_connect_request& request);
    boost::asio::awaitable<void> start_udp_associate_session(const proxy::udp_associate_request& request);

    [[nodiscard]] trace_event make_base_event() const;

   private:
    io_worker& worker_;
    std::shared_ptr<proxy_reality_connection> connection_;
    std::shared_ptr<router> router_;
    std::string inbound_tag_;
    const config& cfg_;
    reality_protocol_context context_;
};

}    // namespace relay

#endif
