#ifndef APP_RUNTIME_H
#define APP_RUNTIME_H

#include <memory>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "outbound.h"
#include "context_pool.h"
#include "reality_inbound.h"
#include "trace_web_server.h"
#include "socks_inbound.h"
#if SOCKS_HAS_TPROXY
#include "tproxy_inbound.h"
#endif
#if SOCKS_HAS_TUN
#include "tun_inbound.h"
#endif

namespace relay
{

class app_runtime
{
   public:
    explicit app_runtime(const config& cfg);

    app_runtime(const app_runtime&) = delete;
    app_runtime& operator=(const app_runtime&) = delete;

    void start();
    void stop();

    [[nodiscard]] io_context_pool& pool() { return pool_; }
    [[nodiscard]] boost::asio::awaitable<void> async_wait_stopped();

   private:
    void start_outbounds();
    void start_web_server();
    void start_inbound(const config::inbound_entry_t& inbound);

   private:
    config cfg_;
    io_context_pool pool_;
    std::vector<std::shared_ptr<outbound_handler>> outbounds_;
    std::shared_ptr<trace_web_server> web_server_;
    std::vector<std::shared_ptr<reality_inbound>> reality_inbounds_;
    std::vector<std::shared_ptr<socks_inbound>> socks_inbounds_;
#if SOCKS_HAS_TPROXY
    std::vector<std::shared_ptr<tproxy_inbound>> tproxy_inbounds_;
#endif
#if SOCKS_HAS_TUN
    std::vector<std::shared_ptr<tun_inbound>> tun_inbounds_;
#endif
};

}    // namespace relay

#endif
