#ifndef SOCKS_CONTROL_SESSION_H
#define SOCKS_CONTROL_SESSION_H

#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "config.h"
#include "constants.h"
#include "router.h"
#include "run_loop_spawner.h"
#include "trace_store.h"

namespace relay
{

struct socks_protocol_request;

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(boost::asio::ip::tcp::socket socket,
                  io_worker& worker,
                  std::shared_ptr<router> router,
                  uint32_t sid,
                  std::string inbound_tag,
                  const config& cfg,
                  const config::socks_t& settings);
    ~socks_session();

    void start();

    void stop();

   private:
    boost::asio::awaitable<void> run_loop();
    void record_stage(trace_stage stage, trace_result result, const socks_protocol_request* request = nullptr) const;

   private:
    friend struct run_loop_spawner;

    uint32_t sid_;
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    std::string inbound_tag_;
    std::string local_host_ = "unknown";
    uint16_t local_port_ = 0;
    std::string client_host_ = "unknown";
    uint16_t client_port_ = 0;
    const config& cfg_;
    config::socks_t settings_;
    io_worker& worker_;
    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
};

}    // namespace relay

#endif
