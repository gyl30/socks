#ifndef OUTBOUND_H
#define OUTBOUND_H

#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "proxy_udp_upstream.h"
#include "upstream.h"

namespace relay
{

class outbound_handler
{
   public:
    outbound_handler(std::string tag, std::string type);
    virtual ~outbound_handler() = default;

   public:
    [[nodiscard]] const std::string& tag() const { return tag_; }
    [[nodiscard]] const std::string& type() const { return type_; }
    [[nodiscard]] virtual std::shared_ptr<upstream> create_tcp_upstream(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const = 0;
    [[nodiscard]] virtual boost::asio::awaitable<proxy_udp_connect_result> connect_udp_upstream(
        const boost::asio::any_io_executor& executor, uint32_t conn_id, uint64_t trace_id, const config& cfg) const = 0;

   private:
    std::string tag_;
    std::string type_;
};

[[nodiscard]] std::shared_ptr<outbound_handler> make_outbound_handler(const config& cfg, const std::string& outbound_tag);
[[nodiscard]] boost::asio::awaitable<proxy_udp_connect_result> connect_udp_proxy_outbound(const boost::asio::any_io_executor& executor,
                                                                                           uint32_t conn_id,
                                                                                           uint64_t trace_id,
                                                                                           const config& cfg,
                                                                                           const std::string& outbound_tag);

}    // namespace relay

#endif
