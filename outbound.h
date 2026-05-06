#ifndef OUTBOUND_H
#define OUTBOUND_H

#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include "config.h"
#include "config_type_facts.h"
#include "udp_proxy_outbound.h"
#include "tcp_outbound_stream.h"

namespace relay
{

struct resolved_outbound
{
    const config::outbound_entry_t* entry = nullptr;
    config_type::outbound_class outbound_class = config_type::outbound_class::kUnsupported;
};

[[nodiscard]] resolved_outbound resolve_outbound(const config& cfg, std::string_view outbound_tag);
[[nodiscard]] std::shared_ptr<tcp_outbound_stream> create_tcp_outbound_for_resolved(const boost::asio::any_io_executor& executor,
                                                                                    uint32_t conn_id,
                                                                                    uint64_t trace_id,
                                                                                    const config& cfg,
                                                                                    const std::string& outbound_tag,
                                                                                    const resolved_outbound& outbound,
                                                                                    uint32_t connect_mark);
[[nodiscard]] boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_proxy_outbound(const boost::asio::any_io_executor& executor,
                                                                                                     uint32_t conn_id,
                                                                                                     uint64_t trace_id,
                                                                                                     const config& cfg,
                                                                                                     const std::string& outbound_tag,
                                                                                                     uint32_t connect_mark);

}    // namespace relay

#endif
