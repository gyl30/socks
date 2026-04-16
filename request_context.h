#ifndef REQUEST_CONTEXT_H
#define REQUEST_CONTEXT_H

#include <cstdint>
#include <optional>
#include <string>

namespace relay
{

enum class request_transport : uint8_t
{
    kTcp,
    kUdp
};

enum class request_command : uint8_t
{
    kConnect,
    kAssociate,
    kDatagram
};

struct request_context
{
    uint64_t trace_id = 0;
    uint32_t conn_id = 0;
    request_transport transport = request_transport::kTcp;
    request_command command = request_command::kConnect;
    std::string inbound_tag{};
    std::string inbound_type{};
    std::string target_host{};
    uint16_t target_port = 0;
    std::optional<std::string> target_ip = std::nullopt;
    std::optional<std::string> target_domain = std::nullopt;
    std::string client_host{};
    uint16_t client_port = 0;
    std::string local_host{};
    uint16_t local_port = 0;
};

}    // namespace relay

#endif
