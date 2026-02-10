#include <string>
#include <cstddef>
#include <cstdint>

#include "config.h"
#include "reflect.h"

namespace reflect
{
REFLECT_STRUCT(mux::config::log_t, level, file);
REFLECT_STRUCT(mux::config::inbound_t, host, port);
REFLECT_STRUCT(mux::config::outbound_t, host, port);
REFLECT_STRUCT(mux::config::socks_t, host, port, auth, username, password);
REFLECT_STRUCT(mux::config::fallback_entry, sni, host, port);
REFLECT_STRUCT(mux::config::timeout_t, read, write, idle);
REFLECT_STRUCT(mux::config::reality_t, sni, fingerprint, dest, type, private_key, public_key, short_id);
REFLECT_STRUCT(mux::config::limits_t, max_connections, max_buffer, max_streams);
REFLECT_STRUCT(mux::config::heartbeat_t, enabled, min_interval, max_interval, min_padding, max_padding);
REFLECT_STRUCT(mux::config::monitor_t, enabled, port, token, min_interval_ms);
REFLECT_STRUCT(mux::config, mode, log, inbound, outbound, socks, fallbacks, timeout, reality, limits, heartbeat, monitor);
}    // namespace reflect

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::string input(reinterpret_cast<const char*>(data), size);

    mux::config cfg;
    reflect::deserialize_struct(cfg, input);

    return 0;
}
