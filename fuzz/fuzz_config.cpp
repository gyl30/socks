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
REFLECT_STRUCT(mux::config::reality_t::fallback_guard_t, enabled, rate_per_sec, burst, circuit_fail_threshold, circuit_open_sec, state_ttl_sec);
REFLECT_STRUCT(mux::config::reality_t,
               fallback_guard,
               sni,
               fingerprint,
               dest,
               type,
               strict_cert_verify,
               replay_cache_max_entries,
               private_key,
               public_key,
               short_id);
REFLECT_STRUCT(mux::config::limits_t, max_connections, max_buffer, max_streams);
REFLECT_STRUCT(mux::config::heartbeat_t, enabled, min_interval, max_interval, min_padding, max_padding);
REFLECT_STRUCT(mux::config::monitor_t, enabled, port);
REFLECT_STRUCT(mux::config, mode, log, inbound, outbound, socks, fallbacks, timeout, reality, limits, heartbeat, monitor);
}    // namespace reflect

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    const std::string input(reinterpret_cast<const char*>(data), size);

    mux::config cfg;
    reflect::deserialize_struct(cfg, input);

    return 0;
}
