#include <string>
#include <string_view>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <utility>

#include "log.h"
#include "log_context.h"
#include "cert_manager.h"

namespace reality
{

namespace
{

std::string normalize_sni_key(std::string_view sni)
{
    std::size_t begin = 0;
    while (begin < sni.size() && std::isspace(static_cast<unsigned char>(sni[begin])) != 0)
    {
        ++begin;
    }
    std::size_t end = sni.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(sni[end - 1])) != 0)
    {
        --end;
    }
    std::string normalized;
    normalized.reserve(end - begin);
    for (std::size_t i = begin; i < end; ++i)
    {
        const char ch = sni[i];
        if (ch == '\0')
        {
            break;
        }
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    while (!normalized.empty() && normalized.back() == '.')
    {
        normalized.pop_back();
    }
    return normalized;
}

}    // namespace

site_material_manager::site_material_manager(const std::size_t capacity) : cache_(capacity > 0 ? capacity : 1) {}

std::optional<site_material_snapshot> site_material_manager::get_material_snapshot(const std::string& cache_key)
{
    const auto key = normalize_sni_key(cache_key);
    return cache_.get(key);
}

void site_material_manager::mark_fetch_started(const std::string& cache_key,
                                               const std::string& target_host,
                                               const std::string& target_sni,
                                               const std::uint16_t port,
                                               const std::uint64_t attempt_at_unix_seconds,
                                               const std::string& trace_id)
{
    const auto key = normalize_sni_key(cache_key);
    cache_.upsert(key,
                  site_material_snapshot{},
                  [&](site_material_snapshot& snapshot)
                  {
                      snapshot.target_host = target_host;
                      snapshot.target_sni = target_sni;
                      snapshot.port = port;
                      snapshot.fetch_in_progress = true;
                      snapshot.last_attempt_at_unix_seconds = attempt_at_unix_seconds;
                  });

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(key);

    LOG_CTX_INFO(ctx, "{} fetch started target {}:{}", mux::log_event::kCert, target_host, port);
}

void site_material_manager::set_material(const std::string& cache_key,
                                         const std::string& target_host,
                                         const std::string& target_sni,
                                         const std::uint16_t port,
                                         site_material material,
                                         const std::uint64_t next_refresh_at_unix_seconds,
                                         const std::string& trace_id)
{
    const auto key = normalize_sni_key(cache_key);
    const auto certs = material.certificate_chain.size();
    const auto cert_msg = material.certificate_message.size();
    const auto alpn = material.fingerprint.alpn;
    const auto cipher = material.fingerprint.cipher_suite;
    const auto sh_exts = material.server_hello_extension_types.size();
    const auto ee_exts = material.encrypted_extension_types.size();
    const auto ee_padding = material.encrypted_extensions_padding_len.value_or(0);
    const auto ccs = material.sends_change_cipher_spec;
    const auto hs_records = material.encrypted_handshake_record_sizes.size();
    const auto groups = material.key_share_groups.size();
    const auto fetched_at = material.fetched_at_unix_seconds;
    auto material_holder = std::move(material);
    cache_.upsert(key,
                  site_material_snapshot{},
                  [&](site_material_snapshot& snapshot) mutable
                  {
                      snapshot.target_host = target_host;
                      snapshot.target_sni = target_sni;
                      snapshot.port = port;
                      snapshot.fetch_in_progress = false;
                      snapshot.last_attempt_at_unix_seconds = fetched_at;
                      snapshot.last_success_at_unix_seconds = fetched_at;
                      snapshot.next_refresh_at_unix_seconds = next_refresh_at_unix_seconds;
                      snapshot.last_error.clear();
                      snapshot.material = std::move(material_holder);
                  });

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(key);

    LOG_CTX_INFO(
        ctx,
        "{} cached site material certs {} cert_msg {} alpn '{}' cipher 0x{:04x} sh_exts {} ee_exts {} ee_padding {} ccs {} hs_records {} groups {}",
        mux::log_event::kCert,
        certs,
        cert_msg,
        alpn,
        cipher,
        sh_exts,
        ee_exts,
        ee_padding,
        ccs,
        hs_records,
        groups);
}

void site_material_manager::set_fetch_failure(const std::string& cache_key,
                                              const std::string& target_host,
                                              const std::string& target_sni,
                                              const std::uint16_t port,
                                              std::string error,
                                              const std::uint64_t attempt_at_unix_seconds,
                                              const std::uint64_t next_refresh_at_unix_seconds,
                                              const std::string& trace_id)
{
    const auto key = normalize_sni_key(cache_key);
    bool has_stale_material = false;
    const auto log_error = error;
    auto error_holder = std::move(error);
    cache_.upsert(key,
                  site_material_snapshot{},
                  [&](site_material_snapshot& snapshot) mutable
                  {
                      snapshot.target_host = target_host;
                      snapshot.target_sni = target_sni;
                      snapshot.port = port;
                      snapshot.fetch_in_progress = false;
                      snapshot.last_attempt_at_unix_seconds = attempt_at_unix_seconds;
                      snapshot.next_refresh_at_unix_seconds = next_refresh_at_unix_seconds;
                      snapshot.last_error = std::move(error_holder);
                      has_stale_material = snapshot.material.has_value();
                  });

    mux::connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.sni(key);

    LOG_CTX_WARN(
        ctx, "{} fetch failed target {}:{} stale_material {} error {}", mux::log_event::kCert, target_host, port, has_stale_material, log_error);
}

}    // namespace reality
