#include <string>
#include <utility>
#include <cstdint>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include "log.h"
#include "config.h"
#include "cert_fetcher.h"
#include "reality/material/material_provider.h"

namespace reality
{

namespace
{

constexpr std::uint16_t kMaterialPort = 443;

}    // namespace

site_material load_site_material(const mux::config& cfg, boost::system::error_code& ec)
{
    ec.clear();
    site_material material;

    const std::string target_host = cfg.reality.sni;
    if (target_host.empty())
    {
        LOG_ERROR("reality site material load failed because reality.sni is empty");
        ec = boost::asio::error::invalid_argument;
        return {};
    }

    material = fetch_site_material(target_host, kMaterialPort, target_host, ec, "site-material:" + target_host);
    if (ec)
    {
        LOG_ERROR("reality site material load failed target {}:{} error {}", target_host, kMaterialPort, ec.message());
        return {};
    }

    LOG_INFO("reality site material loaded target {} certs {} cert_msg {} alpn '{}' cipher 0x{:04x} sh_exts {} ee_exts {} ee_padding {} ccs {} hs_records {} groups {}",
             target_host,
             material.certificate_chain.size(),
             material.certificate_message.size(),
             material.fingerprint.alpn,
             material.fingerprint.cipher_suite,
             material.server_hello_extension_types.size(),
             material.encrypted_extension_types.size(),
             material.encrypted_extensions_padding_len.value_or(0),
             material.sends_change_cipher_spec,
             material.encrypted_handshake_record_sizes.size(),
             material.key_share_groups.size());
    return material;
}

}    // namespace reality
