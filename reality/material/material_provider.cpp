#include <string>

#include <boost/asio/error.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "cert_fetcher.h"
#include "site_material.h"
#include "reality/material/material_provider.h"
namespace reality
{

site_material load_site_material(const mux::config& cfg, boost::system::error_code& ec)
{
    const std::string target_host = cfg.reality.sni;
    if (target_host.empty())
    {
        LOG_ERROR("reality site material load failed because reality.sni is empty");
        ec = boost::asio::error::invalid_argument;
        return {};
    }

    site_material material = fetch_site_material(target_host, constants::reality_limits::kDefaultTlsPort, target_host, ec);
    if (ec)
    {
        LOG_ERROR("reality site material load failed target {}:{} error {}", target_host, constants::reality_limits::kDefaultTlsPort, ec.message());
        return {};
    }

    LOG_INFO(
        "reality site material loaded target {} certs {} cert_msg {} alpn '{}' cipher 0x{:04x} sh_exts {} ee_exts {} ee_padding {} ccs {} hs_records "
        "{} groups {}",
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
