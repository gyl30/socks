#include <iostream>
#include <string>

#include "tls/core.h"
#include "reality/config_validation.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/fingerprint_internal.h"

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

}    // namespace

int main()
{
    reality::fingerprint_template chrome_spec;
    reality::fingerprint_template chrome_mlkem_spec;
    reality::fingerprint_template invalid_spec;

    const bool support_ok =
        require(reality::is_supported_fingerprint_name("random"), "random should be supported") &&
        require(reality::is_supported_fingerprint_name("chrome"), "chrome should be supported") &&
        require(reality::is_supported_fingerprint_name("chrome-mlkem768"), "chrome-mlkem768 should normalize to a supported name") &&
        require(!reality::is_supported_fingerprint_name("chrome_120"), "legacy chrome_120 should stay unsupported");

    const bool build_ok =
        require(reality::build_named_fingerprint_template("chrome", chrome_spec), "build chrome fingerprint failed") &&
        require(reality::build_named_fingerprint_template("chrome_mlkem768", chrome_mlkem_spec), "build chrome_mlkem768 fingerprint failed") &&
        require(!reality::build_named_fingerprint_template("not-real", invalid_spec), "unknown fingerprint should fail");

    const bool chrome_shape_ok =
        require(reality::fingerprint_has_key_share_group(chrome_spec, tls::consts::group::kX25519), "chrome should advertise x25519") &&
        require(!reality::fingerprint_has_key_share_group(chrome_spec, tls::consts::group::kX25519MLKEM768),
                "chrome should not advertise x25519_mlkem768");

    const bool chrome_mlkem_shape_ok =
        require(reality::fingerprint_has_key_share_group(chrome_mlkem_spec, tls::consts::group::kX25519), "chrome_mlkem768 should keep x25519") &&
        require(reality::fingerprint_has_key_share_group(chrome_mlkem_spec, tls::consts::group::kX25519MLKEM768),
                "chrome_mlkem768 should advertise x25519_mlkem768");

    return support_ok && build_ok && chrome_shape_ok && chrome_mlkem_shape_ok ? 0 : 1;
}
