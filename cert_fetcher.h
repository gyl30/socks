#ifndef CERT_FETCHER_H
#define CERT_FETCHER_H

#include <string>

#include <boost/system/error_code.hpp>

#include "site_material.h"
namespace reality
{

[[nodiscard]] site_material fetch_site_material(
    const std::string& host, uint16_t port, const std::string& sni, boost::system::error_code& ec);

}    // namespace reality

#endif
