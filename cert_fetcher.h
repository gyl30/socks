#ifndef CERT_FETCHER_H
#define CERT_FETCHER_H

#include <string>
#include <cstdint>

#include <boost/system/error_code.hpp>

#include "site_material.h"

namespace reality
{

[[nodiscard]] site_material fetch_site_material(std::string host,
                                                std::uint16_t port,
                                                std::string sni,
                                                boost::system::error_code& ec,
                                                const std::string& trace_id = "");

}    // namespace reality

#endif
