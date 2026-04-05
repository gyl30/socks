#ifndef REALITY_MATERIAL_PROVIDER_H
#define REALITY_MATERIAL_PROVIDER_H

#include <boost/system/error_code.hpp>

#include "config.h"
#include "site_material.h"

namespace reality
{

[[nodiscard]] site_material load_site_material(const mux::config& cfg, boost::system::error_code& ec);

}    // namespace reality

#endif
