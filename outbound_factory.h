#ifndef OUTBOUND_FACTORY_H
#define OUTBOUND_FACTORY_H

#include <memory>
#include <string>

#include "outbound.h"

namespace relay
{

[[nodiscard]] std::shared_ptr<outbound_handler> make_direct_outbound_handler(const std::string& outbound_tag);
[[nodiscard]] std::shared_ptr<outbound_handler> make_block_outbound_handler(const std::string& outbound_tag);
[[nodiscard]] std::shared_ptr<outbound_handler> make_proxy_outbound_handler(const std::string& outbound_tag, const std::string& outbound_type);

}    // namespace relay

#endif
