#ifndef TLS_SERVER_NAME_H
#define TLS_SERVER_NAME_H

#include <string_view>

namespace tls
{

[[nodiscard]] bool valid_sni_hostname(std::string_view hostname);

}    // namespace tls

#endif
