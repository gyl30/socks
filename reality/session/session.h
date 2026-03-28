#ifndef REALITY_SESSION_H
#define REALITY_SESSION_H

#include <boost/system/detail/error_code.hpp>

#include "reality/types.h"

namespace reality
{
struct reality_session
{
    negotiated_params negotiated;
    traffic_key_material read_keys;
    traffic_key_material write_keys;
};

[[nodiscard]] reality_session build_reality_session(const client_handshake_result& handshake_result, boost::system::error_code& ec);

[[nodiscard]] reality_session build_reality_session(const authenticated_session& authenticated, boost::system::error_code& ec);

}    // namespace reality

#endif
