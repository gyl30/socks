#ifndef REALITY_SESSION_H
#define REALITY_SESSION_H

#include <boost/system/detail/error_code.hpp>

#include "reality/types.h"

namespace reality
{
struct reality_record_context
{
    negotiated_params negotiated;
    traffic_key_material read_keys;
    traffic_key_material write_keys;
};

[[nodiscard]] reality_record_context build_reality_record_context(const client_handshake_result& handshake_result, boost::system::error_code& ec);

[[nodiscard]] reality_record_context build_reality_record_context(const authenticated_session& authenticated, boost::system::error_code& ec);

}    // namespace reality

#endif
