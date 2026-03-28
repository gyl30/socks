#ifndef REALITY_SESSION_H
#define REALITY_SESSION_H

#include <vector>
#include <cstdint>

#include <boost/system/detail/error_code.hpp>

#include "reality/types.h"

namespace mux
{

class reality_engine;

}    // namespace mux

namespace reality
{

struct traffic_key_material
{
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> iv;
};

class reality_session
{
   public:
    reality_session() = default;
    reality_session(const reality_session&) = delete;
    reality_session& operator=(const reality_session&) = delete;
    reality_session(reality_session&&) = default;
    reality_session& operator=(reality_session&&) = default;

    [[nodiscard]] static reality_session from_client_handshake(const client_handshake_result& handshake_result, boost::system::error_code& ec);
    [[nodiscard]] static reality_session from_authenticated_session(const authenticated_session& authenticated, boost::system::error_code& ec);
    [[nodiscard]] const negotiated_params& negotiated() const { return negotiated_; }
    [[nodiscard]] mux::reality_engine take_engine() &&;

   private:
    enum class perspective : std::uint8_t
    {
        kClient,
        kServer,
    };

    [[nodiscard]] static reality_session build_from_parts(const negotiated_params& negotiated,
                                                          const traffic_secrets& secrets,
                                                          perspective session_perspective,
                                                          boost::system::error_code& ec);

    reality_session(negotiated_params negotiated, traffic_key_material read_keys, traffic_key_material write_keys);

    negotiated_params negotiated_;
    traffic_key_material read_keys_;
    traffic_key_material write_keys_;
};

}    // namespace reality

#endif
