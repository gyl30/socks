#ifndef REALITY_SESSION_INTERNAL_H
#define REALITY_SESSION_INTERNAL_H

#include <utility>

#include "reality/session/session.h"

namespace reality::session_internal
{

class engine_access
{
   public:
    [[nodiscard]] static mux::reality_engine take_engine(reality_session&& session) { return std::move(session).take_engine(); }
};

}    // namespace reality::session_internal

#endif
