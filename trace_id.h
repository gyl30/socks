#ifndef TRACE_ID_H
#define TRACE_ID_H

#include <random>
#include <cstdint>
#ifdef __cplusplus
extern "C"
{
#endif
#include <openssl/rand.h>
#ifdef __cplusplus
}
#endif

namespace mux
{

[[nodiscard]] inline uint64_t generate_trace_id()
{
    uint64_t trace_id = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&trace_id), static_cast<int>(sizeof(trace_id))) != 1)
    {
        std::random_device rd;
        trace_id = (static_cast<uint64_t>(rd()) << 32) ^ static_cast<uint64_t>(rd());
    }
    if (trace_id == 0)
    {
        trace_id = 1;
    }
    return trace_id;
}

}    // namespace mux

#endif
