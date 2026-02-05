#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstddef>
#include <cstdint>

namespace constants
{

namespace net
{
constexpr std::size_t kBufferSize = 4096;
constexpr int kRetryIntervalSec = 1;
constexpr int kMaxListenConnections = 1024;
}    // namespace net

namespace auth
{
constexpr int kMaxClockSkewSec = 300;
constexpr std::size_t kSessionIdLen = 32;
constexpr std::size_t kAuthKeyLen = 32;
constexpr std::size_t kSaltLen = 20;
}    // namespace auth

namespace crypto
{
constexpr std::size_t kKeyLen128 = 16;
constexpr std::size_t kKeyLen256 = 32;
constexpr std::size_t kIvLen = 12;
constexpr std::size_t kTagLen = 16;
}    // namespace crypto

namespace fallback
{
constexpr int kMaxWaitMs = 2000;
}

}    // namespace constants

#endif
