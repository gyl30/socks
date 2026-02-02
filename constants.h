#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>
#include <cstddef>

namespace constants
{

namespace net
{
constexpr std::size_t BUFFER_SIZE = 4096;
constexpr int RETRY_INTERVAL_SEC = 1; // Adjusted from 5 to 1
constexpr int MAX_LISTEN_CONNECTIONS = 1024;
}    // namespace net

namespace auth
{
constexpr int MAX_CLOCK_SKEW_SEC = 300;
constexpr std::size_t SESSION_ID_LEN = 32;
constexpr std::size_t AUTH_KEY_LEN = 32;
constexpr std::size_t SALT_LEN = 20;
}    // namespace auth

namespace crypto
{
constexpr std::size_t KEY_LEN_128 = 16;
constexpr std::size_t KEY_LEN_256 = 32;
constexpr std::size_t IV_LEN = 12;
constexpr std::size_t TAG_LEN = 16;
}    // namespace crypto

namespace fallback
{
constexpr int MAX_WAIT_MS = 2000;
}

}    // namespace constants

#endif
