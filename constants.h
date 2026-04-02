#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <array>
#include <chrono>
#include <string>
#include <cstddef>
#include <cstdint>

#include "reality/handshake/fingerprint.h"
namespace constants
{

namespace net
{
constexpr std::size_t kBufferSize = 4096;
constexpr int kRetryIntervalSec = 1;
constexpr int kMaxListenConnections = 1024;
constexpr uint64_t kOriginalDstLogIntervalMs = 10'000;
constexpr uint64_t kFnvOffsetBasis64 = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime64 = 1099511628211ULL;
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
constexpr std::size_t kRelayBufferSize = 16L * 1024;
}    // namespace fallback

namespace log
{
constexpr uint32_t kFlushIntervalSec = 3;
constexpr uint32_t kFileSize = 50U * 1024U * 1024U;
constexpr uint32_t kFileCount = 5;
}    // namespace log

namespace mux
{
constexpr std::size_t kWriteChannelCapacity = 1024;
constexpr std::size_t kStreamRecvChannelCapacity = 1024;
constexpr std::size_t kStopChannelCapacity = 1;
constexpr uint32_t kControlFrameSendTimeoutSec = 1;
constexpr uint32_t kReconnectRetryIntervalSec = 2;
}    // namespace mux

namespace replay
{
constexpr auto kWindow = std::chrono::seconds(auth::kMaxClockSkewSec * 2);
}    // namespace replay

namespace socks
{
constexpr uint32_t kAuthFailDelayMs = 200;
}    // namespace socks

namespace udp
{
constexpr std::size_t kMaxSessions = 1024;
constexpr std::size_t kPacketChannelCapacity = 1024;
constexpr std::size_t kMaxCacheEntries = 1024;
constexpr uint64_t kCacheTtlMs = 10ULL * 60ULL * 1000ULL;
constexpr uint64_t kNegativeCacheTtlMs = 3ULL * 1000ULL;
constexpr std::size_t kMaxReplySockets = 512;
constexpr std::size_t kMaxPacketSize = 8192;
constexpr std::size_t kMaxPayload = 65507;
constexpr std::size_t kTcpControlReadBufferSize = 1024;
constexpr std::size_t kTcpControlIgnoreLimitBytes = 4096;
constexpr uint32_t kTunnelPollIntervalMs = 200;
}    // namespace udp

namespace tls_limits
{
constexpr std::size_t kMaxCiphertextRecordLen = tls::kMaxTlsPlaintextLen + 256;
constexpr uint32_t kMaxCompatCcsRecords = 8;
constexpr std::size_t kMaxHandshakeMessageSize = 64L * 1024;
constexpr std::size_t kMaxHandshakeReassembleBuffer = kMaxHandshakeMessageSize + 4;
constexpr std::size_t kMaxUnauthenticatedClientHelloLen = 64L * 1024;
constexpr std::array<uint16_t, 3> kFallbackCipherSuites = {
    tls::consts::cipher::kTlsAes128GcmSha256,
    tls::consts::cipher::kTlsAes256GcmSha384,
    tls::consts::cipher::kTlsChacha20Poly1305Sha256,
};
}    // namespace tls_limits

namespace reality_limits
{
constexpr uint16_t kDefaultTlsPort = 443;
constexpr std::size_t kMaxEncryptedRecordLen = 18432;
constexpr uint32_t kMaxHandshakeRecords = 256;
constexpr std::size_t kMaxHandshakeBufferSize = 1024L * 1024;
constexpr uint32_t kMaxHandshakeMessageSize = static_cast<uint32_t>(kMaxHandshakeBufferSize - 4);
constexpr std::size_t kHandshakeBufferCompactThreshold = 32L * 1024;
constexpr std::array<reality::fingerprint_type, 4> kFetchFingerprints = {
    reality::fingerprint_type::kChrome120,
    reality::fingerprint_type::kIOS14,
    reality::fingerprint_type::kFirefox120,
    reality::fingerprint_type::kAndroid11OkHttp,
};
}    // namespace reality_limits

}    // namespace constants

namespace mux
{

namespace log_event
{

constexpr const char* kConnInit = "conn_init";
constexpr const char* kConnEstablished = "conn_established";
constexpr const char* kConnClose = "conn_close";
constexpr const char* kHandshake = "handshake";
constexpr const char* kDataSend = "data_send";
constexpr const char* kDataRecv = "data_recv";
constexpr const char* kStreamOpen = "stream_open";
constexpr const char* kStreamClose = "stream_close";
constexpr const char* kRoute = "route";
constexpr const char* kFallback = "fallback";
constexpr const char* kAuth = "auth";
constexpr const char* kMux = "mux";
constexpr const char* kMuxFrame = "mux_frame";
constexpr const char* kSocks = "socks";
constexpr const char* kDns = "dns";
constexpr const char* kTimeout = "timeout";
constexpr const char* kCert = "cert";

}    // namespace log_event

}    // namespace mux

#endif
