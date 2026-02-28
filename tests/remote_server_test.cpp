// readability-function-cognitive-complexity, readability-isolate-declaration, readability-static-accessed-through-instance)

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <unistd.h>
#include <algorithm>
#include <sys/socket.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "protocol.h"
#include "ch_parser.h"
#include "mux_codec.h"
#include "test_util.h"
#include "crypto_util.h"
#include "scoped_exit.h"
#include "context_pool.h"
#include "reality_auth.h"
#include "tls_record_layer.h"
#include "tls_key_schedule.h"
#include "mock_mux_connection.h"

#define private public
#include "remote_server.h"
#include "remote_session.h"

#undef private
#include "statistics.h"
#include "reality_messages.h"

namespace
{

std::atomic<bool> g_fail_socket_once{false};
std::atomic<int> g_fail_socket_errno{EMFILE};
std::atomic<bool> g_fail_reuse_setsockopt_once{false};
std::atomic<int> g_fail_reuse_setsockopt_errno{EPERM};
std::atomic<bool> g_fail_listen_once{false};
std::atomic<int> g_fail_listen_errno{EACCES};
std::atomic<bool> g_fail_shutdown_once{false};
std::atomic<int> g_fail_shutdown_errno{EIO};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};
std::atomic<bool> g_fail_send_once{false};
std::atomic<int> g_fail_send_errno{EPIPE};
std::atomic<bool> g_fail_rand_bytes_once{false};
std::atomic<bool> g_fail_ed25519_raw_private_key_once{false};
std::atomic<bool> g_fail_pkey_derive_once{false};
std::atomic<int> g_fail_hkdf_add_info_on_call{0};
std::atomic<int> g_hkdf_add_info_call_counter{0};

void reset_failure_injections()
{
    g_fail_socket_once.store(false, std::memory_order_release);
    g_fail_socket_errno.store(EMFILE, std::memory_order_release);
    g_fail_reuse_setsockopt_once.store(false, std::memory_order_release);
    g_fail_reuse_setsockopt_errno.store(EPERM, std::memory_order_release);
    g_fail_listen_once.store(false, std::memory_order_release);
    g_fail_listen_errno.store(EACCES, std::memory_order_release);
    g_fail_shutdown_once.store(false, std::memory_order_release);
    g_fail_shutdown_errno.store(EIO, std::memory_order_release);
    g_fail_close_once.store(false, std::memory_order_release);
    g_fail_close_errno.store(EIO, std::memory_order_release);
    g_fail_send_once.store(false, std::memory_order_release);
    g_fail_send_errno.store(EPIPE, std::memory_order_release);
    g_fail_rand_bytes_once.store(false, std::memory_order_release);
    g_fail_ed25519_raw_private_key_once.store(false, std::memory_order_release);
    g_fail_pkey_derive_once.store(false, std::memory_order_release);
    g_fail_hkdf_add_info_on_call.store(0, std::memory_order_release);
    g_hkdf_add_info_call_counter.store(0, std::memory_order_release);
}

void fail_next_socket(const int err)
{
    g_fail_socket_errno.store(err, std::memory_order_release);
    g_fail_socket_once.store(true, std::memory_order_release);
}

void fail_next_reuse_setsockopt(const int err)
{
    g_fail_reuse_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_reuse_setsockopt_once.store(true, std::memory_order_release);
}

void fail_next_listen(const int err)
{
    g_fail_listen_errno.store(err, std::memory_order_release);
    g_fail_listen_once.store(true, std::memory_order_release);
}

void fail_next_close(const int err)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

void fail_next_shutdown(const int err)
{
    g_fail_shutdown_errno.store(err, std::memory_order_release);
    g_fail_shutdown_once.store(true, std::memory_order_release);
}

void fail_next_send(const int err)
{
    g_fail_send_errno.store(err, std::memory_order_release);
    g_fail_send_once.store(true, std::memory_order_release);
}

void fail_next_rand_bytes() { g_fail_rand_bytes_once.store(true, std::memory_order_release); }

void fail_next_ed25519_raw_private_key() { g_fail_ed25519_raw_private_key_once.store(true, std::memory_order_release); }

void fail_next_pkey_derive() { g_fail_pkey_derive_once.store(true, std::memory_order_release); }

void fail_hkdf_add_info_on_call(const int call_index)
{
    g_hkdf_add_info_call_counter.store(0, std::memory_order_release);
    g_fail_hkdf_add_info_on_call.store(call_index, std::memory_order_release);
}

std::shared_ptr<mux::remote_server::connection_slot_state> remote_server_slot_snapshot(const std::shared_ptr<mux::remote_server>& server)
{
    auto snapshot = std::atomic_load_explicit(&server->connection_slots_, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<mux::remote_server::connection_slot_state>();
}

std::uint32_t remote_server_active_connection_slots(const std::shared_ptr<mux::remote_server>& server)
{
    return remote_server_slot_snapshot(server)->total;
}

std::uint32_t remote_server_source_slots(const std::shared_ptr<mux::remote_server>& server, const std::string& source_key)
{
    const auto snapshot = remote_server_slot_snapshot(server);
    const auto it = snapshot->by_source.find(source_key);
    if (it == snapshot->by_source.end())
    {
        return 0;
    }
    return it->second;
}

void remote_server_set_slot_state(const std::shared_ptr<mux::remote_server>& server,
                                  const std::uint32_t total,
                                  const std::unordered_map<std::string, std::uint32_t>& by_source)
{
    for (;;)
    {
        auto current = std::atomic_load_explicit(&server->connection_slots_, std::memory_order_acquire);
        if (current == nullptr)
        {
            current = std::make_shared<mux::remote_server::connection_slot_state>();
        }

        auto updated = std::make_shared<mux::remote_server::connection_slot_state>();
        updated->total = total;
        updated->by_source = by_source;

        auto expected = current;
        if (std::atomic_compare_exchange_weak_explicit(
                &server->connection_slots_, &expected, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

std::size_t remote_server_tracked_socket_count(const std::shared_ptr<mux::remote_server>& server)
{
    auto snapshot = std::atomic_load_explicit(&server->tracked_connection_sockets_, std::memory_order_acquire);
    if (snapshot == nullptr)
    {
        return 0;
    }
    return snapshot->size();
}

void remote_server_add_expired_tracked_socket(const std::shared_ptr<mux::remote_server>& server, boost::asio::ip::tcp::socket* socket_ptr)
{
    for (;;)
    {
        auto current = std::atomic_load_explicit(&server->tracked_connection_sockets_, std::memory_order_acquire);
        if (current == nullptr)
        {
            current = std::make_shared<mux::remote_server::tracked_socket_map_t>();
        }
        auto updated = std::make_shared<mux::remote_server::tracked_socket_map_t>(*current);
        (*updated)[socket_ptr] = std::weak_ptr<boost::asio::ip::tcp::socket>{};

        auto expected = current;
        if (std::atomic_compare_exchange_weak_explicit(
                &server->tracked_connection_sockets_, &expected, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

const mux::remote_server::fallback_guard_map_t& remote_server_fallback_guard_snapshot(const std::shared_ptr<mux::remote_server>& server)
{
    return server->fallback_guard_states_;
}

std::size_t remote_server_fallback_guard_size(const std::shared_ptr<mux::remote_server>& server)
{
    return remote_server_fallback_guard_snapshot(server).size();
}

std::optional<mux::remote_server::fallback_guard_state> remote_server_find_fallback_guard_state(const std::shared_ptr<mux::remote_server>& server,
                                                                                                const std::string& source_key)
{
    const auto snapshot = remote_server_fallback_guard_snapshot(server);
    const auto it = snapshot.find(source_key);
    if (it == snapshot.end())
    {
        return std::nullopt;
    }
    return it->second;
}

void remote_server_set_fallback_guard_states(const std::shared_ptr<mux::remote_server>& server,
                                             const mux::remote_server::fallback_guard_map_t& states)
{
    server->fallback_guard_states_ = states;
}

void remote_server_cleanup_fallback_guard_state(const std::shared_ptr<mux::remote_server>& server,
                                                const std::chrono::steady_clock::time_point& now)
{
    server->cleanup_fallback_guard_state_locked(server->fallback_guard_states_, now);
}

// NOLINTBEGIN(bugprone-reserved-identifier)
// GNU ld --wrap requires __real_ / __wrap_ symbol names.
extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
extern "C" int __real_listen(int sockfd, int backlog);
extern "C" int __real_shutdown(int sockfd, int how);
extern "C" int __real_close(int fd);
extern "C" ssize_t __real_send(int sockfd, const void* buf, size_t len, int flags);
extern "C" ssize_t __real_sendmsg(int sockfd, const struct msghdr* msg, int flags);
extern "C" int __real_RAND_bytes(unsigned char* buf, int num);
extern "C" EVP_PKEY* __real_EVP_PKEY_new_raw_private_key(int type,
                                                         ENGINE* e,
                                                         const unsigned char* key,
                                                         size_t keylen);
extern "C" int __real_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);
extern "C" int __real_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx,
                                                  const unsigned char* info,
                                                  int infolen);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (g_fail_socket_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_socket_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == SOL_SOCKET && optname == SO_REUSEADDR && g_fail_reuse_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_reuse_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

extern "C" int __wrap_listen(int sockfd, int backlog)
{
    if (g_fail_listen_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_listen_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_listen(sockfd, backlog);
}

extern "C" int __wrap_shutdown(int sockfd, int how)
{
    if (g_fail_shutdown_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_shutdown_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_shutdown(sockfd, how);
}

extern "C" int __wrap_close(int fd)
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        const int injected_errno = g_fail_close_errno.load(std::memory_order_acquire);
        // Keep fd lifecycle realistic while still surfacing close failure to caller.
        (void)__real_close(fd);
        errno = injected_errno;
        return -1;
    }
    return __real_close(fd);
}

extern "C" ssize_t __wrap_send(int sockfd, const void* buf, size_t len, int flags)
{
    if (g_fail_send_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_send_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_send(sockfd, buf, len, flags);
}

extern "C" ssize_t __wrap_sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    if (g_fail_send_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_send_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_sendmsg(sockfd, msg, flags);
}

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)
{
    if (g_fail_rand_bytes_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_RAND_bytes(buf, num);
}

extern "C" EVP_PKEY* __wrap_EVP_PKEY_new_raw_private_key(int type,
                                                         ENGINE* e,
                                                         const unsigned char* key,
                                                         size_t keylen)
{
    if (type == EVP_PKEY_ED25519 && g_fail_ed25519_raw_private_key_once.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return __real_EVP_PKEY_new_raw_private_key(type, e, key, keylen);
}

extern "C" int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen)
{
    if (g_fail_pkey_derive_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_derive(ctx, key, keylen);
}

extern "C" int __wrap_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx,
                                                  const unsigned char* info,
                                                  int infolen)
{
    const int call_no = g_hkdf_add_info_call_counter.fetch_add(1, std::memory_order_acq_rel) + 1;
    const int fail_on = g_fail_hkdf_add_info_on_call.load(std::memory_order_acquire);
    if (fail_on > 0 && call_no == fail_on)
    {
        g_fail_hkdf_add_info_on_call.store(0, std::memory_order_release);
        return 0;
    }
    return __real_EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen);
}
// NOLINTEND(bugprone-reserved-identifier)

std::uint16_t pick_free_port()
{
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    for (std::uint32_t attempt = 0; attempt < 120; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor.is_open())
        {
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)acceptor.close(ec);
        }
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (!ec)
        {
            ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
        }
        if (!ec)
        {
            const auto bound_ep = acceptor.local_endpoint(ec);
            if (!ec)
            {
                return bound_ep.port();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return 0;
}

bool open_ephemeral_acceptor(boost::asio::ip::tcp::acceptor& acceptor,
                             const std::uint32_t max_attempts = 120,
                             const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor.is_open())
        {
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)acceptor.close(ec);
        }
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (!ec)
        {
            ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
        }
        if (!ec)
        {
            ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

bool open_ephemeral_acceptor_with_backlog(boost::asio::ip::tcp::acceptor& acceptor,
                                          const int backlog,
                                          const std::uint32_t max_attempts = 120,
                                          const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor.is_open())
        {
            (void)acceptor.close(ec);
        }
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (!ec)
        {
            ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
        }
        if (!ec)
        {
            ec = acceptor.listen(backlog, ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

template <typename Predicate>
bool wait_for_condition(Predicate predicate,
                        const std::chrono::milliseconds timeout = std::chrono::milliseconds(1500),
                        const std::chrono::milliseconds interval = std::chrono::milliseconds(10))
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (predicate())
        {
            return true;
        }
        std::this_thread::sleep_for(interval);
    }
    return predicate();
}

void drain_io_context(boost::asio::io_context& io_context, const int rounds = 32)
{
    io_context.restart();
    for (int i = 0; i < rounds; ++i)
    {
        if (io_context.poll() == 0)
        {
            break;
        }
    }
    io_context.restart();
}

auto make_thread_join_guard(std::thread& worker)
{
    return make_scoped_exit(
        [&worker]()
        {
            if (worker.joinable())
            {
                worker.join();
            }
        });
}

auto make_pool_thread_guard(mux::io_context_pool& pool, std::thread& worker)
{
    return make_scoped_exit(
        [&pool, &worker]()
        {
            pool.stop();
            if (worker.joinable())
            {
                worker.join();
            }
        });
}

bool start_server_until_listening(const std::shared_ptr<mux::remote_server>& server,
                                  const std::uint32_t max_attempts = 120,
                                  const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        server->start();
        if (server->listen_port() != 0)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

bool open_ephemeral_acceptor_until_ready(boost::asio::ip::tcp::acceptor& acceptor,
                                         const std::uint32_t max_attempts = 120,
                                         const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (ec)
        {
            std::this_thread::sleep_for(backoff);
            continue;
        }
        ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
        }
        if (!ec)
        {
            ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        }
        if (!ec)
        {
            return true;
        }
        boost::system::error_code close_ec;
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)acceptor.close(close_ec);
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

std::shared_ptr<mux::remote_server> construct_server_until_acceptor_ready(mux::io_context_pool& pool,
                                                                          const mux::config& cfg,
                                                                          const std::uint32_t max_attempts = 120,
                                                                          const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        auto server = std::make_shared<mux::remote_server>(pool, cfg);
        if (server->acceptor_.is_open())
        {
            return server;
        }
        std::this_thread::sleep_for(backoff);
    }
    return nullptr;
}

class noop_mux_stream final : public mux::mux_stream_interface
{
   public:
    void on_data(std::vector<std::uint8_t>) override {}
    void on_close() override {}
    void on_reset() override {}
};

}    // namespace

class remote_server_test_fixture : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        reset_failure_injections();
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
    }
    void TearDown() override { reset_failure_injections(); }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& server_pub_key() const { return server_pub_key_; }
    [[nodiscard]] const std::vector<uint8_t>& info_random() const { return info_random_; }
    [[nodiscard]] mux::config make_server_cfg(std::uint16_t port,
                                              const std::vector<mux::config::fallback_entry>& fallbacks,
                                              const std::string& short_id) const
    {
        mux::config cfg;
        cfg.inbound.host = "127.0.0.1";
        cfg.inbound.port = port;
        cfg.fallbacks = fallbacks;
        cfg.reality.private_key = server_priv_key();
        cfg.reality.short_id = short_id;
        return cfg;
    }

    std::vector<uint8_t> build_valid_sid_ch(const std::string& sni,
                                            const std::string& short_id_hex,
                                            uint32_t timestamp,
                                            std::vector<uint8_t>& out_sid)
    {
        std::uint8_t c_pub[32], c_priv[32];
        if (!reality::crypto_util::generate_x25519_keypair(c_pub, c_priv))
        {
            return {};
        }
        auto shared =
            reality::crypto_util::x25519_derive(reality::crypto_util::hex_to_bytes(server_priv_key()), std::vector<uint8_t>(c_pub, c_pub + 32));
        if (!shared)
        {
            return {};
        }
        auto salt = std::vector<uint8_t>(info_random_.begin(), info_random_.begin() + 20);
        auto prk = reality::crypto_util::hkdf_extract(salt, *shared, EVP_sha256());
        if (!prk)
        {
            return {};
        }
        auto auth_key = reality::crypto_util::hkdf_expand(*prk, reality::crypto_util::hex_to_bytes("5245414c495459"), 16, EVP_sha256());
        if (!auth_key)
        {
            return {};
        }

        std::array<uint8_t, 16> payload;
        const std::array<std::uint8_t, 3> ver{1, 0, 0};
        if (!reality::build_auth_payload(reality::crypto_util::hex_to_bytes(short_id_hex), ver, timestamp, payload))
        {
            return {};
        }

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body =
            reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random_, std::vector<uint8_t>(c_pub, c_pub + 32), sni);

        auto record_tmp = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record_tmp.insert(record_tmp.end(), ch_body.begin(), ch_body.end());

        auto info = mux::ch_parser::parse(record_tmp);
        if (info.sid_offset < 5)
        {
            return {};
        }

        std::vector<uint8_t> aad = ch_body;
        const std::uint32_t aad_sid_offset = info.sid_offset - 5;
        if (aad_sid_offset + 32 > aad.size())
        {
            return {};
        }
        std::fill_n(aad.begin() + aad_sid_offset, 32, 0);

        auto sid_res = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                                          *auth_key,
                                                          std::vector<uint8_t>(info_random_.begin() + 20, info_random_.end()),
                                                          std::vector<uint8_t>(payload.begin(), payload.end()),
                                                          aad);
        if (!sid_res || sid_res->size() != 32)
        {
            return {};
        }
        out_sid = std::move(*sid_res);

        std::copy(out_sid.begin(), out_sid.end(), ch_body.begin() + static_cast<std::ptrdiff_t>(aad_sid_offset));
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
        return record;
    }

   private:
    std::vector<uint8_t> info_random_ = std::vector<uint8_t>(32, 0x42);
    std::string server_priv_key_;
    std::string server_pub_key_;
};

TEST_F(remote_server_test_fixture, AuthFailureTriggersFallback)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    mux::config cfg;
    cfg.inbound.host = "127.0.0.1";
    cfg.inbound.port = 0;
    cfg.fallbacks = {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}};
    cfg.reality.private_key = server_priv_key();
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, AuthFailShortIdMismatch)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    std::vector<uint8_t> sid;

    auto record = build_valid_sid_ch("www.google.com", "ffffffffffffffff", static_cast<uint32_t>(time(nullptr)), sid);

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, ClockSkewDetected)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    std::vector<uint8_t> sid;

    auto record = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<uint32_t>(time(nullptr) - 1000), sid);

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, AuthFailInvalidTLSHeader)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});

        std::vector<uint8_t> invalid_header = {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        boost::asio::write(sock, boost::asio::buffer(invalid_header));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, AuthFailBufferTooShort)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});

        std::vector<uint8_t> short_buf = {0x16, 0x03, 0x03, 0x00};
        boost::asio::write(sock, boost::asio::buffer(short_buf));

        sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, AuthFailBufferTooShortPreservesPartialHeaderForFallback)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    auto fallback_payload = std::make_shared<std::vector<std::uint8_t>>();
    auto fallback_payload_ready = std::make_shared<std::atomic<bool>>(false);
    fallback_acceptor.async_accept(
        [fallback_payload, fallback_payload_ready](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (accept_ec)
            {
                fallback_payload->clear();
                fallback_payload_ready->store(true, std::memory_order_release);
                return;
            }
            auto peer_socket = std::make_shared<boost::asio::ip::tcp::socket>(std::move(peer));
            auto read_buf = std::make_shared<std::array<std::uint8_t, 4>>();
            boost::asio::async_read(*peer_socket,
                                    boost::asio::buffer(*read_buf),
                                    [peer_socket, read_buf, fallback_payload, fallback_payload_ready](boost::system::error_code, const std::size_t n)
                                    {
                                        fallback_payload->assign(read_buf->begin(), read_buf->begin() + n);
                                        fallback_payload_ready->store(true, std::memory_order_release);
                                    });
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});

        const std::array<std::uint8_t, 1> first = {0x16};
        const std::array<std::uint8_t, 3> remain = {0x03, 0x03, 0x00};
        boost::asio::write(sock, boost::asio::buffer(first), ec);
        ASSERT_FALSE(ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        boost::asio::write(sock, boost::asio::buffer(remain), ec);
        ASSERT_FALSE(ec);
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        ASSERT_FALSE(ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    EXPECT_TRUE(mux::test::co_wait_until(
        [fallback_payload_ready]() { return fallback_payload_ready->load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    if (fallback_payload_ready->load(std::memory_order_acquire))
    {
        EXPECT_EQ(*fallback_payload, std::vector<std::uint8_t>({0x16, 0x03, 0x03, 0x00}));
    }
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, AuthFailBodyTooShortPreservesPartialBodyForFallback)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    auto fallback_payload = std::make_shared<std::vector<std::uint8_t>>();
    auto fallback_payload_ready = std::make_shared<std::atomic<bool>>(false);
    fallback_acceptor.async_accept(
        [fallback_payload, fallback_payload_ready](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (accept_ec)
            {
                fallback_payload->clear();
                fallback_payload_ready->store(true, std::memory_order_release);
                return;
            }
            auto peer_socket = std::make_shared<boost::asio::ip::tcp::socket>(std::move(peer));
            auto read_buf = std::make_shared<std::array<std::uint8_t, 7>>();
            boost::asio::async_read(*peer_socket,
                                    boost::asio::buffer(*read_buf),
                                    [peer_socket, read_buf, fallback_payload, fallback_payload_ready](boost::system::error_code, const std::size_t n)
                                    {
                                        fallback_payload->assign(read_buf->begin(), read_buf->begin() + n);
                                        fallback_payload_ready->store(true, std::memory_order_release);
                                    });
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});

        const std::array<std::uint8_t, 7> partial = {0x16, 0x03, 0x03, 0x00, 0x06, 0x01, 0x02};
        boost::asio::write(sock, boost::asio::buffer(partial), ec);
        ASSERT_FALSE(ec);
        (void)sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        ASSERT_FALSE(ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    EXPECT_TRUE(mux::test::co_wait_until(
        [fallback_payload_ready]() { return fallback_payload_ready->load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    if (fallback_payload_ready->load(std::memory_order_acquire))
    {
        EXPECT_EQ(*fallback_payload, std::vector<std::uint8_t>({0x16, 0x03, 0x03, 0x00, 0x06, 0x01, 0x02}));
    }
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, FallbackResolveFail)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    const auto resolve_fail_before = mux::statistics::instance().fallback_resolve_failures();
    const auto resolve_error_before = mux::statistics::instance().fallback_resolve_errors();
    const auto resolve_timeout_before = mux::statistics::instance().fallback_resolve_timeouts();

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "nonexistent.invalid", .port = "443"}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer("TRIGGER FALLBACK"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([resolve_fail_before]() { return mux::statistics::instance().fallback_resolve_failures() > resolve_fail_before; },
                                   std::chrono::milliseconds(10000)));
    EXPECT_TRUE(wait_for_condition(
        [resolve_error_before, resolve_timeout_before]()
        { return mux::statistics::instance().fallback_resolve_errors() > resolve_error_before ||
                 mux::statistics::instance().fallback_resolve_timeouts() > resolve_timeout_before; },
        std::chrono::milliseconds(10000)));

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, FallbackConnectFail)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    const auto connect_fail_before = mux::statistics::instance().fallback_connect_failures();
    const auto connect_error_before = mux::statistics::instance().fallback_connect_errors();

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = "1"}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer("TRIGGER FALLBACK"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(
        wait_for_condition([connect_fail_before]() { return mux::statistics::instance().fallback_connect_failures() > connect_fail_before; }));
    EXPECT_TRUE(
        wait_for_condition([connect_error_before]() { return mux::statistics::instance().fallback_connect_errors() > connect_error_before; }));

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, FallbackConnectTimeoutIncrementsMetricWhenBacklogSaturated)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor saturated_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_with_backlog(saturated_acceptor, 1));
    const auto saturated_port = saturated_acceptor.local_endpoint().port();

    boost::asio::ip::tcp::socket queued_client_a(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)queued_client_a.connect({boost::asio::ip::make_address("127.0.0.1"), saturated_port}, ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket queued_client_b(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)queued_client_b.connect({boost::asio::ip::make_address("127.0.0.1"), saturated_port}, ec);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(saturated_port)}}, "0102030405060708");
    cfg.timeout.read = 8;
    cfg.timeout.connect = 1;
    cfg.timeout.write = 100;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    const auto connect_fail_before = mux::statistics::instance().fallback_connect_failures();
    const auto connect_timeout_before = mux::statistics::instance().fallback_connect_timeouts();
    auto fallback_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    mux::connection_context ctx;
    ctx.conn_id(557);
    ctx.remote_addr("127.0.0.20");
    ctx.trace_id("fallback-connect-timeout");

    std::atomic<bool> done_ready{false};
    const auto start = std::chrono::steady_clock::now();
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, fallback_socket, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->handle_fallback(fallback_socket, std::vector<std::uint8_t>{0x16}, ctx, "backlog.test");
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(8)));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(wait_for_condition([connect_fail_before]() { return mux::statistics::instance().fallback_connect_failures() > connect_fail_before; },
                                   std::chrono::milliseconds(3000)));
    EXPECT_TRUE(wait_for_condition([connect_timeout_before]()
                                   { return mux::statistics::instance().fallback_connect_timeouts() > connect_timeout_before; },
                                   std::chrono::milliseconds(3000)));
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 6);

    boost::system::error_code close_ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)queued_client_a.close(close_ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)queued_client_b.close(close_ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)saturated_acceptor.cancel(close_ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)saturated_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, FallbackWriteFailIncrementsMetric)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);
    auto pool_cleanup = make_scoped_exit(
        [&]()
        {
            pool.stop();
            if (pool_thread.joinable())
            {
                pool_thread.join();
            }
        });

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();

    auto server = std::make_shared<mux::remote_server>(
        pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    auto server_cleanup = make_scoped_exit(
        [&]()
        {
            if (server != nullptr)
            {
                server->stop();
            }
        });
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();

    auto fallback_peer = std::make_shared<std::shared_ptr<boost::asio::ip::tcp::socket>>();
    auto fallback_accepted = std::make_shared<std::atomic<bool>>(false);
    fallback_acceptor.async_accept(
        [fallback_peer, fallback_accepted](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                *fallback_peer = std::make_shared<boost::asio::ip::tcp::socket>(std::move(peer));
            }
            fallback_accepted->store(true, std::memory_order_release);
        });
    auto acceptor_cleanup = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.close(close_ec);
            if (*fallback_peer != nullptr && (*fallback_peer)->is_open())
            {
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->close(close_ec);
            }
        });

    const auto write_fail_before = mux::statistics::instance().fallback_write_failures();
    const auto write_error_before = mux::statistics::instance().fallback_write_errors();
    fail_next_send(EPIPE);

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port}, ec);
        ASSERT_FALSE(ec);

        static constexpr char kTrigger[] = "TRIGGER FALLBACK";
        const auto wrote = ::write(sock.native_handle(), kTrigger, sizeof(kTrigger) - 1);
        ASSERT_GT(wrote, 0);
    }

    EXPECT_TRUE(mux::test::co_wait_until(
        [fallback_accepted]() { return fallback_accepted->load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    EXPECT_TRUE(wait_for_condition([write_fail_before]() { return mux::statistics::instance().fallback_write_failures() > write_fail_before; },
                                   std::chrono::milliseconds(3000)));
    EXPECT_TRUE(wait_for_condition([write_error_before]() { return mux::statistics::instance().fallback_write_errors() > write_error_before; },
                                   std::chrono::milliseconds(3000)));
}

TEST_F(remote_server_test_fixture, HandleFallbackWriteTimeoutIncrementsMetric)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();

    auto cfg = make_server_cfg(0, {{.sni = "timeout.test", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708");
    cfg.timeout.write = 1;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    auto fallback_peer = std::make_shared<std::shared_ptr<boost::asio::ip::tcp::socket>>();
    auto fallback_accepted = std::make_shared<std::atomic<bool>>(false);
    fallback_acceptor.async_accept(
        [fallback_peer, fallback_accepted](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                boost::system::error_code option_ec;
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)peer.set_option(boost::asio::socket_base::receive_buffer_size(1024), option_ec);
                (void)option_ec;
                *fallback_peer = std::make_shared<boost::asio::ip::tcp::socket>(std::move(peer));
            }
            fallback_accepted->store(true, std::memory_order_release);
        });

    auto close_all = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.close(close_ec);
            if (*fallback_peer != nullptr && (*fallback_peer)->is_open())
            {
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->close(close_ec);
            }
        });

    const auto write_fail_before = mux::statistics::instance().fallback_write_failures();
    const auto write_timeout_before = mux::statistics::instance().fallback_write_timeouts();
    auto fallback_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    mux::connection_context ctx;
    ctx.conn_id(556);
    ctx.remote_addr("127.0.0.10");
    ctx.trace_id("fallback-write-timeout");

    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, fallback_socket, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            std::vector<std::uint8_t> const buf(16 * 1024 * 1024, 0x5a);
            co_await server->handle_fallback(fallback_socket, buf, ctx, "timeout.test");
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [fallback_accepted]() { return fallback_accepted->load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(6)));
    EXPECT_TRUE(wait_for_condition([write_fail_before]() { return mux::statistics::instance().fallback_write_failures() > write_fail_before; },
                                   std::chrono::milliseconds(2000)));
    EXPECT_TRUE(wait_for_condition([write_timeout_before]() { return mux::statistics::instance().fallback_write_timeouts() > write_timeout_before; },
                                   std::chrono::milliseconds(2000)));
}

TEST_F(remote_server_test_fixture, HandleFallbackReadTimeoutTerminatesProxySession)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();

    auto cfg = make_server_cfg(0, {{.sni = "timeout.test", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708");
    cfg.timeout.read = 1;
    cfg.timeout.write = 1;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    auto fallback_peer = std::make_shared<std::shared_ptr<boost::asio::ip::tcp::socket>>();
    auto fallback_accepted = std::make_shared<std::atomic<bool>>(false);
    fallback_acceptor.async_accept(
        [fallback_peer, fallback_accepted](boost::system::error_code accept_ec, boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                *fallback_peer = std::make_shared<boost::asio::ip::tcp::socket>(std::move(peer));
            }
            fallback_accepted->store(true, std::memory_order_release);
        });

    boost::asio::ip::tcp::acceptor source_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(source_acceptor));
    boost::asio::ip::tcp::socket source_client(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)source_client.connect(source_acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    auto source_server_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)source_acceptor.accept(*source_server_socket, ec);
    ASSERT_FALSE(ec);

    auto close_all = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_client.shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_client.close(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_acceptor.close(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.close(close_ec);
            if (source_server_socket != nullptr && source_server_socket->is_open())
            {
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)source_server_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)source_server_socket->close(close_ec);
            }
            if (*fallback_peer != nullptr && (*fallback_peer)->is_open())
            {
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->close(close_ec);
            }
        });

    mux::connection_context ctx;
    ctx.conn_id(557);
    ctx.remote_addr("127.0.0.11");
    ctx.trace_id("fallback-read-timeout");

    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, source_server_socket, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->handle_fallback(source_server_socket, std::vector<std::uint8_t>{0x16, 0x03, 0x03, 0x00}, ctx, "timeout.test");
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [fallback_accepted]() { return fallback_accepted->load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(6)));
    EXPECT_TRUE(wait_for_condition([source_server_socket]() { return !source_server_socket->is_open(); }, std::chrono::milliseconds(2000)));
}

TEST_F(remote_server_test_fixture, HandleFallbackReadTimeoutRecordedAsGuardFailure)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();

    auto cfg = make_server_cfg(0, {{.sni = "timeout.test", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708");
    cfg.timeout.read = 1;
    cfg.timeout.write = 1;
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.circuit_fail_threshold = 2;
    cfg.reality.fallback_guard.state_ttl_sec = 3600;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    auto fallback_peer = std::make_shared<std::shared_ptr<boost::asio::ip::tcp::socket>>();
    auto fallback_accepted = std::make_shared<std::atomic<bool>>(false);
    fallback_acceptor.async_accept(
        [fallback_peer, fallback_accepted](boost::system::error_code accept_ec, boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                *fallback_peer = std::make_shared<boost::asio::ip::tcp::socket>(std::move(peer));
            }
            fallback_accepted->store(true, std::memory_order_release);
        });

    boost::asio::ip::tcp::acceptor source_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(source_acceptor));
    boost::asio::ip::tcp::socket source_client(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)source_client.connect(source_acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    auto source_server_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)source_acceptor.accept(*source_server_socket, ec);
    ASSERT_FALSE(ec);

    auto close_all = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_client.shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_client.close(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)source_acceptor.close(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.close(close_ec);
            if (source_server_socket != nullptr && source_server_socket->is_open())
            {
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)source_server_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)source_server_socket->close(close_ec);
            }
            if (*fallback_peer != nullptr && (*fallback_peer)->is_open())
            {
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
                // NOLINTNEXTLINE(bugprone-unused-return-value)
                (void)(*fallback_peer)->close(close_ec);
            }
        });

    mux::connection_context ctx;
    ctx.conn_id(558);
    ctx.remote_addr("127.0.0.12");
    ctx.trace_id("fallback-read-timeout-guard");

    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, source_server_socket, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->handle_fallback(source_server_socket, std::vector<std::uint8_t>{0x16, 0x03, 0x03, 0x00}, ctx, "timeout.test");
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [fallback_accepted]() { return fallback_accepted->load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(6)));

    const auto state = remote_server_find_fallback_guard_state(server, "127.0.0.12");
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->consecutive_failures, 1U);
}

TEST_F(remote_server_test_fixture, StartRejectsInvalidAuthConfig)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server =
        std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "abc"));
    server->start();
    EXPECT_FALSE(server->running());
    EXPECT_EQ(server->listen_port(), 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(fallback_triggered.load());
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, StartInvalidAuthConfigHandlesAcceptorCloseFailure)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "abc"));
    fail_next_close(EIO);
    server->start();

    EXPECT_FALSE(server->running());
    EXPECT_FALSE(server->started_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->stop_.load(std::memory_order_acquire));
}

TEST_F(remote_server_test_fixture, StartFailsWhenAcceptorReopenUnavailable)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    ASSERT_TRUE(server->acceptor_.is_open());

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)server->acceptor_.close(ec);
    ASSERT_FALSE(ec);
    ASSERT_FALSE(server->acceptor_.is_open());

    fail_next_socket(EMFILE);
    server->start();

    EXPECT_FALSE(server->running());
    EXPECT_FALSE(server->started_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(server->acceptor_.is_open());
    EXPECT_EQ(server->listen_port(), 0);
}

TEST_F(remote_server_test_fixture, MultiSNIFallback)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor acceptor_a(pool.get_io_context());
    boost::asio::ip::tcp::acceptor acceptor_b(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(acceptor_a));
    ASSERT_TRUE(open_ephemeral_acceptor(acceptor_b));
    const auto fallback_port_a = acceptor_a.local_endpoint().port();
    const auto fallback_port_b = acceptor_b.local_endpoint().port();
    ASSERT_NE(fallback_port_a, static_cast<std::uint16_t>(0));
    ASSERT_NE(fallback_port_b, static_cast<std::uint16_t>(0));

    std::atomic<int> fallback_a_count{0};
    std::atomic<int> fallback_b_count{0};

    acceptor_a.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_a_count++;
            }
        });
    acceptor_b.async_accept(
        [&](boost::system::error_code ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_b_count++;
            }
        });

    std::vector<mux::config::fallback_entry> const fallbacks = {{.sni = "www.a.com", .host = "127.0.0.1", .port = std::to_string(fallback_port_a)},
                                                                {.sni = "www.b.com", .host = "127.0.0.1", .port = std::to_string(fallback_port_b)}};

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, fallbacks, ""));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    auto trigger_fallback = [&](const std::string& sni)
    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body = reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random(), std::vector<uint8_t>(32, 0), sni);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
        boost::asio::write(sock, boost::asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    trigger_fallback("www.a.com");
    trigger_fallback("www.b.com");

    EXPECT_TRUE(wait_for_condition([&fallback_a_count]() { return fallback_a_count.load() == 1; }));
    EXPECT_TRUE(wait_for_condition([&fallback_b_count]() { return fallback_b_count.load() == 1; }));

    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_EQ(fallback_a_count.load(), 1);
    EXPECT_EQ(fallback_b_count.load(), 1);
}

TEST_F(remote_server_test_fixture, WildcardStarFallback)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    ASSERT_NE(fallback_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                fallback_triggered = true;
            }
        });

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {{.sni = "*", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    boost::system::error_code close_ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)fallback_acceptor.cancel(close_ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)fallback_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, RealityDestFallbackUsedWhenNoFallbackEntries)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    boost::asio::ip::tcp::acceptor dest_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor(dest_acceptor));
    const auto dest_port = dest_acceptor.local_endpoint().port();
    ASSERT_NE(dest_port, static_cast<std::uint16_t>(0));
    std::atomic<bool> dest_triggered{false};
    dest_acceptor.async_accept(
        [&](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                dest_triggered = true;
            }
        });

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.dest = std::string("127.0.0.1:") + std::to_string(dest_port);
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port});
        boost::asio::write(sock, boost::asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&dest_triggered]() { return dest_triggered.load(); }));
    boost::system::error_code close_ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dest_acceptor.cancel(close_ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dest_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_TRUE(dest_triggered.load());
}

TEST_F(remote_server_test_fixture, ExactSniFallbackPreferredOverRealityDest)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);
    auto pool_cleanup = make_scoped_exit(
        [&]()
        {
            pool.stop();
            if (pool_thread.joinable())
            {
                pool_thread.join();
            }
        });

    boost::asio::ip::tcp::acceptor exact_acceptor(pool.get_io_context());
    boost::asio::ip::tcp::acceptor dest_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(exact_acceptor));
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(dest_acceptor));
    auto acceptor_cleanup = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)exact_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)exact_acceptor.close(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)dest_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)dest_acceptor.close(close_ec);
        });
    const auto exact_port = exact_acceptor.local_endpoint().port();
    const auto dest_port = dest_acceptor.local_endpoint().port();
    std::atomic<int> exact_count{0};
    std::atomic<int> dest_count{0};
    exact_acceptor.async_accept(
        [&](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                exact_count++;
            }
        });
    dest_acceptor.async_accept(
        [&](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                dest_count++;
            }
        });

    std::vector<mux::config::fallback_entry> const fallbacks = {{.sni = "www.exact.test", .host = "127.0.0.1", .port = std::to_string(exact_port)}};
    auto cfg = make_server_cfg(0, fallbacks, "0102030405060708");
    cfg.reality.dest = std::string("127.0.0.1:") + std::to_string(dest_port);
    std::shared_ptr<mux::remote_server> server = std::make_shared<mux::remote_server>(pool, cfg);
    auto server_cleanup = make_scoped_exit(
        [&]()
        {
            if (server != nullptr)
            {
                server->stop();
            }
        });
    const bool started = start_server_until_listening(server);
    if (!started)
    {
        FAIL() << "server failed to start listening";
    }
    const auto server_port = server->listen_port();

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        boost::system::error_code connect_ec;
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port}, connect_ec);
        ASSERT_FALSE(connect_ec);
        if (connect_ec)
        {
            return;
        }

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body =
            reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random(), std::vector<uint8_t>(32, 0), "www.exact.test");
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
        boost::system::error_code write_ec;
        boost::asio::write(sock, boost::asio::buffer(record), write_ec);
        ASSERT_FALSE(write_ec);
        if (write_ec)
        {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&exact_count]() { return exact_count.load() == 1; }));
    EXPECT_TRUE(wait_for_condition([&dest_count]() { return dest_count.load() == 0; }));

    EXPECT_EQ(exact_count.load(), 1);
    EXPECT_EQ(dest_count.load(), 0);
}

TEST_F(remote_server_test_fixture, InvalidExactSniFallbackDoesNotBlockWildcardFallback)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);
    auto pool_cleanup = make_scoped_exit(
        [&]()
        {
            pool.stop();
            if (pool_thread.joinable())
            {
                pool_thread.join();
            }
        });

    boost::asio::ip::tcp::acceptor wildcard_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(wildcard_acceptor));
    auto acceptor_cleanup = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            (void)wildcard_acceptor.cancel(close_ec);
            (void)wildcard_acceptor.close(close_ec);
        });
    const auto wildcard_port = wildcard_acceptor.local_endpoint().port();
    std::atomic<int> wildcard_count{0};
    wildcard_acceptor.async_accept(
        [&](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                wildcard_count++;
            }
        });

    std::vector<mux::config::fallback_entry> const fallbacks = {
        {.sni = "www.exact.test", .host = "", .port = "443"},
        {.sni = "*", .host = "127.0.0.1", .port = std::to_string(wildcard_port)},
    };
    auto cfg = make_server_cfg(0, fallbacks, "0102030405060708");
    std::shared_ptr<mux::remote_server> server = std::make_shared<mux::remote_server>(pool, cfg);
    auto server_cleanup = make_scoped_exit(
        [&]()
        {
            if (server != nullptr)
            {
                server->stop();
            }
        });
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, static_cast<std::uint16_t>(0));

    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        boost::system::error_code connect_ec;
        (void)sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port}, connect_ec);
        ASSERT_FALSE(connect_ec);
        if (connect_ec)
        {
            return;
        }

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body =
            reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random(), std::vector<uint8_t>(32, 0), "www.exact.test");
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
        boost::system::error_code write_ec;
        boost::asio::write(sock, boost::asio::buffer(record), write_ec);
        ASSERT_FALSE(write_ec);
        if (write_ec)
        {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&wildcard_count]() { return wildcard_count.load() == 1; }));
    EXPECT_EQ(wildcard_count.load(), 1);
}

TEST_F(remote_server_test_fixture, FallbackGuardRateLimitBlocksFallbackDial)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);
    auto pool_cleanup = make_scoped_exit(
        [&]()
        {
            pool.stop();
            if (pool_thread.joinable())
            {
                pool_thread.join();
            }
        });

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(fallback_acceptor));
    auto acceptor_cleanup = make_scoped_exit(
        [&]()
        {
            boost::system::error_code close_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.cancel(close_ec);
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)fallback_acceptor.close(close_ec);
        });
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](boost::system::error_code accept_ec, [[maybe_unused]] boost::asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                fallback_triggered = true;
            }
        });

    auto cfg = make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 0;
    std::shared_ptr<mux::remote_server> server = std::make_shared<mux::remote_server>(pool, cfg);
    auto server_cleanup = make_scoped_exit(
        [&]()
        {
            if (server != nullptr)
            {
                server->stop();
            }
        });
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();

    const auto before = mux::statistics::instance().fallback_rate_limited();
    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        boost::system::error_code connect_ec;
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port}, connect_ec);
        ASSERT_FALSE(connect_ec);
        if (connect_ec)
        {
            return;
        }
        boost::system::error_code write_ec;
        boost::asio::write(sock, boost::asio::buffer("INVALID DATA"), write_ec);
        ASSERT_FALSE(write_ec);
        if (write_ec)
        {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_FALSE(fallback_triggered.load());
    EXPECT_GT(mux::statistics::instance().fallback_rate_limited(), before);
}

TEST_F(remote_server_test_fixture, FallbackGuardCircuitBreakerBlocksSubsequentAttempt)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);
    auto pool_cleanup = make_scoped_exit(
        [&]()
        {
            pool.stop();
            if (pool_thread.joinable())
            {
                pool_thread.join();
            }
        });

    auto cfg = make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = "1"}}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.circuit_fail_threshold = 1;
    cfg.reality.fallback_guard.circuit_open_sec = 2;
    std::shared_ptr<mux::remote_server> server = std::make_shared<mux::remote_server>(pool, cfg);
    auto server_cleanup = make_scoped_exit(
        [&]()
        {
            if (server != nullptr)
            {
                server->stop();
            }
        });
    ASSERT_TRUE(start_server_until_listening(server));
    const auto server_port = server->listen_port();

    const auto before = mux::statistics::instance().fallback_rate_limited();

    auto trigger_invalid = [&]()
    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        boost::system::error_code connect_ec;
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)sock.connect({boost::asio::ip::make_address("127.0.0.1"), server_port}, connect_ec);
        EXPECT_FALSE(connect_ec);
        if (connect_ec)
        {
            return;
        }
        boost::system::error_code write_ec;
        boost::asio::write(sock, boost::asio::buffer("TRIGGER FALLBACK"), write_ec);
        EXPECT_FALSE(write_ec);
        if (write_ec)
        {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    };

    trigger_invalid();
    trigger_invalid();

    EXPECT_GT(mux::statistics::instance().fallback_rate_limited(), before);
}

TEST_F(remote_server_test_fixture, ConstructorHandlesInvalidInboundHostAndUnsupportedFallbackType)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto fallback_type_cfg = make_server_cfg(0, {}, "0102030405060708");
    fallback_type_cfg.reality.type = "udp";
    auto fallback_type_server = construct_server_until_acceptor_ready(pool, fallback_type_cfg);
    ASSERT_NE(fallback_type_server, nullptr);
    EXPECT_EQ(fallback_type_server->fallback_type_, "udp");
    EXPECT_TRUE(fallback_type_server->auth_config_valid_);

    auto invalid_host_cfg = make_server_cfg(0, {}, "0102030405060708");
    invalid_host_cfg.inbound.host = "not-a-valid-ip";
    auto invalid_host_server = std::make_shared<mux::remote_server>(pool, invalid_host_cfg);
    ASSERT_NE(invalid_host_server, nullptr);
    EXPECT_FALSE(invalid_host_server->inbound_config_valid_);
    EXPECT_FALSE(invalid_host_server->acceptor_.is_open());

    invalid_host_server->start();
    EXPECT_FALSE(invalid_host_server->running());
    EXPECT_FALSE(invalid_host_server->started_.load(std::memory_order_acquire));
    EXPECT_TRUE(invalid_host_server->stop_.load(std::memory_order_acquire));
}

TEST_F(remote_server_test_fixture, ConstructorNormalizesZeroMaxConnections)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.max_connections = 0;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_EQ(server->limits_config_.max_connections, 1U);
}

TEST_F(remote_server_test_fixture, ConnectionSlotReservationPreHandshakeLimit)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.max_connections = 2;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    const std::string source_key = "127.0.0.1/32";

    EXPECT_TRUE(server->try_reserve_connection_slot(source_key));
    EXPECT_TRUE(server->try_reserve_connection_slot(source_key));
    EXPECT_FALSE(server->try_reserve_connection_slot(source_key));
    EXPECT_EQ(remote_server_active_connection_slots(server), 2U);

    server->release_connection_slot(source_key);
    EXPECT_EQ(remote_server_active_connection_slots(server), 1U);

    EXPECT_TRUE(server->try_reserve_connection_slot(source_key));
    EXPECT_EQ(remote_server_active_connection_slots(server), 2U);

    server->release_connection_slot(source_key);
    server->release_connection_slot(source_key);
    server->release_connection_slot(source_key);
    EXPECT_EQ(remote_server_active_connection_slots(server), 0U);
}

TEST_F(remote_server_test_fixture, ConnectionSlotReservationRespectsPerSourceLimit)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.max_connections = 4;
    cfg.limits.max_connections_per_source = 1;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_TRUE(server->try_reserve_connection_slot("10.0.0.1/32"));
    EXPECT_FALSE(server->try_reserve_connection_slot("10.0.0.1/32"));
    EXPECT_TRUE(server->try_reserve_connection_slot("10.0.0.2/32"));
    EXPECT_EQ(remote_server_active_connection_slots(server), 2U);

    server->release_connection_slot("10.0.0.1/32");
    server->release_connection_slot("10.0.0.2/32");
    EXPECT_EQ(remote_server_active_connection_slots(server), 0U);
}

TEST_F(remote_server_test_fixture, ConstructorClampsSourcePrefixRange)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.source_prefix_v4 = 255;
    cfg.limits.source_prefix_v6 = 255;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_EQ(server->limits_config_.source_prefix_v4, 32U);
    EXPECT_EQ(server->limits_config_.source_prefix_v6, 128U);
}

TEST_F(remote_server_test_fixture, ConnectionLimitSourceKeyUsesConfiguredSubnet)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.source_prefix_v4 = 24;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));
    boost::asio::ip::tcp::socket client(io_context);
    boost::asio::ip::tcp::socket accepted(io_context);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), acceptor.local_endpoint().port()), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(accepted, ec);
    ASSERT_FALSE(ec);

    auto accepted_ptr = std::make_shared<boost::asio::ip::tcp::socket>(std::move(accepted));
    EXPECT_EQ(server->connection_limit_source_key(accepted_ptr), "127.0.0.0/24");
}

TEST_F(remote_server_test_fixture, SnapshotAndTrackedSocketNullBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    server->active_tunnels_.reset();
    EXPECT_TRUE(server->snapshot_active_tunnels()->empty());

    server->track_connection_socket(nullptr);
    server->untrack_connection_socket(nullptr);

    remote_server_add_expired_tracked_socket(server, reinterpret_cast<boost::asio::ip::tcp::socket*>(0x1));
    const auto tracked = server->snapshot_tracked_connection_sockets();
    EXPECT_TRUE(tracked.empty());
    EXPECT_EQ(remote_server_tracked_socket_count(server), 0U);
}

TEST_F(remote_server_test_fixture, ReleaseConnectionSlotMissingAndDecrementBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.max_connections = 8;
    cfg.limits.max_connections_per_source = 4;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    remote_server_set_slot_state(server, 2, {{"existing", 2}});

    server->release_connection_slot("missing");
    EXPECT_EQ(remote_server_active_connection_slots(server), 1U);
    EXPECT_EQ(remote_server_source_slots(server, "existing"), 2U);

    server->release_connection_slot("existing");
    EXPECT_EQ(remote_server_active_connection_slots(server), 0U);
    EXPECT_EQ(remote_server_source_slots(server, "existing"), 1U);
}

TEST_F(remote_server_test_fixture, ConnectionLimitSourceKeyUnknownAndZeroPrefixBranches)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.source_prefix_v4 = 0;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    auto unconnected = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    EXPECT_EQ(server->connection_limit_source_key(unconnected), "unknown");

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));
    boost::asio::ip::tcp::socket client(io_context);
    boost::asio::ip::tcp::socket accepted(io_context);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), acceptor.local_endpoint().port()), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(accepted, ec);
    ASSERT_FALSE(ec);

    auto accepted_ptr = std::make_shared<boost::asio::ip::tcp::socket>(std::move(accepted));
    EXPECT_EQ(server->connection_limit_source_key(accepted_ptr), "0.0.0.0/0");
}

TEST_F(remote_server_test_fixture, ConnectionLimitSourceKeyIpv6PrefixBranches)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.limits.source_prefix_v6 = 0;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.open(boost::asio::ip::tcp::v6(), ec);
    if (ec)
    {
        GTEST_SKIP() << "IPv6 not available: " << ec.message();
    }
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.set_option(boost::asio::ip::v6_only(true), ec);
    if (ec)
    {
        GTEST_SKIP() << "IPv6 only socket unsupported: " << ec.message();
    }
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address_v6("::1"), 0), ec);
    if (ec)
    {
        GTEST_SKIP() << "IPv6 loopback bind failed: " << ec.message();
    }
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec);

    boost::asio::ip::tcp::socket client(io_context);
    boost::asio::ip::tcp::socket accepted(io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address_v6("::1"), acceptor.local_endpoint().port()), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(accepted, ec);
    ASSERT_FALSE(ec);

    auto accepted_ptr = std::make_shared<boost::asio::ip::tcp::socket>(std::move(accepted));
    const auto v6_prefix_0 = server->connection_limit_source_key(accepted_ptr);
    EXPECT_THAT(v6_prefix_0, ::testing::EndsWith("/0"));

    server->limits_config_.source_prefix_v6 = 65;
    const auto v6_prefix_65 = server->connection_limit_source_key(accepted_ptr);
    EXPECT_THAT(v6_prefix_65, ::testing::EndsWith("/65"));
}

TEST_F(remote_server_test_fixture, BuildConnectionContextUsesUnknownWhenEndpointQueryFails)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto unconnected = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    const auto ctx = mux::remote_server::build_connection_context(unconnected, 42);

    EXPECT_EQ(ctx.local_addr(), "unknown");
    EXPECT_EQ(ctx.local_port(), 0U);
    EXPECT_EQ(ctx.remote_addr(), "unknown");
    EXPECT_EQ(ctx.remote_port(), 0U);
}

TEST_F(remote_server_test_fixture, ConstructorRejectsInvalidRealityDest)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.dest = "invalid-dest-without-port";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_FALSE(server->fallback_dest_valid_);
    EXPECT_FALSE(server->auth_config_valid_);
}

TEST_F(remote_server_test_fixture, ConstructorRejectsInvalidPrivateKeyLength)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.private_key = "0102";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_FALSE(server->auth_config_valid_);
}

TEST_F(remote_server_test_fixture, ConstructorReturnsEarlyWhenBindFails)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    boost::asio::ip::tcp::acceptor occupied(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(occupied));
    const auto used_port = occupied.local_endpoint().port();

    auto cfg = make_server_cfg(used_port, {}, "0102030405060708");
    cfg.inbound.host = "127.0.0.1";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_TRUE(server->private_key_.empty());
}

TEST_F(remote_server_test_fixture, FallbackSelectionAndCertificateTargetBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const std::uint16_t exact_port = pick_free_port();
    const std::uint16_t wildcard_port = pick_free_port();
    const std::uint16_t dest_port = pick_free_port();
    std::vector<mux::config::fallback_entry> const fallbacks = {
        {.sni = "www.exact.test", .host = "127.0.0.1", .port = std::to_string(exact_port)},
        {.sni = "*", .host = "127.0.0.1", .port = std::to_string(wildcard_port)},
    };

    auto cfg = make_server_cfg(0, fallbacks, "0102030405060708");
    cfg.reality.dest = std::string("127.0.0.1:") + std::to_string(dest_port);
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    const auto exact = server->find_fallback_target_by_sni("www.exact.test");
    EXPECT_EQ(exact.first, "127.0.0.1");
    EXPECT_EQ(exact.second, std::to_string(exact_port));
    const auto exact_case = server->find_fallback_target_by_sni("WWW.Exact.Test.");
    EXPECT_EQ(exact_case.first, "127.0.0.1");
    EXPECT_EQ(exact_case.second, std::to_string(exact_port));
    std::string exact_with_nul = "  WWW.Exact.Test. ";
    exact_with_nul.push_back('\0');
    exact_with_nul += "ignored";
    const auto exact_nul = server->find_fallback_target_by_sni(exact_with_nul);
    EXPECT_EQ(exact_nul.first, "127.0.0.1");
    EXPECT_EQ(exact_nul.second, std::to_string(exact_port));

    const auto wildcard = server->find_fallback_target_by_sni("other.domain");
    EXPECT_EQ(wildcard.first, "127.0.0.1");
    EXPECT_EQ(wildcard.second, std::to_string(wildcard_port));

    mux::client_hello_info exact_info{};
    exact_info.sni = "WWW.Exact.Test.";
    const auto exact_target = server->resolve_certificate_target(exact_info);
    EXPECT_EQ(exact_target.fetch_host, "127.0.0.1");
    EXPECT_EQ(exact_target.fetch_port, exact_port);
    EXPECT_EQ(exact_target.cert_sni, "www.exact.test");
    mux::client_hello_info exact_info_nul{};
    exact_info_nul.sni = exact_with_nul;
    const auto exact_target_nul = server->resolve_certificate_target(exact_info_nul);
    EXPECT_EQ(exact_target_nul.fetch_host, "127.0.0.1");
    EXPECT_EQ(exact_target_nul.fetch_port, exact_port);
    EXPECT_EQ(exact_target_nul.cert_sni, "www.exact.test");

    server->fallbacks_.clear();
    const auto dest = server->find_fallback_target_by_sni("none");
    EXPECT_EQ(dest.first, "127.0.0.1");
    EXPECT_EQ(dest.second, std::to_string(dest_port));

    mux::client_hello_info info{};
    info.sni.clear();
    const auto target = server->resolve_certificate_target(info);
    EXPECT_EQ(target.fetch_host, "127.0.0.1");
    EXPECT_EQ(target.fetch_port, static_cast<std::uint16_t>(dest_port));
    EXPECT_TRUE(target.cert_sni.empty());
}

TEST_F(remote_server_test_fixture, FallbackGuardStateMachineBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.circuit_fail_threshold = 1;
    cfg.reality.fallback_guard.circuit_open_sec = 1;
    cfg.reality.fallback_guard.state_ttl_sec = 1;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    mux::connection_context ctx;
    EXPECT_EQ(server->fallback_guard_key(ctx, ""), "unknown");
    ctx.remote_addr("127.0.0.2");
    EXPECT_EQ(server->fallback_guard_key(ctx, ""), "127.0.0.2");

    EXPECT_TRUE(server->consume_fallback_token(ctx, ""));
    EXPECT_FALSE(server->consume_fallback_token(ctx, ""));

    server->record_fallback_result(ctx, "", false);
    EXPECT_FALSE(server->consume_fallback_token(ctx, ""));
    server->record_fallback_result(ctx, "", true);

    ASSERT_GT(remote_server_fallback_guard_size(server), 0U);
    const auto future = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    remote_server_cleanup_fallback_guard_state(server, future);
    EXPECT_EQ(remote_server_fallback_guard_size(server), 0U);

    mux::connection_context unknown_ctx;
    unknown_ctx.remote_addr("127.0.0.9");
    server->record_fallback_result(unknown_ctx, "", false);
}

TEST_F(remote_server_test_fixture, FallbackGuardCapsTrackedSources)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.state_ttl_sec = 3600;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    constexpr std::size_t kMaxFallbackGuardSources = 4096;
    const auto ts = std::chrono::steady_clock::now();
    mux::remote_server::fallback_guard_map_t states;
    states.reserve(kMaxFallbackGuardSources);
    for (std::size_t i = 0; i < kMaxFallbackGuardSources; ++i)
    {
        mux::remote_server::fallback_guard_state state{};
        state.tokens = 1.0;
        state.last_refill = ts;
        state.last_seen = ts;
        states.emplace("source-" + std::to_string(i), state);
    }
    remote_server_set_fallback_guard_states(server, states);
    ASSERT_EQ(remote_server_fallback_guard_size(server), kMaxFallbackGuardSources);

    mux::connection_context new_ctx;
    new_ctx.remote_addr("source-new");
    EXPECT_TRUE(server->consume_fallback_token(new_ctx, ""));

    const auto& snapshot = remote_server_fallback_guard_snapshot(server);
    EXPECT_EQ(snapshot.size(), kMaxFallbackGuardSources);
    EXPECT_NE(snapshot.find("source-new"), snapshot.end());
}

TEST_F(remote_server_test_fixture, FallbackGuardKeyModeIpSniSeparatesBuckets)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.state_ttl_sec = 3600;
    cfg.reality.fallback_guard.key_mode = "ip_sni";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    mux::connection_context ctx;
    ctx.remote_addr("127.0.0.3");

    EXPECT_EQ(server->fallback_guard_key(ctx, "WWW.Example.Com"), "127.0.0.3|www.example.com");
    EXPECT_EQ(server->fallback_guard_key(ctx, "WWW.Example.Com."), "127.0.0.3|www.example.com");

    EXPECT_TRUE(server->consume_fallback_token(ctx, "www.example.com"));
    EXPECT_FALSE(server->consume_fallback_token(ctx, "www.example.com"));
    EXPECT_TRUE(server->consume_fallback_token(ctx, "api.example.com"));
}

TEST_F(remote_server_test_fixture, SetCertificateAsyncPathAfterStart)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    const std::string sni = "post.start.test";
    server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint, "trace-1");

    const auto cert_opt = server->cert_manager_.get_certificate(sni);
    EXPECT_TRUE(cert_opt.has_value());

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, SetCertificateReturnsQuicklyWhenIoContextStopped)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();
    server->stop();
    pool.stop();
    pool_thread.join();

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    const std::string sni = "stopped.ctx.test";

    std::atomic<bool> done{false};
    std::thread setter(
        [&]()
        {
            server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint, "trace-stopped");
            done.store(true, std::memory_order_release);
        });
    auto setter_guard = make_thread_join_guard(setter);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const bool done_before_poll = done.load(std::memory_order_acquire);

    if (!done_before_poll)
    {
        auto& io_context = pool.get_io_context();
        io_context.restart();
        for (int i = 0; i < 20 && !done.load(std::memory_order_acquire); ++i)
        {
            io_context.poll();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    if (setter.joinable())
    {
        setter.join();
    }

    EXPECT_TRUE(done_before_poll);
    const auto cert_opt = server->cert_manager_.get_certificate(sni);
    EXPECT_TRUE(cert_opt.has_value());
}

TEST_F(remote_server_test_fixture, SetCertificateReturnsWhenAsyncQueueBusy)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& io_context = pool.get_io_context();
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_context,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });
    EXPECT_TRUE(mux::test::co_wait_until(
        [&blocker_started]() { return blocker_started.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    const std::string sni = "busy.queue.test";

    std::atomic<bool> setter_done{false};
    std::thread setter(
        [&]()
        {
            server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint, "trace-busy");
            setter_done.store(true, std::memory_order_release);
        });
    auto setter_guard = make_thread_join_guard(setter);

    const bool setter_status = mux::test::co_wait_until(
        [&setter_done]() { return setter_done.load(std::memory_order_acquire); }, std::chrono::milliseconds(500));
    release_blocker.store(true, std::memory_order_release);
    if (setter.joinable())
    {
        setter.join();
    }

    EXPECT_TRUE(setter_status);

    bool cert_ready = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline)
    {
        std::atomic<bool> cert_query_done{false};
        bool cert_query_result = false;
        boost::asio::post(io_context,
                          [server, sni, &cert_query_done, &cert_query_result]()
                          {
                              cert_query_result = server->cert_manager_.get_certificate(sni).has_value();
                              cert_query_done.store(true, std::memory_order_release);
                          });
        EXPECT_TRUE(mux::test::co_wait_until(
            [&cert_query_done]() { return cert_query_done.load(std::memory_order_acquire); }, std::chrono::seconds(1)));
        if (cert_query_result)
        {
            cert_ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(cert_ready);

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test_fixture, SetCertificateRunsWhenAsyncQueueBlockedThenIoStopped)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& io_context = pool.get_io_context();
    std::thread pool_thread([&pool] { pool.run(); });
    auto pool_thread_guard = make_pool_thread_guard(pool, pool_thread);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_context,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });
    EXPECT_TRUE(mux::test::co_wait_until(
        [&blocker_started]() { return blocker_started.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    const std::string sni = "blocked.then.stop.test";

    std::atomic<bool> setter_done{false};
    std::thread setter(
        [&]()
        {
            server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint, "trace-stop-race");
            setter_done.store(true, std::memory_order_release);
        });
    auto setter_guard = make_thread_join_guard(setter);

    EXPECT_TRUE(mux::test::co_wait_until(
        [&setter_done]() { return setter_done.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    server->stop();
    pool.stop();
    release_blocker.store(true, std::memory_order_release);

    if (setter.joinable())
    {
        setter.join();
    }
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }

    const auto cert_opt = server->cert_manager_.get_certificate(sni);
    EXPECT_TRUE(cert_opt.has_value());
}

TEST_F(remote_server_test_fixture, ConstructorCoversShortIdAndDestParsingBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg_invalid_hex = make_server_cfg(0, {}, "zz");
    auto server_invalid_hex = construct_server_until_acceptor_ready(pool, cfg_invalid_hex);
    ASSERT_NE(server_invalid_hex, nullptr);
    EXPECT_FALSE(server_invalid_hex->auth_config_valid_);

    auto cfg_long_short_id = make_server_cfg(0, {}, "010203040506070809");
    auto server_long_short_id = construct_server_until_acceptor_ready(pool, cfg_long_short_id);
    ASSERT_NE(server_long_short_id, nullptr);
    EXPECT_FALSE(server_long_short_id->auth_config_valid_);

    auto cfg_ipv6_dest = make_server_cfg(0, {{.sni = "www.example.test", .host = "127.0.0.1", .port = "not-a-port"}}, "0102030405060708");
    cfg_ipv6_dest.reality.dest = "[::1]:8443";
    auto server_ipv6_dest = construct_server_until_acceptor_ready(pool, cfg_ipv6_dest);
    ASSERT_NE(server_ipv6_dest, nullptr);
    EXPECT_TRUE(server_ipv6_dest->fallback_dest_valid_);
    EXPECT_EQ(server_ipv6_dest->fallback_dest_host_, "::1");
    EXPECT_EQ(server_ipv6_dest->fallback_dest_port_, "8443");

    mux::client_hello_info info{};
    info.sni = "www.example.test";
    const auto target = server_ipv6_dest->resolve_certificate_target(info);
    EXPECT_EQ(target.fetch_host, "::1");
    EXPECT_EQ(target.fetch_port, static_cast<std::uint16_t>(8443));

    auto cfg_port_suffix = make_server_cfg(0, {{.sni = "www.port.test", .host = "127.0.0.1", .port = "443abc"}}, "0102030405060708");
    auto server_port_suffix = construct_server_until_acceptor_ready(pool, cfg_port_suffix);
    ASSERT_NE(server_port_suffix, nullptr);
    mux::client_hello_info suffix_info{};
    suffix_info.sni = "www.port.test";
    const auto suffix_target = server_port_suffix->resolve_certificate_target(suffix_info);
    EXPECT_EQ(suffix_target.fetch_host, "www.apple.com");
    EXPECT_EQ(suffix_target.fetch_port, static_cast<std::uint16_t>(443));

    auto cfg_port_zero = make_server_cfg(0, {{.sni = "www.zero-port.test", .host = "127.0.0.1", .port = "0"}}, "0102030405060708");
    auto server_port_zero = construct_server_until_acceptor_ready(pool, cfg_port_zero);
    ASSERT_NE(server_port_zero, nullptr);
    mux::client_hello_info zero_info{};
    zero_info.sni = "www.zero-port.test";
    const auto zero_target = server_port_zero->resolve_certificate_target(zero_info);
    EXPECT_EQ(zero_target.fetch_host, "www.apple.com");
    EXPECT_EQ(zero_target.fetch_port, static_cast<std::uint16_t>(443));
}

TEST_F(remote_server_test_fixture, ParseClientHelloAndTranscriptGuardBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = construct_server_until_acceptor_ready(pool, make_server_cfg(0, {}, "0102030405060708"));
    ASSERT_NE(server, nullptr);

    std::string client_sni = "seed";
    const auto empty_info = mux::remote_server::parse_client_hello({}, client_sni);
    EXPECT_FALSE(empty_info.is_tls13);
    EXPECT_TRUE(client_sni.empty());

    reality::transcript trans;
    mux::connection_context const ctx;
    EXPECT_FALSE(server->init_handshake_transcript({0x16, 0x03, 0x03, 0x00, 0x00}, trans, ctx));
    EXPECT_TRUE(server->init_handshake_transcript({0x16, 0x03, 0x03, 0x00, 0x01, 0x01}, trans, ctx));
}

TEST_F(remote_server_test_fixture, AuthenticateClientFailureBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    mux::connection_context const ctx;

    mux::client_hello_info invalid_tls_info{};
    invalid_tls_info.is_tls13 = false;
    invalid_tls_info.session_id.assign(32, 0x01);
    EXPECT_FALSE(server->authenticate_client(invalid_tls_info, std::vector<std::uint8_t>(64, 0x00), ctx));

    mux::client_hello_info missing_share_info{};
    missing_share_info.is_tls13 = true;
    missing_share_info.session_id.assign(32, 0x02);
    missing_share_info.random.assign(32, 0x03);
    EXPECT_FALSE(server->authenticate_client(missing_share_info, std::vector<std::uint8_t>(64, 0x00), ctx));

    mux::client_hello_info malformed_sni_info{};
    malformed_sni_info.malformed_sni = true;
    malformed_sni_info.is_tls13 = true;
    malformed_sni_info.session_id.assign(32, 0x04);
    malformed_sni_info.random.assign(32, 0x05);
    EXPECT_FALSE(server->authenticate_client(malformed_sni_info, std::vector<std::uint8_t>(64, 0x00), ctx));

    mux::client_hello_info malformed_key_share_info{};
    malformed_key_share_info.malformed_key_share = true;
    malformed_key_share_info.is_tls13 = true;
    malformed_key_share_info.session_id.assign(32, 0x06);
    malformed_key_share_info.random.assign(32, 0x07);
    EXPECT_FALSE(server->authenticate_client(malformed_key_share_info, std::vector<std::uint8_t>(64, 0x00), ctx));

    std::uint8_t peer_pub[32];
    std::uint8_t peer_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

    mux::client_hello_info sid_offset_info{};
    sid_offset_info.is_tls13 = true;
    sid_offset_info.has_x25519_share = true;
    sid_offset_info.x25519_pub.assign(peer_pub, peer_pub + 32);
    sid_offset_info.session_id.assign(32, 0x11);
    sid_offset_info.random.assign(32, 0x22);
    sid_offset_info.sid_offset = 3;
    EXPECT_FALSE(server->authenticate_client(sid_offset_info, std::vector<std::uint8_t>(64, 0x33), ctx));

    mux::client_hello_info aad_mismatch_info = sid_offset_info;
    aad_mismatch_info.sid_offset = 200;
    EXPECT_FALSE(server->authenticate_client(aad_mismatch_info, std::vector<std::uint8_t>(40, 0x44), ctx));

    mux::client_hello_info short_random_info = sid_offset_info;
    short_random_info.random.assign(16, 0x55);
    EXPECT_FALSE(server->authenticate_client(short_random_info, std::vector<std::uint8_t>(64, 0x66), ctx));
}

TEST_F(remote_server_test_fixture, AuthenticateClientShortIdAndTimestampFailureBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    mux::connection_context const ctx;

    std::vector<std::uint8_t> sid_mismatch;
    const auto record_mismatch = build_valid_sid_ch("www.google.com", "ffffffffffffffff", static_cast<std::uint32_t>(time(nullptr)), sid_mismatch);
    const auto info_mismatch = mux::ch_parser::parse(record_mismatch);
    EXPECT_FALSE(server->authenticate_client(info_mismatch, record_mismatch, ctx));

    std::vector<std::uint8_t> sid_skew;
    const auto record_skew = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr) - 1000), sid_skew);
    const auto info_skew = mux::ch_parser::parse(record_skew);
    EXPECT_FALSE(server->authenticate_client(info_skew, record_skew, ctx));
}

TEST_F(remote_server_test_fixture, DeriveShareAndFallbackHelperBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));

    mux::client_hello_info const no_share_info{};
    std::array<std::uint8_t, 32> pub_key{};
    std::array<std::uint8_t, 32> priv_key{};
    const auto key_share_res = server->derive_server_key_share(no_share_info, pub_key.data(), priv_key.data(), mux::connection_context{});
    EXPECT_FALSE(key_share_res.has_value());
    EXPECT_EQ(key_share_res.error(), std::errc::invalid_argument);

    mux::remote_server::server_handshake_res bad_handshake{};
    bad_handshake.cipher = EVP_aes_128_gcm();
    bad_handshake.negotiated_md = EVP_sha256();
    bad_handshake.handshake_hash.assign(32, 0x55);
    bad_handshake.hs_keys.master_secret.clear();
    const auto app_keys_res = server->derive_application_traffic_keys(bad_handshake);
    EXPECT_FALSE(app_keys_res.has_value());
    EXPECT_TRUE(app_keys_res.error());

    mux::connection_context const ctx;
    server->record_fallback_result(ctx, "", false);
}

TEST_F(remote_server_test_fixture, InvalidSynTargetRejectsEmptyHostAndConnectPortZero)
{
    mux::syn_payload syn{};
    syn.socks_cmd = socks::kCmdConnect;
    syn.addr = "";
    syn.port = 443;
    EXPECT_TRUE(mux::remote_server::invalid_syn_target(syn));

    syn.addr = "example.com";
    syn.port = 0;
    EXPECT_TRUE(mux::remote_server::invalid_syn_target(syn));

    syn.socks_cmd = socks::kCmdUdpAssociate;
    EXPECT_FALSE(mux::remote_server::invalid_syn_target(syn));

    syn.addr.clear();
    EXPECT_TRUE(mux::remote_server::invalid_syn_target(syn));
}

TEST_F(remote_server_test_fixture, TryRegisterStreamWithReasonClassifiesLimitAndConflict)
{
    boost::asio::io_context io_context;
    mux::config::limits_t limits_cfg;
    limits_cfg.max_streams = 1;
    auto connection = std::make_shared<mux::mux_connection>(
        boost::asio::ip::tcp::socket(io_context),
        io_context,
        mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
        true,
        99,
        "",
        mux::config::timeout_t{},
        limits_cfg);
    ASSERT_TRUE(connection->try_register_stream(1, std::make_shared<noop_mux_stream>()));

    EXPECT_EQ(connection->try_register_stream_with_reason(1, std::make_shared<noop_mux_stream>()), mux::stream_register_result::kIdConflict);
    EXPECT_EQ(connection->try_register_stream_with_reason(3, std::make_shared<noop_mux_stream>()), mux::stream_register_result::kLimitReached);

    connection->remove_stream(1);
    EXPECT_EQ(connection->try_register_stream_with_reason(1, std::make_shared<noop_mux_stream>()), mux::stream_register_result::kSuccess);
    EXPECT_EQ(connection->try_register_stream_with_reason(3, std::make_shared<noop_mux_stream>()), mux::stream_register_result::kLimitReached);
    connection->remove_stream(1);
    drain_io_context(io_context);
    EXPECT_EQ(connection->try_register_stream_with_reason(1, std::make_shared<noop_mux_stream>()), mux::stream_register_result::kSuccess);
    connection->remove_stream(1);
    drain_io_context(io_context);

    connection->stop();
    EXPECT_EQ(connection->try_register_stream_with_reason(3, std::make_shared<noop_mux_stream>()), mux::stream_register_result::kClosed);
    EXPECT_EQ(connection->try_register_stream_with_reason(5, nullptr), mux::stream_register_result::kInvalidStream);
}

TEST_F(remote_server_test_fixture, RejectStreamForLimitSendsAckAndReset)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto conn = std::make_shared<mux::mock_mux_connection>(pool.get_io_context());

    mux::connection_context ctx;
    ctx.conn_id(7);
    ctx.trace_id("reject-limit");

    EXPECT_CALL(*conn, mock_send_async(42, mux::kCmdAck, testing::_))
        .WillOnce(
            [](std::uint32_t, std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                mux::ack_payload ack{};
                EXPECT_TRUE(mux::mux_codec::decode_ack(payload.data(), payload.size(), ack));
                EXPECT_EQ(ack.socks_rep, socks::kRepGenFail);
                return boost::system::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(42, mux::kCmdRst, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));

    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, conn, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->reject_stream_for_limit(conn, ctx, 42);
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, HandleStreamRegisterFailureSendsResetForClosedAndInvalidStream)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto conn = std::make_shared<mux::mock_mux_connection>(pool.get_io_context());

    mux::connection_context ctx;
    ctx.conn_id(9);
    ctx.trace_id("register-failure");

    EXPECT_CALL(*conn, mock_send_async(43, mux::kCmdRst, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*conn, mock_send_async(44, mux::kCmdRst, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));

    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, conn, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            EXPECT_TRUE(co_await server->handle_stream_register_failure(conn, ctx, 43, mux::stream_register_result::kClosed));
            EXPECT_TRUE(co_await server->handle_stream_register_failure(conn, ctx, 44, mux::stream_register_result::kInvalidStream));
            EXPECT_FALSE(co_await server->handle_stream_register_failure(conn, ctx, 45, mux::stream_register_result::kSuccess));
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, ProcessStreamRequestOnClosedConnectionSendsResetOnly)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto conn = std::make_shared<mux::mock_mux_connection>(pool.get_io_context());
    conn->stop();

    EXPECT_CALL(*conn, register_stream(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(*conn, mock_send_async(55, mux::kCmdAck, testing::_)).Times(0);
    EXPECT_CALL(*conn, mock_send_async(55, mux::kCmdRst, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(pool.get_io_context()),
        pool.get_io_context(),
        mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
        false,
        321,
        "",
        mux::config::timeout_t{},
        mux::config::limits_t{},
        mux::config::heartbeat_t{});
    tunnel->connection_ = conn;

    mux::syn_payload syn{
        .socks_cmd = socks::kCmdConnect,
        .addr = "1.1.1.1",
        .port = 443,
        .trace_id = "closed-conn",
    };
    std::vector<std::uint8_t> payload;
    ASSERT_TRUE(mux::mux_codec::encode_syn(syn, payload));

    mux::connection_context ctx;
    ctx.conn_id(321);
    ctx.trace_id("closed-conn");

    auto& io_context = pool.get_io_context();
    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        io_context,
        [server, tunnel, ctx, payload = std::move(payload), &io_context, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->process_stream_request(tunnel, ctx, 55, std::move(payload), io_context);
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, HandleTcpConnectStreamUsesConfiguredConnectTimeout)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.timeout.connect = 9;
    cfg.timeout.read = 27;
    cfg.timeout.write = 11;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    auto conn = std::make_shared<mux::mock_mux_connection>(pool.get_io_context());
    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(pool.get_io_context()),
        pool.get_io_context(),
        mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
        false,
        3003);
    tunnel->connection_ = conn;

    std::shared_ptr<mux::mux_stream_interface> registered_stream;
    EXPECT_CALL(*conn, register_stream(77, testing::_))
        .WillOnce(testing::DoAll(testing::SaveArg<1>(&registered_stream), testing::Return(false)));
    EXPECT_CALL(*conn, mock_send_async(77, mux::kCmdRst, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));

    mux::connection_context stream_ctx;
    stream_ctx.conn_id(17);
    stream_ctx.trace_id("tcp-connect-timeout");
    mux::syn_payload syn{};
    syn.socks_cmd = socks::kCmdConnect;
    syn.addr = "198.51.100.1";
    syn.port = 443;

    auto* stream_io_context = &pool.get_io_context();
    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        *stream_io_context,
        [server, tunnel, stream_ctx, syn, stream_io_context, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->handle_tcp_connect_stream(tunnel, stream_ctx, 77, syn, 0, *stream_io_context);
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);
    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    ASSERT_NE(registered_stream, nullptr);
    const auto remote_sess = std::dynamic_pointer_cast<mux::remote_session>(registered_stream);
    ASSERT_NE(remote_sess, nullptr);
    EXPECT_EQ(remote_sess->connect_timeout_sec_, 9U);
    EXPECT_EQ(remote_sess->write_timeout_sec_, 11U);
    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, FallbackFailedAndGuardDisabledBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = false;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    mux::connection_context guard_ctx;
    guard_ctx.remote_addr("127.0.0.8");
    EXPECT_TRUE(server->consume_fallback_token(guard_ctx, ""));
    server->record_fallback_result(guard_ctx, "", false);
}

TEST_F(remote_server_test_fixture, PerformHandshakeResponseCoversCipherSuiteSelectionBranches)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));

    reality::server_fingerprint invalid_fp;
    invalid_fp.cipher_suite = 0x9999;
    invalid_fp.alpn = "h2";
    server->set_certificate("cipher.invalid", reality::construct_certificate({0x01, 0x02, 0x03}), invalid_fp, "trace-invalid");

    reality::server_fingerprint chacha_fp;
    chacha_fp.cipher_suite = 0x1303;
    chacha_fp.alpn = "h2";
    server->set_certificate("cipher.chacha", reality::construct_certificate({0x01, 0x02, 0x03}), chacha_fp, "trace-chacha");

    auto run_once = [&](const std::string& sni, const std::uint32_t conn_id, const bool expect_ok) -> mux::remote_server::server_handshake_res
    {
        boost::asio::ip::tcp::acceptor acceptor(pool.get_io_context());
        if (!open_ephemeral_acceptor_until_ready(acceptor))
        {
            ADD_FAILURE() << "open ephemeral acceptor failed";
            return {};
        }
        boost::asio::ip::tcp::socket client_socket(pool.get_io_context());
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)client_socket.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);

        auto server_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)acceptor.accept(*server_socket, ec);
        EXPECT_FALSE(ec);

        std::uint8_t peer_pub[32];
        std::uint8_t peer_priv[32];
        EXPECT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

        mux::client_hello_info info{};
        info.sni = sni;
        info.session_id.assign(32, 0x11);
        info.has_x25519_share = true;
        info.x25519_pub.assign(peer_pub, peer_pub + 32);

        mux::connection_context ctx;
        ctx.conn_id(conn_id);
        ctx.trace_id(sni);

        std::pair<mux::remote_server::server_handshake_res, boost::system::error_code> done_result{};
        std::atomic<bool> done_ready{false};
        boost::asio::co_spawn(
            pool.get_io_context(),
            [server, server_socket, info, ctx, &done_result, &done_ready]() mutable -> boost::asio::awaitable<void>
            {
                reality::transcript trans;
                auto res = co_await server->perform_handshake_response(server_socket, info, trans, ctx);
                const auto res_ec = res.ec;
                done_result = {std::move(res), res_ec};
                done_ready.store(true, std::memory_order_release);
                co_return;
            },
            boost::asio::detached);

        EXPECT_TRUE(mux::test::co_wait_until(
            [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
        auto [result, hs_ec] = done_result;
        if (expect_ok)
        {
            EXPECT_FALSE(hs_ec);
            EXPECT_TRUE(result.ok);
        }
        else
        {
            EXPECT_TRUE(hs_ec);
            EXPECT_FALSE(result.ok);
        }
        return result;
    };

    const auto invalid_res = run_once("cipher.invalid", 71, true);
    EXPECT_EQ(invalid_res.cipher, EVP_aes_128_gcm());

    (void)run_once("cipher.chacha", 72, false);

    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, ConstructorCoversMalformedBracketDestParseBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg_missing_bracket = make_server_cfg(0, {}, "0102030405060708");
    cfg_missing_bracket.reality.dest = "[::1";
    auto server_missing_bracket = construct_server_until_acceptor_ready(pool, cfg_missing_bracket);
    ASSERT_NE(server_missing_bracket, nullptr);
    EXPECT_FALSE(server_missing_bracket->fallback_dest_valid_);
    EXPECT_FALSE(server_missing_bracket->auth_config_valid_);

    auto cfg_missing_colon = make_server_cfg(0, {}, "0102030405060708");
    cfg_missing_colon.reality.dest = "[::1]8443";
    auto server_missing_colon = construct_server_until_acceptor_ready(pool, cfg_missing_colon);
    ASSERT_NE(server_missing_colon, nullptr);
    EXPECT_FALSE(server_missing_colon->fallback_dest_valid_);
    EXPECT_FALSE(server_missing_colon->auth_config_valid_);

    auto cfg_unbracketed_ipv6 = make_server_cfg(0, {}, "0102030405060708");
    cfg_unbracketed_ipv6.reality.dest = "::1:8443";
    auto server_unbracketed_ipv6 = construct_server_until_acceptor_ready(pool, cfg_unbracketed_ipv6);
    ASSERT_NE(server_unbracketed_ipv6, nullptr);
    EXPECT_FALSE(server_unbracketed_ipv6->fallback_dest_valid_);
    EXPECT_FALSE(server_unbracketed_ipv6->auth_config_valid_);
}

TEST_F(remote_server_test_fixture, ConstructorRejectsInvalidDestPortBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg_non_numeric_port = make_server_cfg(0, {}, "0102030405060708");
    cfg_non_numeric_port.reality.dest = "example.com:not-a-port";
    auto server_non_numeric_port = construct_server_until_acceptor_ready(pool, cfg_non_numeric_port);
    ASSERT_NE(server_non_numeric_port, nullptr);
    EXPECT_FALSE(server_non_numeric_port->fallback_dest_valid_);
    EXPECT_FALSE(server_non_numeric_port->auth_config_valid_);

    auto cfg_zero_port = make_server_cfg(0, {}, "0102030405060708");
    cfg_zero_port.reality.dest = "example.com:0";
    auto server_zero_port = construct_server_until_acceptor_ready(pool, cfg_zero_port);
    ASSERT_NE(server_zero_port, nullptr);
    EXPECT_FALSE(server_zero_port->fallback_dest_valid_);
    EXPECT_FALSE(server_zero_port->auth_config_valid_);

    auto cfg_overflow_port = make_server_cfg(0, {}, "0102030405060708");
    cfg_overflow_port.reality.dest = "[::1]:70000";
    auto server_overflow_port = construct_server_until_acceptor_ready(pool, cfg_overflow_port);
    ASSERT_NE(server_overflow_port, nullptr);
    EXPECT_FALSE(server_overflow_port->fallback_dest_valid_);
    EXPECT_FALSE(server_overflow_port->auth_config_valid_);

    auto cfg_host_with_nul = make_server_cfg(0, {}, "0102030405060708");
    cfg_host_with_nul.reality.dest = std::string("example.com\0:443", 16);
    auto server_host_with_nul = construct_server_until_acceptor_ready(pool, cfg_host_with_nul);
    ASSERT_NE(server_host_with_nul, nullptr);
    EXPECT_FALSE(server_host_with_nul->fallback_dest_valid_);
    EXPECT_FALSE(server_host_with_nul->auth_config_valid_);
}

TEST_F(remote_server_test_fixture, ConstructorAcceptorSetupFailureBranchesWithWrappers)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const auto open_fail_port = pick_free_port();
    fail_next_socket(EMFILE);
    auto open_fail_server = std::make_shared<mux::remote_server>(pool, make_server_cfg(open_fail_port, {}, "0102030405060708"));
    EXPECT_TRUE(open_fail_server->private_key_.empty());
    EXPECT_FALSE(open_fail_server->acceptor_.is_open());

    const auto reuse_fail_port = pick_free_port();
    fail_next_reuse_setsockopt(EPERM);
    auto reuse_fail_server = std::make_shared<mux::remote_server>(pool, make_server_cfg(reuse_fail_port, {}, "0102030405060708"));
    EXPECT_TRUE(reuse_fail_server->private_key_.empty());
    EXPECT_FALSE(reuse_fail_server->acceptor_.is_open());

    const auto listen_fail_port = pick_free_port();
    fail_next_listen(EACCES);
    auto listen_fail_server = std::make_shared<mux::remote_server>(pool, make_server_cfg(listen_fail_port, {}, "0102030405060708"));
    EXPECT_TRUE(listen_fail_server->private_key_.empty());
    EXPECT_FALSE(listen_fail_server->acceptor_.is_open());
}

TEST_F(remote_server_test_fixture, AuthenticateClientCoversShortIdClockSkewAndReplayBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    mux::connection_context const ctx;

    const auto short_id_before = mux::statistics::instance().auth_short_id_failures();
    const auto skew_before = mux::statistics::instance().auth_clock_skew_failures();
    const auto replay_before = mux::statistics::instance().auth_replay_failures();

    std::vector<std::uint8_t> sid_mismatch;
    const auto record_mismatch = build_valid_sid_ch("www.google.com", "ffffffffffffffff", static_cast<std::uint32_t>(time(nullptr)), sid_mismatch);
    const auto info_mismatch = mux::ch_parser::parse(record_mismatch);
    EXPECT_FALSE(server->authenticate_client(info_mismatch, record_mismatch, ctx));

    std::vector<std::uint8_t> sid_skew;
    const auto record_skew = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr) - 1000), sid_skew);
    const auto info_skew = mux::ch_parser::parse(record_skew);
    EXPECT_FALSE(server->authenticate_client(info_skew, record_skew, ctx));

    std::vector<std::uint8_t> sid_ok;
    const auto record_ok = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr)), sid_ok);
    const auto info_ok = mux::ch_parser::parse(record_ok);
    EXPECT_TRUE(server->authenticate_client(info_ok, record_ok, ctx));
    EXPECT_FALSE(server->authenticate_client(info_ok, record_ok, ctx));

    EXPECT_GT(mux::statistics::instance().auth_short_id_failures(), short_id_before);
    EXPECT_GT(mux::statistics::instance().auth_clock_skew_failures(), skew_before);
    EXPECT_GT(mux::statistics::instance().auth_replay_failures(), replay_before);
}

TEST_F(remote_server_test_fixture, AuthenticateClientCoversInvalidPayloadAndShortIdLengthBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    mux::connection_context const ctx;

    std::vector<std::uint8_t> sid_ok;
    auto record = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr)), sid_ok);
    auto info = mux::ch_parser::parse(record);
    ASSERT_EQ(info.session_id.size(), 32U);

    auto invalid_payload_info = info;
    invalid_payload_info.session_id[0] ^= 0x01;
    EXPECT_FALSE(server->authenticate_client(invalid_payload_info, record, ctx));

    server->auth_config_valid_ = true;
    server->short_id_bytes_.assign(reality::kShortIdMaxLen + 1, 0x01);
    EXPECT_FALSE(server->authenticate_client(info, record, ctx));
}

TEST_F(remote_server_test_fixture, AuthenticateClientRejectsWhenAuthConfigInvalid)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    server->auth_config_valid_ = false;

    mux::client_hello_info info{};
    info.is_tls13 = true;
    info.session_id.assign(32, 0x11);
    info.sni = "auth.invalid";

    mux::connection_context const ctx;
    EXPECT_FALSE(server->authenticate_client(info, std::vector<std::uint8_t>(64, 0x22), ctx));
}

TEST_F(remote_server_test_fixture, PerformHandshakeResponseCoversRandomAndSignKeyFailureBranches)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("fault.test", reality::construct_certificate({0x01, 0x02, 0x03}), fp, "fault-trace");

    auto run_once = [&](const bool fail_rand, const bool fail_sign_key) -> std::pair<bool, boost::system::error_code>
    {
        boost::asio::ip::tcp::acceptor acceptor(pool.get_io_context());
        if (!open_ephemeral_acceptor_until_ready(acceptor))
        {
            ADD_FAILURE() << "open ephemeral acceptor failed";
            return {false, boost::asio::error::address_in_use};
        }
        boost::asio::ip::tcp::socket client_socket(pool.get_io_context());
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)client_socket.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);

        auto server_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)acceptor.accept(*server_socket, ec);
        EXPECT_FALSE(ec);

        std::uint8_t peer_pub[32];
        std::uint8_t peer_priv[32];
        EXPECT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

        mux::client_hello_info info{};
        info.sni = "fault.test";
        info.session_id.assign(32, 0x12);
        info.has_x25519_share = true;
        info.x25519_pub.assign(peer_pub, peer_pub + 32);

        mux::connection_context ctx;
        ctx.conn_id(91);
        ctx.trace_id("fault-branch");

        if (fail_rand)
        {
            fail_next_rand_bytes();
        }
        if (fail_sign_key)
        {
            fail_next_ed25519_raw_private_key();
        }

        std::pair<mux::remote_server::server_handshake_res, boost::system::error_code> done_result{};
        std::atomic<bool> done_ready{false};
        boost::asio::co_spawn(
            pool.get_io_context(),
            [server, server_socket, info, ctx, &done_result, &done_ready]() mutable -> boost::asio::awaitable<void>
            {
                reality::transcript trans;
                auto res = co_await server->perform_handshake_response(server_socket, info, trans, ctx);
                const auto res_ec = res.ec;
                done_result = {std::move(res), res_ec};
                done_ready.store(true, std::memory_order_release);
                co_return;
            },
            boost::asio::detached);

        EXPECT_TRUE(mux::test::co_wait_until(
            [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
        auto [result, hs_ec] = done_result;
        return {result.ok, hs_ec};
    };

    {
        const auto [ok, hs_ec] = run_once(true, false);
        EXPECT_FALSE(ok);
        EXPECT_EQ(hs_ec, std::errc::operation_canceled);
    }

    {
        const auto [ok, hs_ec] = run_once(false, true);
        EXPECT_FALSE(ok);
        EXPECT_EQ(hs_ec, boost::asio::error::fault);
    }

    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, VerifyClientFinishedCoversPlaintextValidationBranches)
{
    auto run_case = [](const std::vector<std::uint8_t>& plaintext, const std::uint8_t inner_content_type) -> bool
    {
        boost::asio::io_context io_context;
        boost::system::error_code ec;

        boost::asio::ip::tcp::acceptor acceptor(io_context);
        if (!open_ephemeral_acceptor_until_ready(acceptor))
        {
            ADD_FAILURE() << "open ephemeral acceptor failed";
            return false;
        }
        boost::asio::ip::tcp::socket writer(io_context);
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)writer.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);
        auto reader = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)acceptor.accept(*reader, ec);
        EXPECT_FALSE(ec);

        const std::vector<std::uint8_t> key(16, 0x41);
        const std::vector<std::uint8_t> iv(12, 0x62);
        const auto encrypted = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, inner_content_type);
        EXPECT_TRUE(encrypted.has_value());
        if (!encrypted)
        {
            return false;
        }
        boost::asio::write(writer, boost::asio::buffer(*encrypted), ec);
        EXPECT_FALSE(ec);
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        (void)writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

        mux::connection_context ctx;
        ctx.conn_id(88);
        ctx.trace_id("verify-client-finished");

        reality::handshake_keys hs_keys;
        hs_keys.client_handshake_traffic_secret.assign(32, 0x55);
        reality::transcript trans;

        bool ok = true;
        boost::system::error_code verify_ec;
        boost::asio::co_spawn(
            io_context,
            [&]() -> boost::asio::awaitable<void>
            {
                verify_ec =
                    co_await mux::remote_server::verify_client_finished(reader, {key, iv}, hs_keys, trans, EVP_aes_128_gcm(), EVP_sha256(), ctx);
                ok = !verify_ec;
                co_return;
            },
            boost::asio::detached);
        io_context.run();
        return ok;
    };

    EXPECT_FALSE(run_case({0x14, 0x00, 0x00, 0x00}, reality::kContentTypeApplicationData));
    EXPECT_FALSE(run_case({0x14, 0x00, 0x00, 0x01, 0x00}, reality::kContentTypeHandshake));

    std::vector<std::uint8_t> wrong_hmac(4 + 32, 0x00);
    wrong_hmac[0] = 0x14;
    wrong_hmac[3] = 0x20;
    EXPECT_FALSE(run_case(wrong_hmac, reality::kContentTypeHandshake));
}

TEST_F(remote_server_test_fixture, VerifyClientFinishedAcceptsMultipleCompatibilityCcsRecords)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));

    boost::asio::ip::tcp::socket writer(io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    auto reader = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(*reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x41);
    const std::vector<std::uint8_t> iv(12, 0x62);

    reality::handshake_keys hs_keys;
    hs_keys.client_handshake_traffic_secret.assign(32, 0x55);
    reality::transcript trans;
    const auto verify_data =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), EVP_sha256());
    ASSERT_TRUE(verify_data.has_value());

    const auto finished_plaintext = reality::construct_finished(*verify_data);
    const auto encrypted =
        reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, finished_plaintext, reality::kContentTypeHandshake);
    ASSERT_TRUE(encrypted.has_value());

    const std::vector<std::uint8_t> ccs_record = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    std::vector<std::uint8_t> wire;
    wire.reserve(ccs_record.size() * 2 + encrypted->size());
    wire.insert(wire.end(), ccs_record.begin(), ccs_record.end());
    wire.insert(wire.end(), ccs_record.begin(), ccs_record.end());
    wire.insert(wire.end(), encrypted->begin(), encrypted->end());

    boost::asio::write(writer, boost::asio::buffer(wire), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    mux::connection_context ctx;
    ctx.conn_id(110);
    ctx.trace_id("verify-client-finished-multi-ccs");

    boost::system::error_code verify_ec;
    boost::asio::co_spawn(
        io_context,
        [&]() -> boost::asio::awaitable<void>
        {
            verify_ec =
                co_await mux::remote_server::verify_client_finished(reader, {key, iv}, hs_keys, trans, EVP_aes_128_gcm(), EVP_sha256(), ctx);
            co_return;
        },
        boost::asio::detached);

    io_context.run();
    EXPECT_FALSE(verify_ec);
}

TEST_F(remote_server_test_fixture, VerifyClientFinishedRejectsTooManyCompatibilityCcsRecords)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));

    boost::asio::ip::tcp::socket writer(io_context);
    (void)writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    auto reader = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    (void)acceptor.accept(*reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> ccs_record = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    std::vector<std::uint8_t> wire;
    wire.reserve(ccs_record.size() * 9);
    for (std::size_t i = 0; i < 9; ++i)
    {
        wire.insert(wire.end(), ccs_record.begin(), ccs_record.end());
    }

    boost::asio::write(writer, boost::asio::buffer(wire), ec);
    ASSERT_FALSE(ec);
    (void)writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    const std::vector<std::uint8_t> key(16, 0x41);
    const std::vector<std::uint8_t> iv(12, 0x62);
    reality::handshake_keys hs_keys;
    hs_keys.client_handshake_traffic_secret.assign(32, 0x55);
    reality::transcript trans;

    mux::connection_context ctx;
    ctx.conn_id(111);
    ctx.trace_id("verify-client-finished-overlimit-ccs");

    boost::system::error_code verify_ec;
    boost::asio::co_spawn(
        io_context,
        [&]() -> boost::asio::awaitable<void>
        {
            verify_ec =
                co_await mux::remote_server::verify_client_finished(reader, {key, iv}, hs_keys, trans, EVP_aes_128_gcm(), EVP_sha256(), ctx);
            co_return;
        },
        boost::asio::detached);

    io_context.run();
    EXPECT_EQ(verify_ec, std::errc::bad_message);
}

TEST_F(remote_server_test_fixture, VerifyClientFinishedTimeoutWhenPeerStalls)
{
    const auto client_finished_failures_before = mux::statistics::instance().client_finished_failures();

    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));

    boost::asio::ip::tcp::socket writer(io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    auto reader = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(*reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x41);
    const std::vector<std::uint8_t> iv(12, 0x62);
    reality::handshake_keys hs_keys;
    hs_keys.client_handshake_traffic_secret.assign(32, 0x55);
    reality::transcript trans;

    mux::connection_context ctx;
    ctx.conn_id(109);
    ctx.trace_id("verify-client-finished-timeout");

    boost::system::error_code verify_ec;
    boost::asio::co_spawn(
        io_context,
        [&]() -> boost::asio::awaitable<void>
        {
            verify_ec =
                co_await mux::remote_server::verify_client_finished(reader, {key, iv}, hs_keys, trans, EVP_aes_128_gcm(), EVP_sha256(), ctx, 1);
            co_return;
        },
        boost::asio::detached);

    io_context.run();
    EXPECT_EQ(verify_ec, boost::asio::error::timed_out);
    EXPECT_GT(mux::statistics::instance().client_finished_failures(), client_finished_failures_before);
}

TEST_F(remote_server_test_fixture, SendServerHelloFlightTimeoutWhenPeerStalls)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto* io_context = &pool.get_io_context();

    boost::asio::ip::tcp::acceptor acceptor(*io_context);
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));

    boost::asio::ip::tcp::socket client_socket(*io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    auto server_socket = std::make_shared<boost::asio::ip::tcp::socket>(*io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(*server_socket, ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)server_socket->set_option(boost::asio::socket_base::send_buffer_size(1024), ec);
    ASSERT_FALSE(ec);

    boost::system::error_code done_ec;
    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        *io_context,
        [server, server_socket, &done_ec, &done_ready]() -> boost::asio::awaitable<void>
        {
            mux::connection_context ctx;
            ctx.conn_id(110);
            ctx.trace_id("send-server-hello-timeout");

            const std::vector<std::uint8_t> sh_msg = {0x02, 0x00, 0x00, 0x00};
            std::vector<std::uint8_t> const flight2_enc(8 * 1024 * 1024, 0x5a);
            const auto write_ec = co_await server->send_server_hello_flight(server_socket, sh_msg, flight2_enc, ctx, 1);
            done_ec = write_ec;
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    ASSERT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(4)));
    EXPECT_EQ(done_ec, boost::asio::error::timed_out);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.close(ec);
    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, DeriveApplicationTrafficKeysCoversFirstAndSecondDeriveFailure)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));

    mux::remote_server::server_handshake_res sh_res{};
    sh_res.cipher = EVP_aes_128_gcm();
    sh_res.negotiated_md = EVP_sha256();
    sh_res.hs_keys.master_secret.assign(32, 0x71);
    sh_res.handshake_hash.assign(32, 0x72);

    fail_hkdf_add_info_on_call(3);
    const auto first_app_keys_res = server->derive_application_traffic_keys(sh_res);
    EXPECT_FALSE(first_app_keys_res.has_value());
    EXPECT_TRUE(first_app_keys_res.error());

    ec.clear();
    fail_hkdf_add_info_on_call(5);
    const auto second_app_keys_res = server->derive_application_traffic_keys(sh_res);
    EXPECT_FALSE(second_app_keys_res.has_value());
    EXPECT_TRUE(second_app_keys_res.error());
}

TEST_F(remote_server_test_fixture, DeriveServerKeyShareCoversX25519DeriveFailureBranch)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));

    std::uint8_t pub[32];
    std::uint8_t priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));

    mux::client_hello_info info{};
    info.has_x25519_share = true;
    info.x25519_pub.assign(32, 0x23);

    mux::connection_context const ctx;

    fail_next_pkey_derive();
    const auto key_share_res = server->derive_server_key_share(info, pub, priv, ctx);
    EXPECT_FALSE(key_share_res.has_value());
    EXPECT_TRUE(key_share_res.error());
}

TEST_F(remote_server_test_fixture, StopCoversAcceptorCloseFailureBranch)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    server->start();

    fail_next_close(EIO);
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    pool.stop();
    runner.join();
}

TEST_F(remote_server_test_fixture, StopLocalCoversTrackedSocketCloseFailureBranch)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto tracked_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)tracked_socket->open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);

    server->track_connection_socket(tracked_socket);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)server->acceptor_.close(ec);
    fail_next_close(EIO);
    server->stop_local(false);
}

TEST_F(remote_server_test_fixture, StopClosesInFlightHandshakeConnections)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    ASSERT_TRUE(start_server_until_listening(server));
    const auto listen_port = server->listen_port();
    ASSERT_NE(listen_port, 0);

    boost::asio::io_context client_io_context;
    boost::asio::ip::tcp::socket client_socket(client_io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), listen_port), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 5> partial_client_hello = {0x16, 0x03, 0x03, 0x00, 0x20};
    boost::asio::write(client_socket, boost::asio::buffer(partial_client_hello), ec);
    ASSERT_FALSE(ec);

    const auto tracked_non_empty = wait_for_condition(
        [&server]() { return remote_server_tracked_socket_count(server) > 0; });
    EXPECT_TRUE(tracked_non_empty);

    server->stop();

    const auto tracked_cleared = wait_for_condition(
        [&server]() { return remote_server_tracked_socket_count(server) == 0; });
    EXPECT_TRUE(tracked_cleared);

    const auto slots_released = wait_for_condition([&server]() { return remote_server_active_connection_slots(server) == 0; });
    EXPECT_TRUE(slots_released);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.non_blocking(true, ec);
    ASSERT_FALSE(ec);
    const auto peer_closed = wait_for_condition(
        [&client_socket]()
        {
            std::array<std::uint8_t, 1> buf = {0};
            boost::system::error_code read_ec;
            (void)client_socket.read_some(boost::asio::buffer(buf), read_ec);
            if (read_ec == boost::asio::error::would_block || read_ec == boost::asio::error::try_again)
            {
                return false;
            }
            return read_ec == boost::asio::error::eof || read_ec == boost::asio::error::connection_reset ||
                   read_ec == boost::asio::error::operation_aborted;
        });
    EXPECT_TRUE(peer_closed);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.close(ec);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST_F(remote_server_test_fixture, HandshakeReadTimeoutReleasesSlotWithoutFallback)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    boost::asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(fallback_acceptor));
    const auto fallback_port = fallback_acceptor.local_endpoint().port();
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&fallback_triggered](const boost::system::error_code& accept_ec, boost::asio::ip::tcp::socket)
        {
            if (!accept_ec)
            {
                fallback_triggered.store(true, std::memory_order_release);
            }
        });

    auto cfg = make_server_cfg(0, {{.sni = "", .host = "127.0.0.1", .port = std::to_string(fallback_port)}}, "0102030405060708");
    cfg.timeout.read = 1;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    ASSERT_TRUE(start_server_until_listening(server));
    const auto listen_port = server->listen_port();
    ASSERT_NE(listen_port, 0);

    boost::asio::io_context client_io_context;
    boost::asio::ip::tcp::socket client_socket(client_io_context);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), listen_port), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 5> partial_client_hello = {0x16, 0x03, 0x03, 0x00, 0x20};
    boost::asio::write(client_socket, boost::asio::buffer(partial_client_hello), ec);
    ASSERT_FALSE(ec);

    const auto slot_reserved = wait_for_condition([&server]() { return remote_server_active_connection_slots(server) > 0; });
    EXPECT_TRUE(slot_reserved);

    const auto slot_released = wait_for_condition([&server]() { return remote_server_active_connection_slots(server) == 0; },
                                                  std::chrono::milliseconds(4000),
                                                  std::chrono::milliseconds(20));
    EXPECT_TRUE(slot_released);
    EXPECT_FALSE(fallback_triggered.load(std::memory_order_acquire));

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.non_blocking(true, ec);
    ASSERT_FALSE(ec);
    const auto peer_closed = wait_for_condition(
        [&client_socket]()
        {
            std::array<std::uint8_t, 1> buf = {0};
            boost::system::error_code read_ec;
            (void)client_socket.read_some(boost::asio::buffer(buf), read_ec);
            if (read_ec == boost::asio::error::would_block || read_ec == boost::asio::error::try_again)
            {
                return false;
            }
            return read_ec == boost::asio::error::eof || read_ec == boost::asio::error::connection_reset ||
                   read_ec == boost::asio::error::operation_aborted;
        },
        std::chrono::milliseconds(2500),
        std::chrono::milliseconds(20));
    EXPECT_TRUE(peer_closed);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.close(ec);
    server->stop();
    boost::system::error_code close_ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)fallback_acceptor.cancel(close_ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)fallback_acceptor.close(close_ec);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST_F(remote_server_test_fixture, ReadInitialAndValidateAcceptsFragmentedTlsHeader)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));

    boost::asio::ip::tcp::acceptor acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));

    boost::asio::ip::tcp::socket client_socket(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    auto server_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(*server_socket, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> sid;
    auto record = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr)), sid);
    ASSERT_GT(record.size(), 5U);

    mux::remote_server::initial_read_res done_res{};
    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, server_socket, &done_res, &done_ready]() -> boost::asio::awaitable<void>
        {
            mux::connection_context ctx;
            ctx.conn_id(9001);
            ctx.trace_id("fragmented-header");
            std::vector<std::uint8_t> initial_buf;
            auto res = co_await server->read_initial_and_validate(server_socket, ctx, initial_buf);
            done_res = res;
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    boost::asio::write(client_socket, boost::asio::buffer(record.data(), 2), ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::asio::write(client_socket, boost::asio::buffer(record.data() + 2, record.size() - 2), ec);
    ASSERT_FALSE(ec);

    ASSERT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    const auto res = done_res;
    EXPECT_TRUE(res.ok);
    EXPECT_FALSE(res.allow_fallback);
    EXPECT_FALSE(res.ec);
}

TEST_F(remote_server_test_fixture, ReadInitialAndValidateKeepsOnlyClientHelloRecord)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));

    boost::asio::ip::tcp::acceptor acceptor(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_acceptor_until_ready(acceptor));

    boost::asio::ip::tcp::socket client_socket(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client_socket.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    auto server_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)acceptor.accept(*server_socket, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> sid;
    auto record = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr)), sid);
    ASSERT_GT(record.size(), 5U);

    std::vector<std::uint8_t> wire = record;
    wire.insert(wire.end(), 64, 0xAA);
    boost::asio::write(client_socket, boost::asio::buffer(wire), ec);
    ASSERT_FALSE(ec);

    std::pair<mux::remote_server::initial_read_res, std::size_t> done_res{};
    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, server_socket, &done_res, &done_ready]() -> boost::asio::awaitable<void>
        {
            mux::connection_context ctx;
            ctx.conn_id(9002);
            ctx.trace_id("trim-client-hello-record");
            std::vector<std::uint8_t> initial_buf;
            auto res = co_await server->read_initial_and_validate(server_socket, ctx, initial_buf);
            done_res = std::make_pair(res, initial_buf.size());
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    ASSERT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    const auto [res, buf_size] = done_res;
    EXPECT_TRUE(res.ok);
    EXPECT_FALSE(res.allow_fallback);
    EXPECT_FALSE(res.ec);
    EXPECT_EQ(buf_size, record.size());
}

TEST_F(remote_server_test_fixture, DelayAndFallbackShortCircuitsWhenStopRequested)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    mux::connection_context ctx;
    ctx.conn_id(6060);
    ctx.trace_id("delay-stop-short-circuit");

    std::pair<mux::remote_server::server_handshake_res, boost::system::error_code> done_res{};
    std::atomic<bool> done_ready{false};
    server->stop_.store(true, std::memory_order_release);
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, socket, ctx, &done_res, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            auto res = co_await server->delay_and_fallback(
                socket, std::vector<std::uint8_t>{0x16}, ctx, "stop.test");
            done_res = std::make_pair(std::move(res), boost::system::error_code{});
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(2)));
    if (done_ready.load(std::memory_order_acquire))
    {
        const auto [res, spawn_ec] = done_res;
        EXPECT_FALSE(spawn_ec);
        EXPECT_FALSE(res.ok);
        EXPECT_EQ(res.ec, boost::asio::error::operation_aborted);
    }

    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST_F(remote_server_test_fixture, DelayAndFallbackReturnsHostNotFoundWhenNoFallbackTarget)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    mux::connection_context ctx;
    ctx.conn_id(6061);
    ctx.trace_id("delay-no-fallback-target");

    std::pair<mux::remote_server::server_handshake_res, boost::system::error_code> done_res{};
    std::atomic<bool> done_ready{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, socket, ctx, &done_res, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            auto res = co_await server->delay_and_fallback(socket, std::vector<std::uint8_t>{0x16, 0x03, 0x03, 0x00}, ctx, "none.test");
            done_res = std::make_pair(std::move(res), boost::system::error_code{});
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(4)));
    if (done_ready.load(std::memory_order_acquire))
    {
        const auto [res, spawn_ec] = done_res;
        EXPECT_FALSE(spawn_ec);
        EXPECT_FALSE(res.ok);
        EXPECT_EQ(res.ec, boost::asio::error::host_not_found);
    }

    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST_F(remote_server_test_fixture, StopRunsInlineWhenIoContextStopped)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    server->start();

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(boost::asio::ip::tcp::socket(pool.get_io_context()),
                                                                                       pool.get_io_context(),
                                                                                       mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                                                       true,
                                                                                       901);
    auto conn = tunnel->connection();
    ASSERT_NE(conn, nullptr);
    ASSERT_TRUE(conn->is_open());
    server->append_active_tunnel(tunnel);

    pool.stop();

    EXPECT_TRUE(server->acceptor_.is_open());
    server->stop();

    EXPECT_TRUE(server->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->acceptor_.is_open());
    EXPECT_TRUE(conn->is_open());
    EXPECT_GT(server->active_tunnel_count(), 0U);
    drain_io_context(pool.get_io_context());
    EXPECT_FALSE(server->acceptor_.is_open());
    EXPECT_FALSE(conn->is_open());
    EXPECT_EQ(server->active_tunnel_count(), 0U);
}

TEST_F(remote_server_test_fixture, StopRunsWhenIoQueueBlocked)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    server->start();

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(boost::asio::ip::tcp::socket(pool.get_io_context()),
                                                                                       pool.get_io_context(),
                                                                                       mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                                                       true,
                                                                                       902);
    auto conn = tunnel->connection();
    ASSERT_NE(conn, nullptr);
    ASSERT_TRUE(conn->is_open());
    server->append_active_tunnel(tunnel);

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(pool.get_io_context(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        pool.stop();
        if (runner.joinable())
        {
            runner.join();
        }
        FAIL();
    }

    EXPECT_TRUE(server->acceptor_.is_open());
    server->stop();
    EXPECT_TRUE(server->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->acceptor_.is_open());
    EXPECT_TRUE(conn->is_open());
    EXPECT_GT(server->active_tunnel_count(), 0U);

    release_blocker.store(true, std::memory_order_release);
    EXPECT_TRUE(wait_for_condition(
        [&server, &conn]() { return !server->acceptor_.is_open() && !conn->is_open() && server->active_tunnel_count() == 0; },
        std::chrono::seconds(2)));
    EXPECT_FALSE(server->acceptor_.is_open());
    EXPECT_FALSE(conn->is_open());
    EXPECT_EQ(server->active_tunnel_count(), 0U);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST_F(remote_server_test_fixture, StopRunsWhenIoContextNotRunning)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    server->start();

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(boost::asio::ip::tcp::socket(pool.get_io_context()),
                                                                                       pool.get_io_context(),
                                                                                       mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                                                       true,
                                                                                       903);
    auto conn = tunnel->connection();
    ASSERT_NE(conn, nullptr);
    ASSERT_TRUE(conn->is_open());
    server->append_active_tunnel(tunnel);

    EXPECT_TRUE(server->acceptor_.is_open());
    server->stop();

    EXPECT_TRUE(server->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->acceptor_.is_open());
    EXPECT_TRUE(conn->is_open());
    EXPECT_GT(server->active_tunnel_count(), 0U);
    drain_io_context(pool.get_io_context());
    EXPECT_FALSE(server->acceptor_.is_open());
    EXPECT_FALSE(conn->is_open());
    EXPECT_EQ(server->active_tunnel_count(), 0U);
    pool.stop();
}

TEST_F(remote_server_test_fixture, DrainClosesAcceptorButKeepsActiveTunnels)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0, {}, "0102030405060708"));
    server->start();

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(boost::asio::ip::tcp::socket(pool.get_io_context()),
                                                                                       pool.get_io_context(),
                                                                                       mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                                                       true,
                                                                                       904);
    auto conn = tunnel->connection();
    ASSERT_NE(conn, nullptr);
    ASSERT_TRUE(conn->is_open());
    server->append_active_tunnel(tunnel);

    EXPECT_TRUE(server->acceptor_.is_open());
    server->drain();

    EXPECT_TRUE(server->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->acceptor_.is_open());
    drain_io_context(pool.get_io_context());
    EXPECT_FALSE(server->acceptor_.is_open());
    EXPECT_TRUE(conn->is_open());
    EXPECT_GT(server->active_tunnel_count(), 0U);

    server->stop();
    EXPECT_TRUE(conn->is_open());
    EXPECT_GT(server->active_tunnel_count(), 0U);
    drain_io_context(pool.get_io_context());
    EXPECT_FALSE(conn->is_open());
    EXPECT_EQ(server->active_tunnel_count(), 0U);
    pool.stop();
}

TEST_F(remote_server_test_fixture, StartReopensAcceptorAfterStop)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const auto port = pick_free_port();
    auto cfg = make_server_cfg(port, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    server->start();
    EXPECT_TRUE(wait_for_condition([&server, port]() { return server->listen_port() == port; }));

    server->stop();
    EXPECT_TRUE(wait_for_condition([&server]() { return server->listen_port() == 0; }));

    server->start();
    EXPECT_TRUE(wait_for_condition([&server, port]() { return server->listen_port() == port; }));

    server->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST_F(remote_server_test_fixture, StartWhileRunningIsIgnored)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(0, {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    server->start();
    EXPECT_TRUE(server->started_.load(std::memory_order_acquire));
    EXPECT_FALSE(server->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->acceptor_.is_open());

    server->start();
    EXPECT_TRUE(server->started_.load(std::memory_order_acquire));
    EXPECT_FALSE(server->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(server->acceptor_.is_open());

    server->stop();
    pool.stop();
}

TEST_F(remote_server_test_fixture, HandleFallbackCoversCloseSocketErrorBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });
    auto runner_guard = make_pool_thread_guard(pool, runner);

    auto cfg = make_server_cfg(0, {{.sni = "*", .host = "127.0.0.1", .port = "1"}}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 0;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    auto fallback_socket = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
    mux::connection_context ctx;
    ctx.conn_id(555);
    ctx.remote_addr("127.0.0.10");
    ctx.trace_id("fallback-close-errors");

    std::atomic<bool> done_ready{false};

    fail_next_shutdown(EIO);
    fail_next_close(EIO);
    boost::asio::co_spawn(
        pool.get_io_context(),
        [server, fallback_socket, ctx, &done_ready]() mutable -> boost::asio::awaitable<void>
        {
            co_await server->handle_fallback(fallback_socket, std::vector<std::uint8_t>{0x16}, ctx, "blocked.test");
            done_ready.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    EXPECT_TRUE(mux::test::co_wait_until(
        [&done_ready]() { return done_ready.load(std::memory_order_acquire); }, std::chrono::seconds(5)));

    server->stop();
    pool.stop();
    runner.join();
}

// readability-function-cognitive-complexity, readability-isolate-declaration, readability-static-accessed-through-instance)
