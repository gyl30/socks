
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

extern "C"
{
#include <openssl/ssl.h>
}

#define private public
#include "cert_fetcher.h"

#undef private
#include "crypto_util.h"

namespace
{

std::atomic<bool> g_fail_hkdf_md_once{false};
std::atomic<bool> g_fail_keygen_once{false};
std::atomic<int> g_fail_rand_bytes_on_call{0};
std::atomic<int> g_rand_bytes_call_count{0};

void fail_next_hkdf_md() { g_fail_hkdf_md_once.store(true, std::memory_order_release); }

void fail_next_keygen() { g_fail_keygen_once.store(true, std::memory_order_release); }

void fail_rand_bytes_on_call(const int call_index)
{
    g_rand_bytes_call_count.store(0, std::memory_order_release);
    g_fail_rand_bytes_on_call.store(call_index, std::memory_order_release);
}

extern "C" int __real_EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);    
extern "C" int __real_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);             
extern "C" int __real_RAND_bytes(unsigned char* buf, int num);                          

extern "C" int __wrap_EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX* ctx, const EVP_MD* md)    
{
    if (g_fail_hkdf_md_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_CTX_set_hkdf_md(ctx, md);    
}

extern "C" int __wrap_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey)    
{
    if (g_fail_keygen_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_keygen(ctx, ppkey);    
}

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)    
{
    const int target_call = g_fail_rand_bytes_on_call.load(std::memory_order_acquire);
    if (target_call > 0)
    {
        const int current_call = g_rand_bytes_call_count.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (current_call == target_call)
        {
            g_fail_rand_bytes_on_call.store(0, std::memory_order_release);
            return 0;
        }
    }
    return __real_RAND_bytes(buf, num);    
}

constexpr char kTestCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDDTCCAfWgAwIBAgIUDRrlEpld7PUqh0ckVHLU6OJVJQAwDQYJKoZIhvcNAQEL\n"
    "BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYwMjEwMDc1NDM0WhcNMjYw\n"
    "MjExMDc1NDM0WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\n"
    "AQEBBQADggEPADCCAQoCggEBAKQO4v+I/oTmITOpWez3p040cqAHMKuXd9j5Ttcf\n"
    "5ZNrlTXeh4AQ4NnDprunP76/AcU0NZNR69MoUssh1pI/rg4W+j6+1cIUDiN85iWR\n"
    "7dUAKL7e2XqOGfSF3aLL4cQWnLQx0YK99MYHM8LO18NGHeTmmvB6IZA22J44DPv7\n"
    "le1fxoXik9mTTTnzJTr1xcC3Pmjks669TF8Z1Hz91i78naBD3KocZA7drU0KuElM\n"
    "CjWVcbKEYdLb9D23eeHKlxAqyO/vPvzzSrJFS3FdGzBfB9IccfhIqNCQ84LrOEqv\n"
    "vUGcAq3T3g+72CezjgQ6ULrEjwiJ2aEKnUIhXA556JaY9/MCAwEAAaNTMFEwHQYD\n"
    "VR0OBBYEFJaGH0kdvlwvMJVJC6x6mx8a23m9MB8GA1UdIwQYMBaAFJaGH0kdvlwv\n"
    "MJVJC6x6mx8a23m9MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
    "AGsavg/DKBjIWgOVYsoIaBIZmvcuSzPfN4VUxTyEDLbiB/YDdMIq1adRPzbzFfQQ\n"
    "21ordt01PokiDKWK6tQXufMveYGjwqN+YrftnUAZF9qanvWKTems6YYZUJZIdYX9\n"
    "QT462fvBabwYk2CKNBo6VeQg1IxwT4zID80/wE08/5TVdTVIstCUxCCcKEO4gj5m\n"
    "PxBEOWdqQuyCFyCSfDsmtfoDWpbFzvLWJ8WxSeHlnjUktkvFfSoAmtlt6IhFPyHd\n"
    "CsLcT+t1V7umOWzrXLGqxSudkuV/DwFpGTt/jhfTfSzenQGmeFUdUHeuRTRo4Hn+\n"
    "2+nRqvFgBBeZbOsPGdUw1rM=\n"
    "-----END CERTIFICATE-----\n";

constexpr char kTestKeyPem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkDuL/iP6E5iEz\n"
    "qVns96dONHKgBzCrl3fY+U7XH+WTa5U13oeAEODZw6a7pz++vwHFNDWTUevTKFLL\n"
    "IdaSP64OFvo+vtXCFA4jfOYlke3VACi+3tl6jhn0hd2iy+HEFpy0MdGCvfTGBzPC\n"
    "ztfDRh3k5prweiGQNtieOAz7+5XtX8aF4pPZk0058yU69cXAtz5o5LOuvUxfGdR8\n"
    "/dYu/J2gQ9yqHGQO3a1NCrhJTAo1lXGyhGHS2/Q9t3nhypcQKsjv7z7880qyRUtx\n"
    "XRswXwfSHHH4SKjQkPOC6zhKr71BnAKt094Pu9gns44EOlC6xI8IidmhCp1CIVwO\n"
    "eeiWmPfzAgMBAAECggEAFpvElZGD/b2XEr8CWQEyCbl5mGsVPnhjuD93KXdIVH4N\n"
    "dHyDsNbina/0QMUGKFu7Ozl8Lp6qAJH8gujZYJMtAd0RxGbZH2NTJXnXX5MSMvnQ\n"
    "I6mjT9vYYNW32vD83mB9XOnGpR1XZ5jjfbOykUMO6JYNARnbmTuts3Qm+ezMVwdU\n"
    "ca508dXyKdT8AY+fJRxVl/QNZU81hL3/gHUTnABVy00OACdjTrq2jOtJeUUXSI0P\n"
    "AZ28Yn3EcsWx1/YNfW8zkiuNRnwheL+pVkWnpqJNojWU4NuC6FXUINvow6o5rEg1\n"
    "bNtld57xz/rfG7PohMeYzEw3PhiySW51foinrJ5eZQKBgQDn+tJsA0Nyq1jWQV2D\n"
    "xtZPtTWksPJa7iFgb5AKDOry6h5bDTWNzRSKNdc4eLNtaf1F+MGNdGDYhLjZWOLj\n"
    "IYkMIZzEdBRC7LFQHLwin+skO0ldasx6cSp4/j990CuUx7by+yTOlXCCBd9py38a\n"
    "Yv8R+3Ri5aSfJwDOnKqmstEoRwKBgQC1C6PRCSb3PAsHJZjcflnGzD2nTvTT/fHw\n"
    "8V1pdgsYtyvVObXxR+S8xlY5qKRGaL6wuw7dmmme+WB1F18GBTQOM/NW47TIc7L1\n"
    "7sU6CJhj3Xus3hZ/0BgiJYsK+hkzs147OGES0mwQG30Bd96uGJ1vOLwweDGOphxu\n"
    "LhMNpEk09QKBgHriJu0InYX0tk5oubzAa241s4DWKst4MT4AWvC3/w1Gb2YUDTZc\n"
    "WHEOLD/B0Go5Ju0V5JGmAFcxlymrKCTg8tP2SjDWvJTnBNZHInHE/K5oqWhO1ppV\n"
    "sAX/yGpBB5T8ZjE4UDsOdlap/brxDRdRMYS5CuIIe7fC1W6dFtjPCHSpAoGABFtA\n"
    "WOJYfrCCL2zXLc8Yh/EYNrNurr84mCymq8f8Yl7d/iaCW0j4lxZKst58/Xi9xfDq\n"
    "Xai+i+XCTW7/iVyMsR7M5zVZf01RbBuPwWK9kAGfXTyG3BJ80i2HF/+GpbjWNqSX\n"
    "qWVI1mZi7qscv6G2ABwkYyIxRxZ2LqyLJtPiMxUCgYEAt973HNDhAzNYxACZMpLe\n"
    "dhN7nWcEbAUqd3gzuJEYId6F4q5F66MneMoWhjb5EheIc/+NdqyFUel3TR+WBRaj\n"
    "rwdZzzwdf3+I1mtx1i8/KkM/7zxhlGjQA731dWSpp4e7yJrSzj4tsJAXyj4j9zgc\n"
    "0p5ijORI4ZnFfGABG11xtyQ=\n"
    "-----END PRIVATE KEY-----\n";

class local_tls_server
{
   public:
    explicit local_tls_server(boost::asio::io_context& ctx) : ssl_ctx_(boost::asio::ssl::context::tls_server), acceptor_(ctx)
    {
        ssl_ctx_.set_options(boost::asio::ssl::context::default_workarounds);
        ssl_ctx_.use_certificate_chain(boost::asio::buffer(kTestCertPem, sizeof(kTestCertPem) - 1));
        ssl_ctx_.use_private_key(boost::asio::buffer(kTestKeyPem, sizeof(kTestKeyPem) - 1), boost::asio::ssl::context::pem);
#if defined(TLS1_3_VERSION)
        SSL_CTX_set_min_proto_version(ssl_ctx_.native_handle(), TLS1_3_VERSION);
#endif

        boost::asio::ip::tcp::endpoint const ep(boost::asio::ip::make_address("127.0.0.1"), 0);
        boost::system::error_code ec;
        acceptor_.open(ep.protocol(), ec);
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(ep, ec);
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
        port_ = acceptor_.local_endpoint(ec).port();
    }

    void start()
    {
        acceptor_.async_accept(
            [this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket)
            {
                if (ec)
                {
                    return;
                }
                auto stream = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(std::move(socket), ssl_ctx_);
                stream->async_handshake(boost::asio::ssl::stream_base::server, [stream](const boost::system::error_code&) {});
            });
    }

    [[nodiscard]] std::uint16_t port() const { return port_; }

   private:
    boost::asio::ssl::context ssl_ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::uint16_t port_ = 0;
};

}    // namespace

TEST(CertFetcherTest, BasicFetch)
{
    boost::asio::io_context ctx;
    local_tls_server server(ctx);
    server.start();
    bool finished = false;

    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            const auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", server.port(), "example.com");
            if (res.has_value())
            {
                EXPECT_FALSE(res->cert_msg.empty());
            }
            finished = true;
            co_return;
        },
        boost::asio::detached);

    boost::asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(10));
    timer.async_wait(
        [&](const boost::system::error_code ec)
        {
            if (!ec)
            {
                ctx.stop();
            }
        });

    ctx.run();
    EXPECT_TRUE(finished);
}

TEST(CertFetcherTest, ReassemblerLimits)
{
    {
        reality::handshake_reassembler assembler;
        std::vector<std::uint8_t> msg;
        std::vector<std::uint8_t> tiny = {0x01, 0x01};
        assembler.append(tiny);
        const auto tiny_res = assembler.next(msg);
        ASSERT_TRUE(tiny_res.has_value());
        EXPECT_FALSE(*tiny_res);
    }

    {
        reality::handshake_reassembler assembler;
        std::vector<std::uint8_t> msg;
        std::vector<std::uint8_t> header_only = {0x01, 0x00, 0x00, 0x10};
        assembler.append(header_only);
        const auto header_res = assembler.next(msg);
        ASSERT_TRUE(header_res.has_value());
        EXPECT_FALSE(*header_res);
    }

    {
        reality::handshake_reassembler assembler;
        std::vector<std::uint8_t> msg;
        std::vector<std::uint8_t> huge_header = {0x01, 0x01, 0x00, 0x01};
        assembler.append(huge_header);
        const auto huge_res = assembler.next(msg);
        EXPECT_FALSE(huge_res.has_value());
        EXPECT_EQ(huge_res.error(), std::errc::message_size);
    }

    {
        reality::handshake_reassembler assembler;
        std::vector<std::uint8_t> msg;
        std::vector<std::uint8_t> complete_msg = {0x01, 0x00, 0x00, 0x01, 0x7f};
        assembler.append(complete_msg);
        const auto complete_res = assembler.next(msg);
        ASSERT_TRUE(complete_res.has_value());
        EXPECT_TRUE(*complete_res);
        EXPECT_EQ(msg, complete_msg);
    }
}

TEST(CertFetcherTest, ReassemblerPartialMessagePath)
{
    reality::handshake_reassembler assembler;
    std::vector<std::uint8_t> msg;

    const std::vector<std::uint8_t> partial_msg = {0x01, 0x00, 0x00, 0x02, 0x7f};
    assembler.append(partial_msg);
    const auto partial_res = assembler.next(msg);
    ASSERT_TRUE(partial_res.has_value());
    EXPECT_FALSE(*partial_res);

    const std::array<std::uint8_t, 1> tail = {0x80};
    assembler.append(tail);
    const auto final_res = assembler.next(msg);
    ASSERT_TRUE(final_res.has_value());
    EXPECT_TRUE(*final_res);
    EXPECT_EQ(msg, std::vector<std::uint8_t>({0x01, 0x00, 0x00, 0x02, 0x7f, 0x80}));
}

TEST(CertFetcherTest, InitHandshakeMaterialFailureBranches)
{
    boost::asio::io_context ctx;
    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", 443, "example.com", "trace");

    std::vector<std::uint8_t> client_random(32, 0);
    std::vector<std::uint8_t> session_id(32, 0);

    fail_next_keygen();
    EXPECT_FALSE(session.init_handshake_material(client_random, session_id));

    fail_rand_bytes_on_call(1);
    EXPECT_FALSE(session.init_handshake_material(client_random, session_id));

    fail_rand_bytes_on_call(2);
    EXPECT_FALSE(session.init_handshake_material(client_random, session_id));
}

TEST(CertFetcherTest, MockServerScenarios)
{
    using boost::asio::ip::tcp;
    boost::asio::io_context ctx;

    auto run_mock_server = [&](std::vector<std::uint8_t> data_to_send)
    {
        auto acceptor = std::make_shared<tcp::acceptor>(ctx, tcp::endpoint(tcp::v4(), 0));
        std::uint16_t const port = acceptor->local_endpoint().port();

        boost::asio::co_spawn(
            ctx,
            [acceptor, data_to_send]() -> boost::asio::awaitable<void>
            {
                auto socket = co_await acceptor->async_accept(boost::asio::use_awaitable);
                co_await boost::asio::async_write(socket, boost::asio::buffer(data_to_send), boost::asio::use_awaitable);
                co_return;
            },
            boost::asio::detached);

        return port;
    };

    {
        std::vector<std::uint8_t> const bad_rec = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32};
        std::uint16_t port = run_mock_server(bad_rec);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> const unexpected_type = {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        std::uint16_t port = run_mock_server(unexpected_type);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> const short_sh = {0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01};
        std::uint16_t port = run_mock_server(short_sh);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> const too_short_sh = {0x16, 0x03, 0x03, 0x00, 0x03, 0x02, 0x00, 0x00};
        std::uint16_t port = run_mock_server(too_short_sh);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> const long_rec = {0x16, 0x03, 0x03, 0x48, 0x01};
        std::uint16_t port = run_mock_server(long_rec);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> const bad_cs_sh = {0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03, 0,    0,    0,    0,   0,
                                                0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,
                                                0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x00, 0x00, 0x00, 0x00};
        uint16_t port = run_mock_server(bad_cs_sh);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> const short_sid_sh = {0x16, 0x03, 0x03, 0x00, 0x26, 0x02, 0x00, 0x00, 0x22, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0

        };
        uint16_t port = run_mock_server(short_sid_sh);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> const sh_1302 = {0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03, 0,    0,    0,    0,   0,
                                              0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,
                                              0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x00, 0x13, 0x02, 0x00};
        uint16_t port = run_mock_server(sh_1302);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> const sh_1303 = {0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03, 0,    0,    0,    0,   0,
                                              0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,
                                              0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x00, 0x13, 0x03, 0x00};
        uint16_t port = run_mock_server(sh_1303);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> const short_sh_for_cs = {0x16, 0x03, 0x03, 0x00, 0x27, 0x02, 0x00, 0x00, 0x23, 0x03, 0x03, 0, 0, 0,   0,
                                                      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0,   0,
                                                      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0x00

        };
        uint16_t port = run_mock_server(short_sh_for_cs);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> const invalid_type = {0x99, 0x03, 0x03, 0x00, 0x01, 0x00};
        uint16_t port = run_mock_server(invalid_type);

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            boost::asio::detached);
        ctx.run();
        ctx.restart();
    }
}

TEST(CertFetcherTest, ConnectFailure)
{
    boost::asio::io_context ctx;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", 1, "localhost", "test");
            EXPECT_FALSE(res.has_value());
            co_return;
        },
        boost::asio::detached);
    ctx.run();
}

TEST(CertFetcherTest, ConnectTimeout)
{
    boost::asio::io_context ctx;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor saturated_acceptor(ctx);
    ec = saturated_acceptor.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.listen(1, ec);
    ASSERT_FALSE(ec);

    const auto target_port = saturated_acceptor.local_endpoint().port();
    boost::asio::ip::tcp::socket queued_client_a(ctx);
    queued_client_a.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket queued_client_b(ctx);
    queued_client_b.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);

    bool finished = false;
    const auto start = std::chrono::steady_clock::now();
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            auto res = co_await reality::cert_fetcher::fetch(ctx, "127.0.0.1", target_port, "localhost", "test", 1);
            EXPECT_FALSE(res.has_value());
            finished = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_TRUE(finished);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);

    boost::system::error_code close_ec;
    queued_client_a.close(close_ec);
    queued_client_b.close(close_ec);
    saturated_acceptor.close(close_ec);
}

TEST(CertFetcherTest, ReadRecordPlaintextRejectsOversizedLength)
{
    using boost::asio::ip::tcp;
    boost::asio::io_context ctx;

    auto acceptor = std::make_shared<tcp::acceptor>(ctx, tcp::endpoint(tcp::v4(), 0));
    const std::uint16_t port = acceptor->local_endpoint().port();

    boost::asio::co_spawn(
        ctx,
        [acceptor]() -> boost::asio::awaitable<void>
        {
            auto socket = co_await acceptor->async_accept(boost::asio::use_awaitable);
            const std::array<std::uint8_t, 5> oversized_header = {0x16, 0x03, 0x03, 0x48, 0x01};
            co_await boost::asio::async_write(socket, boost::asio::buffer(oversized_header), boost::asio::use_awaitable);
            boost::system::error_code close_ec;
            socket.close(close_ec);
            co_return;
        },
        boost::asio::detached);

    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", port, "example.com", "trace");
    boost::system::error_code read_ec;
    bool finished = false;

    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            const auto connect_ec = co_await session.connect();
            EXPECT_FALSE(connect_ec);

            const auto [ec, body] = co_await session.read_record_plaintext();
            read_ec = ec;
            EXPECT_TRUE(body.empty());
            finished = true;
            co_return;
        },
        boost::asio::detached);

    ctx.run();
    EXPECT_TRUE(finished);
    EXPECT_EQ(read_ec, std::errc::message_size);
}

TEST(CertFetcherTest, WhiteBoxHelpersAndRecordTypeBranches)
{
    std::array<std::uint8_t, 3> raw = {0x01, 0xab, 0xff};
    EXPECT_EQ(reality::cert_fetcher::hex(std::vector<std::uint8_t>{0x0f}), "0f");
    EXPECT_EQ(reality::cert_fetcher::hex(raw.data(), raw.size()), "01abff");

    boost::asio::io_context ctx;
    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", 443, "example.com", "trace");

    EXPECT_FALSE(session.validate_server_hello_body({}));
    EXPECT_TRUE(session.validate_server_hello_body({0x01}));

    const auto len_res = session.validate_record_length(20000);
    EXPECT_FALSE(len_res.has_value());
    EXPECT_EQ(len_res.error(), std::errc::message_size);

    std::vector<std::uint8_t> const rec = {0xaa, 0xbb, 0xcc};
    std::vector<std::uint8_t> pt_buf(1, 0);

    std::uint8_t alert_head[5] = {reality::kContentTypeAlert, 0x03, 0x03, 0x00, 0x03};
    auto alert_ret = session.handle_record_by_content_type(alert_head, rec, pt_buf);
    EXPECT_FALSE(alert_ret.has_value());
    EXPECT_EQ(alert_ret.error(), boost::asio::error::connection_reset);

    std::uint8_t bad_head[5] = {0x99, 0x03, 0x03, 0x00, 0x03};
    auto bad_ret = session.handle_record_by_content_type(bad_head, rec, pt_buf);
    EXPECT_FALSE(bad_ret.has_value());
    EXPECT_EQ(bad_ret.error(), boost::asio::error::invalid_argument);

    std::uint8_t ccs_head[5] = {reality::kContentTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x03};
    auto ccs_ret = session.handle_record_by_content_type(ccs_head, rec, pt_buf);
    ASSERT_TRUE(ccs_ret.has_value());
    EXPECT_EQ(ccs_ret->first, reality::kContentTypeChangeCipherSpec);
    EXPECT_EQ(ccs_ret->second.size(), rec.size());
    EXPECT_GE(pt_buf.size(), rec.size());

    session.negotiated_cipher_ = EVP_aes_128_gcm();
    session.dec_iv_.assign(12, 0);
    session.dec_key_.clear();

    std::uint8_t app_head[5] = {reality::kContentTypeApplicationData, 0x03, 0x03, 0x00, 0x10};
    std::vector<std::uint8_t> const app_rec(16, 0);
    auto app_ret = session.decrypt_application_record(app_head, app_rec, pt_buf);
    EXPECT_FALSE(app_ret.has_value());
    EXPECT_EQ(app_ret.error(), std::errc::invalid_argument);
}

TEST(CertFetcherTest, WhiteBoxProcessServerHelloAndHandshakeMessage)
{
    boost::asio::io_context ctx;
    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", 443, "example.com", "trace");

    std::vector<std::uint8_t> server_hello(43, 0);
    server_hello[0] = 0x02;
    server_hello[3] = 39;
    server_hello[38] = 0x00;
    server_hello[39] = 0x12;
    server_hello[40] = 0x34;

    const auto ec = session.process_server_hello(server_hello);
    EXPECT_EQ(ec, boost::asio::error::no_protocol_option);

    auto encrypted_extensions = reality::construct_encrypted_extensions("h2");
    std::vector<std::uint8_t> cert_msg;
    EXPECT_FALSE(session.process_handshake_message(encrypted_extensions, cert_msg));
    EXPECT_EQ(session.fingerprint_.alpn, "h2");

    const std::vector<std::uint8_t> cert_handshake = {0x0b, 0x00, 0x00, 0x00};
    EXPECT_TRUE(session.process_handshake_message(cert_handshake, cert_msg));
    EXPECT_EQ(cert_msg, cert_handshake);

    const std::vector<std::uint8_t> other_handshake = {0x0f, 0x00, 0x00, 0x00};
    EXPECT_FALSE(session.process_handshake_message(other_handshake, cert_msg));
}

TEST(CertFetcherTest, ProcessServerHelloHandlesHkdfContextFailure)
{
    boost::asio::io_context ctx;
    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", 443, "example.com", "trace");

    std::array<std::uint8_t, 32> client_public{};
    std::array<std::uint8_t, 32> client_private{};
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(client_public.data(), client_private.data()));
    std::memcpy(session.client_private_, client_private.data(), client_private.size());

    std::array<std::uint8_t, 32> server_public{};
    std::array<std::uint8_t, 32> server_private{};
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(server_public.data(), server_private.data()));

    const auto server_hello = reality::construct_server_hello(std::vector<std::uint8_t>(32, 0x11),
                                                              std::vector<std::uint8_t>(32, 0x22),
                                                              reality::tls_consts::cipher::kTlsAes128GcmSha256,
                                                              reality::tls_consts::group::kX25519,
                                                              std::vector<std::uint8_t>(server_public.begin(), server_public.end()));

    fail_next_hkdf_md();
    const auto ec = session.process_server_hello(server_hello);
    EXPECT_EQ(ec, std::errc::protocol_error);
}

TEST(CertFetcherTest, ProcessServerHelloTruncatedMessageLength)
{
    boost::asio::io_context ctx;
    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", 443, "example.com", "trace");

    std::vector<std::uint8_t> const server_hello = {0x02, 0x00, 0x00, 0x20, 0x01};
    const auto ec = session.process_server_hello(server_hello);
    EXPECT_EQ(ec, boost::asio::error::fault);
}

TEST(CertFetcherTest, SendClientHelloRejectsOversizedPayload)
{
    boost::asio::io_context ctx;
    reality::cert_fetcher::fetch_session session(ctx, "127.0.0.1", 443, "example.com", "trace");

    boost::system::error_code write_ec;
    bool finished = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            const std::vector<std::uint8_t> oversized_client_hello(70000, 0x42);
            write_ec = co_await session.send_client_hello_record(oversized_client_hello);
            finished = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();

    EXPECT_TRUE(finished);
    EXPECT_EQ(write_ec, std::errc::message_size);
}
