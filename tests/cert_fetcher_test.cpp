#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/this_coro.hpp>
#include <asio/io_context.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include "cert_fetcher.h"

namespace
{

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

class LocalTlsServer
{
   public:
    explicit LocalTlsServer(asio::io_context& ctx)
        : ssl_ctx_(asio::ssl::context::tls_server), acceptor_(ctx)
    {
        ssl_ctx_.set_options(asio::ssl::context::default_workarounds);
        ssl_ctx_.use_certificate_chain(asio::buffer(kTestCertPem, sizeof(kTestCertPem) - 1));
        ssl_ctx_.use_private_key(asio::buffer(kTestKeyPem, sizeof(kTestKeyPem) - 1), asio::ssl::context::pem);
#if defined(TLS1_3_VERSION)
        SSL_CTX_set_min_proto_version(ssl_ctx_.native_handle(), TLS1_3_VERSION);
#endif

        asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), 0);
        std::error_code ec;
        acceptor_.open(ep.protocol(), ec);
        acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(ep, ec);
        acceptor_.listen(asio::socket_base::max_listen_connections, ec);
        port_ = acceptor_.local_endpoint(ec).port();
    }

    void start()
    {
        acceptor_.async_accept(
            [this](const std::error_code& ec, asio::ip::tcp::socket socket)
            {
                if (ec)
                {
                    return;
                }
                auto stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(socket), ssl_ctx_);
                stream->async_handshake(asio::ssl::stream_base::server, [stream](const std::error_code&) {});
            });
    }

    [[nodiscard]] std::uint16_t port() const { return port_; }

   private:
    asio::ssl::context ssl_ctx_;
    asio::ip::tcp::acceptor acceptor_;
    std::uint16_t port_ = 0;
};

}    // namespace

TEST(CertFetcherTest, BasicFetch)
{
    asio::io_context ctx;
    LocalTlsServer server(ctx);
    server.start();
    bool finished = false;

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            const auto ex = co_await asio::this_coro::executor;
            const auto res = co_await reality::cert_fetcher::fetch(ex, "127.0.0.1", server.port(), "example.com");
            if (res.has_value())
            {
                EXPECT_FALSE(res->cert_msg.empty());
            }
            finished = true;
            co_return;
        },
        asio::detached);

    asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(10));
    timer.async_wait(
        [&](const std::error_code ec)
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
    reality::handshake_reassembler assembler;
    std::vector<std::uint8_t> msg;
    std::error_code ec;

    std::vector<std::uint8_t> tiny = {0x01, 0x01};
    assembler.append(tiny);
    EXPECT_FALSE(assembler.next(msg, ec));

    std::vector<std::uint8_t> header_only = {0x01, 0x00, 0x00, 0x10};
    assembler.append(header_only);
    EXPECT_FALSE(assembler.next(msg, ec));

    std::vector<std::uint8_t> huge_header = {0x01, 0x01, 0x00, 0x01};
    assembler.append(huge_header);
    EXPECT_FALSE(assembler.next(msg, ec));
    EXPECT_EQ(ec, std::errc::message_size);
}

TEST(CertFetcherTest, MockServerScenarios)
{
    using asio::ip::tcp;
    asio::io_context ctx;

    auto run_mock_server = [&](std::vector<std::uint8_t> data_to_send)
    {
        auto acceptor = std::make_shared<tcp::acceptor>(ctx, tcp::endpoint(tcp::v4(), 0));
        std::uint16_t port = acceptor->local_endpoint().port();

        asio::co_spawn(
            ctx,
            [acceptor, data_to_send]() -> asio::awaitable<void>
            {
                auto socket = co_await acceptor->async_accept(asio::use_awaitable);
                co_await asio::async_write(socket, asio::buffer(data_to_send), asio::use_awaitable);
                co_return;
            },
            asio::detached);

        return port;
    };

    {
        std::vector<std::uint8_t> bad_rec = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32};
        std::uint16_t port = run_mock_server(bad_rec);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> unexpected_type = {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        std::uint16_t port = run_mock_server(unexpected_type);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> short_sh = {0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01};
        std::uint16_t port = run_mock_server(short_sh);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> long_rec = {0x16, 0x03, 0x03, 0x48, 0x01};
        std::uint16_t port = run_mock_server(long_rec);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> bad_cs_sh = {0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03, 0,    0,    0,    0,   0,
                                          0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,
                                          0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x00, 0x00, 0x00, 0x00};
        uint16_t port = run_mock_server(bad_cs_sh);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> short_sid_sh = {0x16, 0x03, 0x03, 0x00, 0x26, 0x02, 0x00, 0x00, 0x22, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0

        };
        uint16_t port = run_mock_server(short_sid_sh);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> sh_1302 = {0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03, 0,    0,    0,    0,   0,
                                        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,
                                        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x00, 0x13, 0x02, 0x00};
        uint16_t port = run_mock_server(sh_1302);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> sh_1303 = {0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03, 0,    0,    0,    0,   0,
                                        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,
                                        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x00, 0x13, 0x03, 0x00};
        uint16_t port = run_mock_server(sh_1303);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<uint8_t> short_sh_for_cs = {0x16, 0x03, 0x03, 0x00, 0x27, 0x02, 0x00, 0x00, 0x23, 0x03, 0x03, 0, 0, 0,   0,
                                                0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0,   0,
                                                0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0x00

        };
        uint16_t port = run_mock_server(short_sh_for_cs);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    {
        std::vector<std::uint8_t> invalid_type = {0x99, 0x03, 0x03, 0x00, 0x01, 0x00};
        uint16_t port = run_mock_server(invalid_type);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }
}

TEST(CertFetcherTest, ConnectFailure)
{
    asio::io_context ctx;
    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", 1, "localhost", "test");
            EXPECT_FALSE(res.has_value());
            co_return;
        },
        asio::detached);
    ctx.run();
}
