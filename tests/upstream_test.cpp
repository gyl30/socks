#include <chrono>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <system_error>
#include <cerrno>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>

#include <sys/socket.h>
#include <netinet/tcp.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "log.h"
#include "statistics.h"
#define private public
#include "upstream.h"
#undef private
#include "test_util.h"
#include "mux_tunnel.h"
#include "mux_codec.h"
#include "protocol.h"
#include "log_context.h"
#include "mock_mux_connection.h"

namespace
{

std::atomic<bool> g_fail_so_mark_setsockopt_once{false};
std::atomic<int> g_fail_so_mark_setsockopt_errno{EPERM};
std::atomic<bool> g_fail_tcp_nodelay_setsockopt_once{false};
std::atomic<int> g_fail_tcp_nodelay_setsockopt_errno{EPERM};

void fail_next_so_mark_setsockopt(const int err)
{
    g_fail_so_mark_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_so_mark_setsockopt_once.store(true, std::memory_order_release);
}

void fail_next_tcp_nodelay_setsockopt(const int err)
{
    g_fail_tcp_nodelay_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_tcp_nodelay_setsockopt_once.store(true, std::memory_order_release);
}

extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
#ifdef SO_MARK
    if (level == SOL_SOCKET && optname == SO_MARK && g_fail_so_mark_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_so_mark_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
#endif
    if (level == IPPROTO_TCP && optname == TCP_NODELAY &&
        g_fail_tcp_nodelay_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_tcp_nodelay_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> make_test_tunnel(
    boost::asio::io_context& io_context, const mux::config::limits_t& limits = {})
{
    return std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(io_context),
        io_context,
        mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
        true,
        9,
        "",
        mux::config::timeout_t{},
        limits,
        mux::config::heartbeat_t{});
}

std::shared_ptr<mux::mux_stream> make_mock_stream(boost::asio::io_context& io_context,
                                                   const std::shared_ptr<mux::mock_mux_connection>& connection,
                                                   const std::uint32_t stream_id = 1)
{
    return std::make_shared<mux::mux_stream>(stream_id, 100, "trace-upstream", connection, io_context);
}

}    // namespace

class upstream_test : public ::testing::Test
{
   protected:
    void TearDown() override { ctx_.stop(); }
    boost::asio::io_context& ctx() { return ctx_; }

   private:
    boost::asio::io_context ctx_;
};

class echo_server
{
   public:
    echo_server() : acceptor_(ctx_, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0))
    {
        do_accept();
        thread_ = std::thread([this] { ctx_.run(); });
    }

    [[nodiscard]] std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

    ~echo_server() noexcept
    {
        stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    void stop()
    {
        if (stopped_.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        ctx_.stop();
    }

   private:
    void do_accept()
    {
        if (stopped_.load(std::memory_order_acquire))
        {
            return;
        }
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*socket,
                               [this, socket](const boost::system::error_code ec)
                               {
                                    if (!ec)
                                    {
                                        do_echo(socket);
                                    }
                                   if (!stopped_.load(std::memory_order_acquire))
                                   {
                                       do_accept();
                                   }
                               });
    }

    void do_echo(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
    {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(1024);
        socket->async_read_some(boost::asio::buffer(*buf),
                                [this, socket, buf](const boost::system::error_code ec, const std::size_t n)
                                {
                                    if (!ec)
                                    {
                                        boost::asio::async_write(*socket,
                                                          boost::asio::buffer(*buf, n),
                                                          [this, socket, buf](const boost::system::error_code ec_write, std::size_t)
                                                          {
                                                              if (!ec_write)
                                                              {
                                                                  do_echo(socket);
                                                              }
                                                          });
                                    }
                                });
    }

    boost::asio::io_context ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::thread thread_;
    std::atomic<bool> stopped_{false};
};

TEST_F(upstream_test, DirectUpstreamConnectSuccess)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    const std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};
    const auto write_n = mux::test::run_awaitable(ctx(), upstream.write(data));
    EXPECT_EQ(write_n, 3);

    std::vector<std::uint8_t> buf(1024);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, 3);
    EXPECT_EQ(buf[0], 0x01);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamConnectFail)
{
    auto& stats = mux::statistics::instance();
    const auto connect_errors_before = stats.direct_upstream_connect_errors();
    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", 1));
    EXPECT_FALSE(success);
    EXPECT_GE(stats.direct_upstream_connect_errors(), connect_errors_before + 1);
}

TEST_F(upstream_test, DirectUpstreamConnectTimeoutWhenBacklogSaturated)
{
    auto& stats = mux::statistics::instance();
    const auto connect_timeouts_before = stats.direct_upstream_connect_timeouts();
    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor saturated_acceptor(ctx());
    ec = saturated_acceptor.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.listen(1, ec);
    ASSERT_FALSE(ec);

    const auto target_port = saturated_acceptor.local_endpoint().port();
    boost::asio::ip::tcp::socket queued_client_a(ctx());
    queued_client_a.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket queued_client_b(ctx());
    queued_client_b.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);

    mux::direct_upstream upstream(ctx(), mux::connection_context{}, 0, 1);
    const auto start = std::chrono::steady_clock::now();
    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", target_port));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_FALSE(success);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);
    EXPECT_GE(stats.direct_upstream_connect_timeouts(), connect_timeouts_before + 1);

    boost::system::error_code close_ec;
    queued_client_a.close(close_ec);
    queued_client_b.close(close_ec);
    saturated_acceptor.close(close_ec);
}

TEST_F(upstream_test, DirectUpstreamResolveFail)
{
    auto& stats = mux::statistics::instance();
    const auto resolve_errors_before = stats.direct_upstream_resolve_errors();
    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("non-existent.invalid", 80));
    EXPECT_FALSE(success);
    EXPECT_GE(stats.direct_upstream_resolve_errors(), resolve_errors_before + 1);
}

TEST_F(upstream_test, DirectUpstreamReconnectSuccess)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{});
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));

    const std::vector<std::uint8_t> data = {0xAB, 0xCD};
    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write(data)), data.size());

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, data.size());
    EXPECT_EQ(buf[0], 0xAB);
    EXPECT_EQ(buf[1], 0xCD);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamConnectWithSocketMark)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{}, 1);
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));

    const std::vector<std::uint8_t> data = {0x11};
    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write(data)), data.size());

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, data.size());
    EXPECT_EQ(buf[0], 0x11);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamConnectWithSocketMarkFailureStillSucceeds)
{
    echo_server server;
    const std::uint16_t port = server.port();

    fail_next_so_mark_setsockopt(EPERM);
    mux::direct_upstream upstream(ctx(), mux::connection_context{}, 1);
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));

    std::vector<std::uint8_t> buf(16);
    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write({0x21})), 1U);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, 1U);
    EXPECT_EQ(buf[0], 0x21);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamConnectWithNoDelayFailureStillSucceeds)
{
    echo_server server;
    const std::uint16_t port = server.port();

    fail_next_tcp_nodelay_setsockopt(EPERM);
    mux::direct_upstream upstream(ctx(), mux::connection_context{});
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));

    std::vector<std::uint8_t> buf(16);
    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write({0x31})), 1U);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, 1U);
    EXPECT_EQ(buf[0], 0x31);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamWriteError)
{
    auto acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(ctx(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
    std::uint16_t port = acceptor->local_endpoint().port();

    boost::asio::co_spawn(
        ctx(),
        [acceptor]() -> boost::asio::awaitable<void>
        {
            auto socket = co_await acceptor->async_accept(boost::asio::use_awaitable);
            socket.close();
            co_return;
        },
        boost::asio::detached);

    mux::direct_upstream upstream(ctx(), mux::connection_context{});
    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::size_t write_n = 1;
    for (int i = 0; i < 10 && write_n > 0; ++i)
    {
        write_n = mux::test::run_awaitable(ctx(), upstream.write({0x01, 0x02, 0x03}));
    }

    EXPECT_EQ(write_n, 0);
}

TEST_F(upstream_test, DirectUpstreamClose)
{
    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    mux::test::run_awaitable_void(ctx(), upstream.close());
}

TEST_F(upstream_test, DirectUpstreamReadAfterCloseReturnsError)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{});
    ASSERT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));
    mux::test::run_awaitable_void(ctx(), upstream.close());

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_TRUE(read_ec);
    EXPECT_EQ(read_n, 0U);
    server.stop();
}

TEST_F(upstream_test, ProxyUpstreamReadWriteWithoutConnect)
{
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_EQ(read_ec, boost::asio::error::operation_aborted);
    EXPECT_EQ(read_n, 0);

    const auto write_n = mux::test::run_awaitable(ctx(), upstream.write({0x01, 0x02, 0x03}));
    EXPECT_EQ(write_n, 0);

    mux::test::run_awaitable_void(ctx(), upstream.close());
}

TEST_F(upstream_test, ProxyUpstreamConnectFailsWhenTunnelStopped)
{
    auto tunnel = make_test_tunnel(ctx());
    tunnel->connection()->stop();

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("example.com", 443));
    EXPECT_FALSE(success);
}

TEST_F(upstream_test, ProxyUpstreamIsTunnelReadyCoversShortCircuitBranches)
{
    mux::proxy_upstream null_tunnel_upstream(nullptr, mux::connection_context{});
    EXPECT_FALSE(null_tunnel_upstream.is_tunnel_ready());

    auto tunnel_without_connection = make_test_tunnel(ctx());
    tunnel_without_connection->connection_ = nullptr;
    mux::proxy_upstream no_connection_upstream(tunnel_without_connection, mux::connection_context{});
    EXPECT_FALSE(no_connection_upstream.is_tunnel_ready());

    auto stopped_tunnel = make_test_tunnel(ctx());
    stopped_tunnel->connection()->stop();
    mux::proxy_upstream stopped_upstream(stopped_tunnel, mux::connection_context{});
    EXPECT_FALSE(stopped_upstream.is_tunnel_ready());

    auto ready_tunnel = make_test_tunnel(ctx());
    mux::proxy_upstream ready_upstream(ready_tunnel, mux::connection_context{});
    EXPECT_TRUE(ready_upstream.is_tunnel_ready());
}

TEST_F(upstream_test, ProxyUpstreamConnectFailsWhenCreateStreamRejectedByLimit)
{
    mux::config::limits_t limits;
    limits.max_streams = 1;
    auto tunnel = make_test_tunnel(ctx(), limits);
    ASSERT_NE(tunnel->create_stream("already-used"), nullptr);

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("example.com", 443));
    EXPECT_FALSE(success);
}

TEST_F(upstream_test, ProxyUpstreamConnectSuccessSetsStream)
{
    auto tunnel = make_test_tunnel(ctx());
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    ON_CALL(*mock_conn, id()).WillByDefault(::testing::Return(9));
    ON_CALL(*mock_conn, mock_send_async(::testing::_, ::testing::_, ::testing::_)).WillByDefault(::testing::Return(boost::system::error_code{}));
    tunnel->connection_ = mock_conn;

    EXPECT_CALL(*mock_conn, mock_send_async(::testing::_, mux::kCmdSyn, ::testing::_)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(::testing::_, ::testing::_))
        .WillOnce(
            [this](const std::uint32_t id, std::shared_ptr<mux::mux_stream_interface> stream_iface) -> bool
            {
                (void)id;
                auto stream = std::dynamic_pointer_cast<mux::mux_stream>(stream_iface);
                EXPECT_NE(stream, nullptr);
                if (stream == nullptr)
                {
                    return false;
                }

                mux::ack_payload ack{};
                ack.socks_rep = socks::kRepSuccess;
                std::vector<std::uint8_t> ack_data;
                mux::mux_codec::encode_ack(ack, ack_data);
                boost::asio::post(this->ctx(), [stream, ack_data]() { stream->on_data(ack_data); });
                return true;
            });

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("example.com", 443)));
    EXPECT_NE(upstream.stream_, nullptr);
}

TEST_F(upstream_test, ProxyUpstreamConnectFailsWhenSendSynFailsAndCleansStream)
{
    auto tunnel = make_test_tunnel(ctx());
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    ON_CALL(*mock_conn, id()).WillByDefault(::testing::Return(9));
    ON_CALL(*mock_conn, mock_send_async(::testing::_, ::testing::_, ::testing::_)).WillByDefault(::testing::Return(boost::system::error_code{}));
    tunnel->connection_ = mock_conn;

    std::uint32_t stream_id = 0;
    EXPECT_CALL(*mock_conn, register_stream(::testing::_, ::testing::_))
        .WillOnce([&stream_id](const std::uint32_t id, std::shared_ptr<mux::mux_stream_interface> stream)
                  {
                      (void)stream;
                      stream_id = id;
                      return true;
                  });
    EXPECT_CALL(*mock_conn, mock_send_async(::testing::_, mux::kCmdSyn, ::testing::_)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));
    EXPECT_CALL(*mock_conn, mock_send_async(::testing::_, mux::kCmdFin, ::testing::_)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(::testing::_)).Times(1);

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    EXPECT_FALSE(mux::test::run_awaitable(ctx(), upstream.connect("example.com", 443)));
    EXPECT_EQ(upstream.stream_, nullptr);
    EXPECT_NE(stream_id, 0U);
}

TEST_F(upstream_test, ProxyUpstreamConnectFailsWhenAckRejectedAndCleansStream)
{
    auto tunnel = make_test_tunnel(ctx());
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    ON_CALL(*mock_conn, id()).WillByDefault(::testing::Return(9));
    ON_CALL(*mock_conn, mock_send_async(::testing::_, ::testing::_, ::testing::_)).WillByDefault(::testing::Return(boost::system::error_code{}));
    tunnel->connection_ = mock_conn;

    EXPECT_CALL(*mock_conn, register_stream(::testing::_, ::testing::_))
        .WillOnce(
            [this](const std::uint32_t id, std::shared_ptr<mux::mux_stream_interface> stream_iface) -> bool
            {
                (void)id;
                auto stream = std::dynamic_pointer_cast<mux::mux_stream>(stream_iface);
                EXPECT_NE(stream, nullptr);
                if (stream == nullptr)
                {
                    return false;
                }

                mux::ack_payload ack{};
                ack.socks_rep = socks::kRepConnRefused;
                std::vector<std::uint8_t> ack_data;
                mux::mux_codec::encode_ack(ack, ack_data);
                boost::asio::post(this->ctx(), [stream, ack_data]() { stream->on_data(ack_data); });
                return true;
            });
    EXPECT_CALL(*mock_conn, mock_send_async(::testing::_, mux::kCmdSyn, ::testing::_)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, mock_send_async(::testing::_, mux::kCmdFin, ::testing::_)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(::testing::_)).Times(1);

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    EXPECT_FALSE(mux::test::run_awaitable(ctx(), upstream.connect("example.com", 443)));
    EXPECT_EQ(upstream.stream_, nullptr);
}

TEST_F(upstream_test, ProxyUpstreamSendSynRequestSuccess)
{
    auto tunnel = make_test_tunnel(ctx());
    auto stream = tunnel->create_stream("trace");
    ASSERT_NE(stream, nullptr);

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.send_syn_request(stream, "example.com", 443)));
}

TEST_F(upstream_test, ProxyUpstreamSendSynRequestFailureWhenConnectionStopped)
{
    auto tunnel = make_test_tunnel(ctx());
    auto stream = tunnel->create_stream("trace");
    ASSERT_NE(stream, nullptr);
    tunnel->connection()->stop();

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    EXPECT_FALSE(mux::test::run_awaitable(ctx(), upstream.send_syn_request(stream, "example.com", 443)));
}

TEST_F(upstream_test, ProxyUpstreamWaitConnectAckSuccess)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    mux::ack_payload ack{};
    ack.socks_rep = socks::kRepSuccess;
    std::vector<std::uint8_t> ack_data;
    mux::mux_codec::encode_ack(ack, ack_data);
    stream->on_data(ack_data);

    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.wait_connect_ack(stream, "example.com", 443)));
}

TEST_F(upstream_test, ProxyUpstreamWaitConnectAckReadError)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    stream->on_reset();
    EXPECT_FALSE(mux::test::run_awaitable(ctx(), upstream.wait_connect_ack(stream, "example.com", 443)));
}

TEST_F(upstream_test, ProxyUpstreamWaitConnectAckDecodeFailure)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    stream->on_data({0x01});
    EXPECT_FALSE(mux::test::run_awaitable(ctx(), upstream.wait_connect_ack(stream, "example.com", 443)));
}

TEST_F(upstream_test, ProxyUpstreamWaitConnectAckRemoteReject)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    mux::ack_payload ack{};
    ack.socks_rep = socks::kRepConnRefused;
    std::vector<std::uint8_t> ack_data;
    mux::mux_codec::encode_ack(ack, ack_data);
    stream->on_data(ack_data);

    EXPECT_FALSE(mux::test::run_awaitable(ctx(), upstream.wait_connect_ack(stream, "example.com", 443)));
}

TEST_F(upstream_test, ProxyUpstreamCleanupNullStreamNoop)
{
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    mux::test::run_awaitable_void(ctx(), upstream.cleanup_stream(nullptr));
}

TEST_F(upstream_test, ProxyUpstreamCleanupStreamWithoutTunnelStillClosesStream)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn, 23);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    EXPECT_CALL(*mock_conn, mock_send_async(23, mux::kCmdFin, std::vector<std::uint8_t>{}))
        .WillOnce(::testing::Return(boost::system::error_code{}));
    mux::test::run_awaitable_void(ctx(), upstream.cleanup_stream(stream));
}

TEST_F(upstream_test, ProxyUpstreamCleanupStreamRemovesFromTunnel)
{
    auto tunnel = make_test_tunnel(ctx());
    auto stream = tunnel->create_stream("trace");
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(tunnel->connection()->has_stream(stream->id()));

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    mux::test::run_awaitable_void(ctx(), upstream.cleanup_stream(stream));
    EXPECT_FALSE(tunnel->connection()->has_stream(stream->id()));
}

TEST_F(upstream_test, ProxyUpstreamReadCopiesDataAndResizesBuffer)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    upstream.stream_ = stream;

    const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC, 0xDD};
    stream->on_data(payload);

    std::vector<std::uint8_t> buf(1);
    const auto [ec, n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(ec);
    EXPECT_EQ(n, payload.size());
    EXPECT_EQ(buf.size(), payload.size());
    EXPECT_EQ(std::vector<std::uint8_t>(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n)), payload);
}

TEST_F(upstream_test, ProxyUpstreamReadReturnsZeroWhenStreamReportsEof)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    upstream.stream_ = stream;

    stream->on_close();
    std::vector<std::uint8_t> buf(8);
    const auto [ec, n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_EQ(ec, boost::asio::error::eof);
    EXPECT_EQ(n, 0U);
}

TEST_F(upstream_test, ProxyUpstreamReadReturnsZeroWhenPayloadEmpty)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    upstream.stream_ = stream;

    stream->on_data({});
    std::vector<std::uint8_t> buf(8);
    const auto [ec, n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_EQ(ec, boost::asio::error::eof);
    EXPECT_EQ(n, 0U);
}

TEST_F(upstream_test, ProxyUpstreamWriteSuccess)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn, 7);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    upstream.stream_ = stream;

    const std::vector<std::uint8_t> data = {1, 2, 3};
    EXPECT_CALL(*mock_conn, mock_send_async(7, mux::kCmdDat, data)).WillOnce(::testing::Return(boost::system::error_code{}));

    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write(data)), data.size());
}

TEST_F(upstream_test, ProxyUpstreamWriteErrorReturnsZero)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn, 8);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    upstream.stream_ = stream;

    const std::vector<std::uint8_t> data = {4, 5, 6};
    EXPECT_CALL(*mock_conn, mock_send_async(8, mux::kCmdDat, data)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));

    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write(data)), 0U);
}

TEST_F(upstream_test, ProxyUpstreamCloseWithStreamNoTunnel)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = make_mock_stream(ctx(), mock_conn, 9);
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});
    upstream.stream_ = stream;

    EXPECT_CALL(*mock_conn, mock_send_async(9, mux::kCmdFin, std::vector<std::uint8_t>())).WillOnce(::testing::Return(boost::system::error_code{}));
    mux::test::run_awaitable_void(ctx(), upstream.close());
    EXPECT_EQ(upstream.stream_, nullptr);
}

TEST_F(upstream_test, ProxyUpstreamCloseWithStreamAndTunnelRemovesStream)
{
    auto tunnel = make_test_tunnel(ctx());
    auto stream = tunnel->create_stream("trace-close");
    ASSERT_NE(stream, nullptr);

    mux::proxy_upstream upstream(tunnel, mux::connection_context{});
    upstream.stream_ = stream;
    ASSERT_TRUE(tunnel->connection()->has_stream(stream->id()));

    mux::test::run_awaitable_void(ctx(), upstream.close());
    EXPECT_EQ(upstream.stream_, nullptr);
    EXPECT_FALSE(tunnel->connection()->has_stream(stream->id()));
}

TEST_F(upstream_test, MovedFromTunnelReturnsNullAndRejectsRegister)
{
    mux::mux_tunnel_impl<boost::asio::ip::tcp::socket> tunnel(
        boost::asio::ip::tcp::socket(ctx()), ctx(), mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 7);
    auto moved = std::move(tunnel);
    (void)moved;

    EXPECT_FALSE(tunnel.try_register_stream(1, nullptr));
    EXPECT_EQ(tunnel.create_stream("moved"), nullptr);
}
