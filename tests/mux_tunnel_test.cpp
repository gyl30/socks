// NOLINTBEGIN(readability-named-parameter)
// NOLINTBEGIN(misc-include-cleaner)
#include <memory>
#include <string>
#include <cstdint>

#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "test_util.h"
#define private public
#include "mux_tunnel.h"
#undef private

namespace
{

using tunnel_t = mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>;

class noop_stream : public mux::mux_stream_interface
{
   public:
    void on_data(std::vector<std::uint8_t>) override {}
    void on_close() override {}
    void on_reset() override {}
};

std::shared_ptr<tunnel_t> make_tunnel(boost::asio::io_context& io_context, const std::uint32_t conn_id = 1)
{
    return std::make_shared<tunnel_t>(
        boost::asio::ip::tcp::socket(io_context),
        io_context,
        mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
        true,
        conn_id,
        "base-trace");
}

TEST(MuxTunnelTest, NullConnectionGuardsAllPublicMethods)
{
    boost::asio::io_context io_context;
    auto tunnel = make_tunnel(io_context);
    tunnel->connection_ = nullptr;

    EXPECT_FALSE(tunnel->register_stream(1, nullptr));
    EXPECT_FALSE(tunnel->try_register_stream(2, nullptr));
    EXPECT_EQ(tunnel->create_stream(), nullptr);
    tunnel->remove_stream(3);

    mux::test::run_awaitable_void(io_context, tunnel->run());
}

TEST(MuxTunnelTest, CreateStreamAndRegisterPaths)
{
    boost::asio::io_context io_context;
    auto tunnel = make_tunnel(io_context, 2);
    auto stream_a = std::make_shared<noop_stream>();
    auto stream_b = std::make_shared<noop_stream>();

    auto stream_default_trace = tunnel->create_stream();
    ASSERT_NE(stream_default_trace, nullptr);
    EXPECT_TRUE(tunnel->connection_->has_stream(stream_default_trace->id()));

    auto stream_custom_trace = tunnel->create_stream("custom-trace");
    ASSERT_NE(stream_custom_trace, nullptr);
    EXPECT_TRUE(tunnel->connection_->has_stream(stream_custom_trace->id()));
    EXPECT_NE(stream_default_trace->id(), stream_custom_trace->id());

    EXPECT_TRUE(tunnel->try_register_stream(9001, stream_a));
    EXPECT_FALSE(tunnel->try_register_stream(9001, stream_b));
    EXPECT_TRUE(tunnel->connection_->has_stream(9001));

    EXPECT_TRUE(tunnel->register_stream(9002, stream_b));
    EXPECT_TRUE(tunnel->connection_->has_stream(9002));

    tunnel->remove_stream(9001);
    tunnel->remove_stream(9002);
    EXPECT_FALSE(tunnel->connection_->has_stream(9001));
    EXPECT_FALSE(tunnel->connection_->has_stream(9002));
}

TEST(MuxTunnelTest, RunWithConnectionCoversStartPath)
{
    boost::asio::io_context io_context;
    auto tunnel = make_tunnel(io_context, 7);

    tunnel->connection_->connection_state_.store(mux::mux_connection_state::kClosed, std::memory_order_release);
    mux::test::run_awaitable_void(io_context, tunnel->run());
}

TEST(MuxTunnelTest, CreateStreamReturnsNullWhenClosedOrAtCapacity)
{
    boost::asio::io_context io_context;
    auto tunnel = make_tunnel(io_context, 3);

    tunnel->connection_->connection_state_.store(mux::mux_connection_state::kClosed, std::memory_order_release);
    EXPECT_EQ(tunnel->create_stream(), nullptr);

    tunnel->connection_->connection_state_.store(mux::mux_connection_state::kConnected, std::memory_order_release);
    tunnel->connection_->limits_config_.max_streams = 1;
    auto first = tunnel->create_stream();
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(tunnel->create_stream(), nullptr);
}

}    // namespace
// NOLINTEND(misc-include-cleaner)
// NOLINTEND(readability-named-parameter)
