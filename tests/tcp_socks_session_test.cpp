#include <memory>

#include <gtest/gtest.h>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>

#define private public
#include "tcp_socks_session.h"
#undef private

namespace
{

TEST(TcpSocksSessionTest, CreateBackendReturnsNullForBlockRoute)
{
    asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};

    auto session = std::make_shared<mux::tcp_socks_session>(
        asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    EXPECT_EQ(session->create_backend(mux::route_type::kBlock), nullptr);
}

}    // namespace
