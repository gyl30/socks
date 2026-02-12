#include <memory>

#include <gtest/gtest.h>
#include <asio/io_context.hpp>

#define private public
#include "remote_udp_session.h"
#undef private

namespace
{

TEST(RemoteUdpSessionTest, CloseSocketNoopWhenNotOpen)
{
    asio::io_context io_context;
    mux::connection_context ctx;

    auto session = std::make_shared<mux::remote_udp_session>(std::shared_ptr<mux::mux_connection>{}, 1, io_context, ctx);
    session->close_socket();
    SUCCEED();
}

}    // namespace
