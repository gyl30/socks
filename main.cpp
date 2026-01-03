#include <iostream>
#include <memory>
#include <vector>
#include <thread>
#include <boost/asio.hpp>
#include "log.h"
#include "session.h"
#include "scoped_exit.h"
#include "context_pool.h"

[[nodiscard]] boost::asio::awaitable<void> listener(boost::asio::ip::tcp::acceptor acceptor, io_context_pool& pool)
{
    while (true)
    {
        boost::asio::io_context& target_ctx = pool.get_io_context();
        auto target_executor = target_ctx.get_executor();

        boost::asio::ip::tcp::socket socket = co_await acceptor.async_accept(target_executor, boost::asio::use_awaitable);

        boost::asio::co_spawn(
            target_executor,
            [socket = std::move(socket)]() mutable -> boost::asio::awaitable<void>
            { co_await std::make_shared<session>(std::move(socket))->start(); },
            boost::asio::detached);
    }
}

int main(int /*unused*/, char** argv)
{
    const std::string app_name(argv[0]);
    init_log(app_name + ".log");
    DEFER(shutdown_log());

    try
    {
        const auto threads_count = std::thread::hardware_concurrency();
        LOG_INFO("server initializing with {} threads", threads_count);

        io_context_pool pool(threads_count);

        boost::asio::io_context& acceptor_ctx = pool.get_io_context();

        const boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v6(), 1080);

        boost::asio::ip::tcp::acceptor acceptor(acceptor_ctx);
        acceptor.open(ep.protocol());
        acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor.bind(ep);
        acceptor.listen(boost::asio::socket_base::max_listen_connections);

        boost::asio::co_spawn(acceptor_ctx, listener(std::move(acceptor), pool), boost::asio::detached);

        pool.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("fatal exception {}", e.what());
        std::cerr << "exception " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
