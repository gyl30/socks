#include "trace_web_server.h"

#include <algorithm>
#include <cstdlib>
#include <string_view>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "log.h"
#include "constants.h"
#include "trace_web_handler.h"

namespace relay
{

namespace
{

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

[[nodiscard]] std::pair<std::string_view, std::string_view> split_target(std::string_view target)
{
    const auto question = target.find('?');
    if (question == std::string_view::npos)
    {
        return {target, std::string_view{}};
    }
    return {target.substr(0, question), target.substr(question + 1)};
}

}    // namespace

trace_web_server::trace_web_server(io_context_pool& pool, const config& cfg)
    : cfg_(cfg), worker_(pool.get_io_worker()), acceptor_(worker_.io_context)
{
}

void trace_web_server::start()
{
    if (!cfg_.web.enabled)
    {
        return;
    }

    boost::system::error_code ec;
    const auto listen_addr = boost::asio::ip::make_address(cfg_.web.host, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen host {} parse failed {}", log_event::kConnInit, cfg_.web.host, ec.message());
        std::exit(EXIT_FAILURE);
    }

    const tcp::endpoint endpoint{listen_addr, cfg_.web.port};
    ec = acceptor_.open(endpoint.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} open failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} reuse_address failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    if (listen_addr.is_v6() && listen_addr.to_v6().is_unspecified())
    {
        ec = acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR("{} stage start web listen {}:{} v6_only failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
            std::exit(EXIT_FAILURE);
        }
    }
    ec = acceptor_.bind(endpoint, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} bind failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} listen failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("{} stage start web listen {}:{} started", log_event::kConnInit, cfg_.web.host, cfg_.web.port);
    worker_.group.spawn([self = shared_from_this()]() -> boost::asio::awaitable<void> { co_await self->accept_loop(); });
}

void trace_web_server::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::system::error_code ec;
    ec = acceptor_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_ERROR("{} stage stop web listen {}:{} close failed {}", log_event::kConnClose, cfg_.web.host, cfg_.web.port, ec.message());
    }
    else
    {
        LOG_INFO("{} stage stop web listen {}:{} stopped", log_event::kConnClose, cfg_.web.host, cfg_.web.port);
    }
}

boost::asio::awaitable<void> trace_web_server::accept_loop()
{
    boost::system::error_code ec;
    while (!stopping_.load(std::memory_order_relaxed))
    {
        tcp::socket socket(worker_.io_context);
        co_await acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            break;
        }
        if (ec)
        {
            LOG_WARN("{} stage accept web listen {}:{} accept failed {}",
                     log_event::kConnInit,
                     cfg_.web.host,
                     cfg_.web.port,
                     ec.message());
            continue;
        }

        worker_.group.spawn([self = shared_from_this(), socket = std::move(socket)]() mutable -> boost::asio::awaitable<void>
                            { co_await self->serve_session(std::move(socket)); });
    }
    co_return;
}

boost::asio::awaitable<void> trace_web_server::serve_session(boost::asio::ip::tcp::socket socket)
{
    beast::tcp_stream stream(std::move(socket));
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    boost::system::error_code ec;
    co_await http::async_read(stream, buffer, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        if (ec != boost::asio::error::operation_aborted && ec != http::error::end_of_stream)
        {
            LOG_WARN("{} stage web request read failed {}", log_event::kConnInit, ec.message());
        }
        co_return;
    }

    web_reply reply;
    if (req.method() != http::verb::get)
    {
        reply.status = http::status::method_not_allowed;
        reply.body = make_trace_web_error_body("method_not_allowed");
        reply.allow_get_only = true;
    }
    else
    {
        const std::string_view target{req.target().data(), req.target().size()};
        const auto [path, query] = split_target(target);
        reply = dispatch_trace_request(path, query);
    }

    http::response<http::string_body> res{reply.status, req.version()};
    res.set(http::field::server, "socks-trace-web");
    res.set(http::field::content_type, reply.content_type);
    if (reply.allow_get_only)
    {
        res.set(http::field::allow, "GET");
    }
    res.keep_alive(false);
    res.body() = std::move(reply.body);
    res.prepare_payload();
    co_await http::async_write(stream, res, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec && ec != boost::asio::error::operation_aborted)
    {
        LOG_WARN("{} stage web response write failed {}", log_event::kConnInit, ec.message());
    }
    co_return;
}

}    // namespace relay
