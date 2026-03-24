#ifndef REALITY_FALLBACK_EXECUTOR_H
#define REALITY_FALLBACK_EXECUTOR_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "log_context.h"

namespace mux
{

struct config;

}    // namespace mux

namespace reality
{

struct fallback_request
{
    boost::asio::ip::tcp::socket* client_socket = nullptr;
    mux::connection_context ctx;
    std::vector<std::uint8_t> client_hello_record;
};

class fallback_executor
{
   public:
    struct options
    {
        std::size_t relay_buffer_size = 16 * 1024;
    };

    struct dependencies
    {
        boost::asio::io_context& io_context;
        const mux::config& cfg;
        options opts{};
    };

    explicit fallback_executor(dependencies deps);

    [[nodiscard]] boost::asio::awaitable<void> run(fallback_request& request,
                                                   const std::string& host,
                                                   std::uint16_t port,
                                                   const char* reason,
                                                   boost::system::error_code& ec) const;

   private:
    [[nodiscard]] boost::asio::awaitable<void> connect_target(boost::asio::ip::tcp::socket& upstream_socket,
                                                              const mux::connection_context& ctx,
                                                              const std::string& host,
                                                              std::uint16_t port,
                                                              boost::system::error_code& ec) const;

    [[nodiscard]] boost::asio::awaitable<void> write_initial_client_hello(boost::asio::ip::tcp::socket& upstream_socket,
                                                                          const mux::connection_context& ctx,
                                                                          const std::string& host,
                                                                          std::uint16_t port,
                                                                          const std::vector<std::uint8_t>& client_hello_record,
                                                                          boost::system::error_code& ec) const;

    [[nodiscard]] boost::asio::awaitable<void> relay_data(boost::asio::ip::tcp::socket& src,
                                                          boost::asio::ip::tcp::socket& dst,
                                                          const mux::connection_context& ctx,
                                                          const char* direction) const;

    [[nodiscard]] boost::asio::awaitable<void> relay_bidirectional(boost::asio::ip::tcp::socket& client_socket,
                                                                   boost::asio::ip::tcp::socket& upstream_socket,
                                                                   const mux::connection_context& ctx) const;

    boost::asio::io_context& io_context_;
    const mux::config& cfg_;
    options options_{};
};

}    // namespace reality

#endif
