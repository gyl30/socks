#ifndef REALITY_FALLBACK_EXECUTOR_H
#define REALITY_FALLBACK_EXECUTOR_H

#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "reality/policy/fallback_request.h"

namespace reality
{

class fallback_executor
{
   public:
    explicit fallback_executor(boost::asio::io_context& io_context, const relay::config& cfg);

    [[nodiscard]] boost::asio::awaitable<void> run(
        fallback_request& request, const std::string& host, uint16_t port, const char* reason, boost::system::error_code& ec) const;

   private:
    [[nodiscard]] boost::asio::awaitable<void> connect_target(boost::asio::ip::tcp::socket& upstream_socket,
                                                              const fallback_request& request,
                                                              const std::string& host,
                                                              uint16_t port,
                                                              boost::system::error_code& ec) const;

    [[nodiscard]] boost::asio::awaitable<void> write_initial_client_hello(boost::asio::ip::tcp::socket& upstream_socket,
                                                                          const fallback_request& request,
                                                                          const std::string& host,
                                                                          uint16_t port,
                                                                          const std::vector<uint8_t>& client_hello_record,
                                                                          boost::system::error_code& ec) const;

    boost::asio::io_context& io_context_;
    const relay::config& cfg_;
};

}    // namespace reality

#endif
