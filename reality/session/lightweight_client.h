#ifndef REALITY_LIGHTWEIGHT_CLIENT_H
#define REALITY_LIGHTWEIGHT_CLIENT_H

#include <string>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/system/detail/error_code.hpp>

namespace reality
{

struct reality_session;

struct lightweight_http_visit_options
{
    std::string host;
    std::uint32_t write_timeout_sec = 0;
    std::uint32_t read_timeout_sec = 0;
    std::uint32_t max_read_iterations = 8;
    std::size_t response_capture_limit = 16L * 1024;
    std::size_t response_sufficient_bytes = 512;
};

struct lightweight_http_visit_result
{
    bool saw_application_data = false;
    bool saw_alert = false;
    bool header_complete = false;
    std::size_t tx_plain_bytes = 0;
    std::size_t rx_plain_bytes = 0;
    std::string status_line;
    std::string error_stage;
};

[[nodiscard]] boost::asio::awaitable<lightweight_http_visit_result> run_lightweight_http_visit(boost::asio::ip::tcp::socket& socket,
                                                                                               reality_session session,
                                                                                               const lightweight_http_visit_options& options,
                                                                                               boost::system::error_code& ec);

}    // namespace reality

#endif
