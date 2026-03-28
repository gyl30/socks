#include <span>
#include <array>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "tls/core.h"
#include "timeout_io.h"
#include "reality/session/engine.h"
#include "reality/session/session.h"
#include "reality/session/lightweight_client.h"

namespace reality
{

namespace
{

std::string build_minimal_http_request(const std::string& host)
{
    std::string request;
    request.reserve(host.size() + 256);
    request.append("GET / HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    request.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n");
    request.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n");
    request.append("Accept-Language: en-US,en;q=0.9\r\n");
    request.append("Connection: close\r\n");
    request.append("\r\n");
    return request;
}

bool contains_http_header_terminator(const std::vector<std::uint8_t>& data)
{
    static constexpr std::array<std::uint8_t, 4> kHttpHeaderTerminator = {'\r', '\n', '\r', '\n'};
    return std::search(data.begin(), data.end(), kHttpHeaderTerminator.begin(), kHttpHeaderTerminator.end()) != data.end();
}

std::string extract_http_status_line(const std::vector<std::uint8_t>& data)
{
    static constexpr std::array<std::uint8_t, 2> kHttpCrlf = {'\r', '\n'};
    const auto status_end = std::search(data.begin(), data.end(), kHttpCrlf.begin(), kHttpCrlf.end());
    if (status_end == data.end())
    {
        return {};
    }
    std::string ret(data.begin(), status_end);
    return ret;
}

}    // namespace

boost::asio::awaitable<lightweight_http_visit_result> run_lightweight_http_visit(boost::asio::ip::tcp::socket& socket,
                                                                                 reality_record_context record_context,
                                                                                 const lightweight_http_visit_options& options,
                                                                                 boost::system::error_code& ec)
{
    ec.clear();
    lightweight_http_visit_result result;
    mux::reality_engine engine(std::move(record_context));

    const auto request_text = build_minimal_http_request(options.host);
    const std::vector<std::uint8_t> request_bytes(request_text.begin(), request_text.end());
    const auto ciphertext = engine.encrypt_record(request_bytes, ec);
    if (ec)
    {
        result.error_stage = "encrypt_request";
        co_return result;
    }

    const auto written = co_await mux::timeout_io::wait_write_with_timeout(
        socket, boost::asio::buffer(ciphertext.data(), ciphertext.size()), options.write_timeout_sec, ec);
    if (ec || written != ciphertext.size())
    {
        if (!ec)
        {
            ec = boost::asio::error::fault;
        }
        result.error_stage = "write_request";
        co_return result;
    }
    result.tx_plain_bytes = request_bytes.size();

    std::size_t captured_bytes = 0;
    bool response_complete = false;
    std::vector<std::uint8_t> response_capture;
    response_capture.reserve(std::min<std::size_t>(options.response_capture_limit, 2048));

    for (std::uint32_t attempt = 0; attempt < options.max_read_iterations && !response_complete; ++attempt)
    {
        const auto buf = engine.read_buffer(4096, ec);
        if (ec)
        {
            result.error_stage = "read_response";
            co_return result;
        }
        const auto n = co_await mux::timeout_io::wait_read_some_with_timeout(socket, buf, options.read_timeout_sec, ec);
        if (ec)
        {
            if ((ec == boost::asio::error::timed_out || ec == boost::asio::error::eof) && result.saw_application_data)
            {
                ec.clear();
                break;
            }
            result.error_stage = "read_response";
            co_return result;
        }
        if (n == 0)
        {
            break;
        }

        engine.commit_read(n);
        boost::system::error_code process_ec;
        while (true)
        {
            const auto record = engine.decrypt_record(process_ec);
            if (process_ec)
            {
                break;
            }
            if (!record.has_value())
            {
                break;
            }

            if (record->content_type == ::tls::kContentTypeApplicationData)
            {
                result.saw_application_data = true;
                result.rx_plain_bytes += record->payload.size();

                const auto current_size = response_capture.size();
                const auto remaining =
                    current_size < options.response_capture_limit ? options.response_capture_limit - current_size : static_cast<std::size_t>(0);
                const auto copy_len = std::min(remaining, record->payload.size());
                response_capture.insert(
                    response_capture.end(), record->payload.begin(), record->payload.begin() + static_cast<std::ptrdiff_t>(copy_len));

                captured_bytes += record->payload.size();
                result.header_complete = result.header_complete || contains_http_header_terminator(response_capture);
                if (result.header_complete && (captured_bytes >= options.response_sufficient_bytes || response_capture.size() >= 2048))
                {
                    response_complete = true;
                }
                if (captured_bytes >= options.response_capture_limit)
                {
                    response_complete = true;
                }
                continue;
            }

            if (record->content_type == ::tls::kContentTypeAlert)
            {
                result.saw_alert = true;
                break;
            }
        }
        if (process_ec)
        {
            ec = process_ec;
            result.error_stage = "process_response";
            co_return result;
        }
    }

    result.status_line = extract_http_status_line(response_capture);
    co_return result;
}

}    // namespace reality
