#include <span>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <optional>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/algorithm/hex.hpp>

#include "log.h"
#include "config.h"
#include "tls/core.h"
#include "constants.h"
#include "net_utils.h"
#include "reality/types.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/client_handshaker.h"

namespace relay
{

namespace
{

struct connect_options
{
    std::string sni;
    std::string remote_host;
    std::string remote_port;
    std::vector<uint8_t> server_pub_key;
    std::vector<uint8_t> short_id_bytes;
    std::optional<reality::fingerprint_type> fingerprint_type;
    uint32_t max_handshake_records = constants::reality_limits::kMaxHandshakeRecords;
    uint32_t connect_mark = 0;
};

std::string normalize_fingerprint_name(const std::string& name)
{
    std::string normalized_name;
    normalized_name.reserve(name.size());
    for (const char ch : name)
    {
        if (ch == '-' || ch == ' ')
        {
            normalized_name.push_back('_');
            continue;
        }
        normalized_name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized_name;
}

std::optional<reality::fingerprint_type> parse_fingerprint_type(const std::string& name)
{
    const auto normalized_name = normalize_fingerprint_name(name);
    if (normalized_name.empty() || normalized_name == "random")
    {
        return std::nullopt;
    }

    struct entry
    {
        const char* name;
        reality::fingerprint_type type;
    };

    static const entry kEntries[] = {
        {.name = "chrome", .type = reality::fingerprint_type::kChrome120},
        {.name = "chrome_120", .type = reality::fingerprint_type::kChrome120},
        {.name = "chrome_mlkem", .type = reality::fingerprint_type::kChrome120Mlkem768},
        {.name = "chrome_mlkem768", .type = reality::fingerprint_type::kChrome120Mlkem768},
        {.name = "chrome_hybrid", .type = reality::fingerprint_type::kChrome120Mlkem768},
        {.name = "firefox", .type = reality::fingerprint_type::kFirefox120},
        {.name = "firefox_120", .type = reality::fingerprint_type::kFirefox120},
        {.name = "ios", .type = reality::fingerprint_type::kIOS14},
        {.name = "ios_14", .type = reality::fingerprint_type::kIOS14},
        {.name = "android", .type = reality::fingerprint_type::kAndroid11OkHttp},
        {.name = "android_11_okhttp", .type = reality::fingerprint_type::kAndroid11OkHttp},
    };

    for (const auto& entry : kEntries)
    {
        if (normalized_name == entry.name)
        {
            return entry.type;
        }
    }
    return kEntries[0].type;
}

connect_options build_connect_options(const config& cfg)
{
    connect_options options;
    options.sni = cfg.reality.sni;
    options.remote_host = cfg.outbound.host;
    options.remote_port = std::to_string(cfg.outbound.port);
    options.max_handshake_records = cfg.reality.max_handshake_records;
    options.connect_mark = cfg.tproxy.enabled ? cfg.tproxy.mark : 0U;
    boost::algorithm::unhex(cfg.reality.public_key, std::back_inserter(options.server_pub_key));
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(options.short_id_bytes));
    options.fingerprint_type = parse_fingerprint_type(cfg.reality.fingerprint);
    return options;
}

void prepare_socket_for_connect(boost::asio::ip::tcp::socket& socket,
                                const boost::asio::ip::tcp::endpoint& endpoint,
                                uint32_t conn_id,
                                uint32_t mark,
                                boost::system::error_code& ec)
{
    if (socket.is_open())
    {
        ec = socket.close(ec);
        if (ec)
        {
            LOG_WARN("{} conn {} stage recycle_socket target {}:{} error {}",
                     log_event::kConnInit,
                     conn_id,
                     endpoint.address().to_string(),
                     endpoint.port(),
                     ec.message());
            return;
        }
    }
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        LOG_WARN("{} conn {} stage open_socket target {}:{} error {}",
                 log_event::kConnInit,
                 conn_id,
                 endpoint.address().to_string(),
                 endpoint.port(),
                 ec.message());
        return;
    }
    if (mark != 0)
    {
        net::set_socket_mark(socket.native_handle(), mark, ec);
        if (ec)
        {
            LOG_WARN("{} conn {} stage set_mark target {}:{} error {}",
                     log_event::kConnInit,
                     conn_id,
                     endpoint.address().to_string(),
                     endpoint.port(),
                     ec.message());
            boost::system::error_code close_ec;
            close_ec = socket.close(close_ec);
            (void)close_ec;
            return;
        }
    }
}

boost::asio::awaitable<void> tcp_connect_remote(
    boost::asio::ip::tcp::socket& socket, const config& cfg, const connect_options& options, uint32_t conn_id, boost::system::error_code& ec)
{
    const auto timeout_sec = cfg.timeout.connect;
    boost::asio::ip::tcp::resolver resolver(socket.get_executor());
    const auto resolve_endpoints = co_await net::wait_resolve_with_timeout(resolver, options.remote_host, options.remote_port, timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} stage resolve target {}:{} error {}",
                  log_event::kConnInit,
                  conn_id,
                  options.remote_host,
                  options.remote_port,
                  ec.message());
        co_return;
    }

    for (const auto& entry : resolve_endpoints)
    {
        const auto endpoint = entry.endpoint();
        prepare_socket_for_connect(socket, endpoint, conn_id, options.connect_mark, ec);
        if (ec)
        {
            continue;
        }
        co_await net::wait_connect_with_timeout(socket, endpoint, timeout_sec, ec);
        if (!ec)
        {
            co_return;
        }
    }

    if (ec == boost::asio::error::timed_out)
    {
        LOG_ERROR("{} conn {} stage connect target {}:{} timeout {}s",
                  log_event::kConnInit,
                  conn_id,
                  options.remote_host,
                  options.remote_port,
                  timeout_sec);
    }
    else
    {
        LOG_ERROR("{} conn {} stage connect target {}:{} error {}",
                  log_event::kConnInit,
                  conn_id,
                  options.remote_host,
                  options.remote_port,
                  ec.message());
    }
}

boost::asio::awaitable<reality::client_handshake_result> perform_reality_handshake(
    boost::asio::ip::tcp::socket& socket, const config& cfg, const connect_options& options, uint32_t conn_id, boost::system::error_code& ec)
{
    const reality::client_handshaker handshaker(
        cfg, options.sni, options.server_pub_key, options.short_id_bytes, options.fingerprint_type, options.max_handshake_records);
    auto handshake_res = co_await handshaker.run(socket, conn_id, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} stage handshake target {}:{} error {}",
                  log_event::kHandshake,
                  conn_id,
                  options.sni,
                  options.remote_host,
                  options.remote_port,
                  ec.message());
    }
    co_return handshake_res;
}

}    // namespace

proxy_reality_connection::proxy_reality_connection(boost::asio::ip::tcp::socket socket,
                                                   reality::reality_record_context record_context,
                                                   const config& cfg,
                                                   const uint32_t conn_id)
    : cfg_(cfg), conn_id_(conn_id), socket_(std::move(socket)), reality_engine_(std::move(record_context))
{
    boost::system::error_code ec;
    const auto local_endpoint = socket_.local_endpoint(ec);
    if (!ec)
    {
        local_host_ = local_endpoint.address().to_string();
        local_port_ = local_endpoint.port();
    }

    ec.clear();
    const auto remote_endpoint = socket_.remote_endpoint(ec);
    if (!ec)
    {
        remote_host_ = remote_endpoint.address().to_string();
        remote_port_ = remote_endpoint.port();
    }
}

boost::asio::awaitable<std::shared_ptr<proxy_reality_connection>> proxy_reality_connection::connect(const boost::asio::any_io_executor& executor,
                                                                                                    const config& cfg,
                                                                                                    const uint32_t conn_id,
                                                                                                    boost::system::error_code& ec)
{
    const auto options = build_connect_options(cfg);
    boost::asio::ip::tcp::socket socket(executor);
    co_await tcp_connect_remote(socket, cfg, options, conn_id, ec);
    if (ec)
    {
        co_return nullptr;
    }

    auto handshake_result = co_await perform_reality_handshake(socket, cfg, options, conn_id, ec);
    if (ec)
    {
        co_return nullptr;
    }
    if (handshake_result.auth_mode == reality::client_auth_mode::kRealCertificateFallback)
    {
        LOG_WARN("{} conn {} sni {} target {}:{} peer is not a reality endpoint",
                 log_event::kHandshake,
                 conn_id,
                 options.sni,
                 options.remote_host,
                 options.remote_port);
        ec = boost::asio::error::operation_not_supported;
        boost::system::error_code close_ec;
        close_ec = socket.close(close_ec);
        (void)close_ec;
        co_return nullptr;
    }

    auto record_context = reality::build_reality_record_context(handshake_result, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} stage build_record_context target {}:{} error {}",
                  log_event::kHandshake,
                  conn_id,
                  options.sni,
                  options.remote_host,
                  options.remote_port,
                  ec.message());
        co_return nullptr;
    }

    co_return std::make_shared<proxy_reality_connection>(std::move(socket), std::move(record_context), cfg, conn_id);
}

boost::asio::awaitable<void> proxy_reality_connection::write(const std::span<const uint8_t> data, boost::system::error_code& ec)
{
    if (data.empty())
    {
        co_return;
    }

    const std::vector<uint8_t> plaintext(data.begin(), data.end());
    const auto ciphertext = reality_engine_.encrypt_record(plaintext, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} stage encrypt_record error {}",
                 log_event::kDataSend,
                 conn_id_,
                 local_host_,
                 local_port_,
                 remote_host_,
                 remote_port_,
                 ec.message());
        co_return;
    }
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(ciphertext.data(), ciphertext.size()), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} stage write_ciphertext error {}",
                 log_event::kDataSend,
                 conn_id_,
                 local_host_,
                 local_port_,
                 remote_host_,
                 remote_port_,
                 ec.message());
    }
}

boost::asio::awaitable<void> proxy_reality_connection::write_packet(const std::vector<uint8_t>& packet, boost::system::error_code& ec)
{
    if (packet.size() > proxy::kMaxPacketSize)
    {
        ec = boost::asio::error::message_size;
        co_return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(4 + packet.size());
    const auto size = static_cast<uint32_t>(packet.size());
    framed.push_back(static_cast<uint8_t>((size >> 24) & 0xFFU));
    framed.push_back(static_cast<uint8_t>((size >> 16) & 0xFFU));
    framed.push_back(static_cast<uint8_t>((size >> 8) & 0xFFU));
    framed.push_back(static_cast<uint8_t>(size & 0xFFU));
    framed.insert(framed.end(), packet.begin(), packet.end());
    co_await write(framed, ec);
}

std::size_t proxy_reality_connection::consume_plaintext(const std::span<uint8_t> output)
{
    const auto size = std::min(output.size(), pending_plaintext_.size());
    std::copy_n(pending_plaintext_.begin(), static_cast<std::ptrdiff_t>(size), output.begin());
    pending_plaintext_.erase(pending_plaintext_.begin(), pending_plaintext_.begin() + static_cast<std::ptrdiff_t>(size));
    return size;
}

boost::asio::awaitable<bool> proxy_reality_connection::ensure_plaintext_available(const uint32_t timeout_sec, boost::system::error_code& ec)
{
    while (pending_plaintext_.empty())
    {
        auto record = reality_engine_.decrypt_record(ec);
        if (ec)
        {
            LOG_WARN("{} conn {} local {}:{} remote {}:{} stage decrypt_record error {}",
                     log_event::kDataRecv,
                     conn_id_,
                     local_host_,
                     local_port_,
                     remote_host_,
                     remote_port_,
                     ec.message());
            co_return false;
        }
        if (record.has_value())
        {
            if (record->content_type != tls::kContentTypeApplicationData)
            {
                ec = boost::asio::error::invalid_argument;
                LOG_WARN("{} conn {} local {}:{} remote {}:{} stage unexpected_record_type {}",
                         log_event::kDataRecv,
                         conn_id_,
                         local_host_,
                         local_port_,
                         remote_host_,
                         remote_port_,
                         record->content_type);
                co_return false;
            }
            pending_plaintext_.insert(pending_plaintext_.end(), record->payload.begin(), record->payload.end());
            if (!pending_plaintext_.empty())
            {
                co_return true;
            }
            continue;
        }

        auto read_buffer = reality_engine_.read_buffer(constants::net::kBufferSize, ec);
        if (ec)
        {
            co_return false;
        }
        const auto bytes_read = co_await net::wait_read_some_with_timeout(socket_, read_buffer, timeout_sec, ec);
        if (ec)
        {
            if (ec != boost::asio::error::eof)
            {
                LOG_WARN("{} conn {} local {}:{} remote {}:{} stage read_ciphertext error {}",
                         log_event::kDataRecv,
                         conn_id_,
                         local_host_,
                         local_port_,
                         remote_host_,
                         remote_port_,
                         ec.message());
            }
            co_return false;
        }
        if (bytes_read == 0)
        {
            ec = boost::asio::error::eof;
            co_return false;
        }
        reality_engine_.commit_read(bytes_read);
    }
    co_return true;
}

boost::asio::awaitable<std::size_t> proxy_reality_connection::read_some(std::vector<uint8_t>& buffer,
                                                                        const uint32_t timeout_sec,
                                                                        boost::system::error_code& ec)
{
    if (buffer.empty())
    {
        buffer.resize(constants::net::kBufferSize);
    }
    if (!(co_await ensure_plaintext_available(timeout_sec, ec)))
    {
        co_return 0;
    }
    const auto n = consume_plaintext(std::span<uint8_t>(buffer.data(), buffer.size()));
    co_return n;
}

boost::asio::awaitable<bool> proxy_reality_connection::read_exact(std::vector<uint8_t>& out,
                                                                  const std::size_t size,
                                                                  const uint32_t timeout_sec,
                                                                  boost::system::error_code& ec)
{
    out.clear();
    out.reserve(size);
    while (out.size() < size)
    {
        if (!(co_await ensure_plaintext_available(timeout_sec, ec)))
        {
            co_return false;
        }
        const auto remaining = size - out.size();
        const auto chunk_size = std::min(remaining, pending_plaintext_.size());
        out.insert(out.end(), pending_plaintext_.begin(), pending_plaintext_.begin() + static_cast<std::ptrdiff_t>(chunk_size));
        pending_plaintext_.erase(pending_plaintext_.begin(), pending_plaintext_.begin() + static_cast<std::ptrdiff_t>(chunk_size));
    }
    co_return true;
}

boost::asio::awaitable<std::vector<uint8_t>> proxy_reality_connection::read_packet(const uint32_t timeout_sec, boost::system::error_code& ec)
{
    std::vector<uint8_t> header;
    if (!(co_await read_exact(header, 4, timeout_sec, ec)))
    {
        co_return std::vector<uint8_t>{};
    }

    const auto packet_size = (static_cast<uint32_t>(header[0]) << 24U) | (static_cast<uint32_t>(header[1]) << 16U) |
                             (static_cast<uint32_t>(header[2]) << 8U) | static_cast<uint32_t>(header[3]);
    if (packet_size > proxy::kMaxPacketSize)
    {
        ec = boost::asio::error::message_size;
        LOG_WARN("{} conn {} local {}:{} remote {}:{} stage read_packet packet_size {} max {}",
                 log_event::kDataRecv,
                 conn_id_,
                 local_host_,
                 local_port_,
                 remote_host_,
                 remote_port_,
                 packet_size,
                 proxy::kMaxPacketSize);
        co_return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> packet;
    if (!(co_await read_exact(packet, packet_size, timeout_sec, ec)))
    {
        co_return std::vector<uint8_t>{};
    }
    co_return packet;
}

boost::asio::awaitable<void> proxy_reality_connection::shutdown_send(boost::system::error_code& ec)
{
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec.clear();
    }
    co_return;
}

void proxy_reality_connection::close(boost::system::error_code& ec)
{
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec.clear();
    }

    boost::system::error_code close_ec;
    close_ec = socket_.close(close_ec);
    if (!ec)
    {
        ec = close_ec;
    }
}

}    // namespace relay
