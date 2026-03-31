#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <optional>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/awaitable.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "net_utils.h"
#include "context_pool.h"
#include "reality/types.h"
#include "mux_connection.h"
#include "client_tunnel_pool.h"
#include "tls/handshake_message.h"
#include "reality/session/session.h"
#include "reality/handshake/fingerprint.h"
#include "reality/session/lightweight_client.h"
#include "reality/handshake/client_handshaker.h"

namespace mux
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

    struct fp_entry
    {
        const char* name;
        reality::fingerprint_type type;
    };

    static const fp_entry kFps[] = {
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

    for (const auto& entry : kFps)
    {
        if (normalized_name == entry.name)
        {
            return entry.type;
        }
    }
    return kFps[0].type;
}

void prepare_socket_for_connect(boost::asio::ip::tcp::socket& socket,
                                const boost::asio::ip::tcp::endpoint& endpoint,
                                uint32_t mark,
                                boost::system::error_code& ec)
{
    if (socket.is_open())
    {
        ec = socket.close(ec);
    }
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        return;
    }
    if (mark != 0)
    {
        net::set_socket_mark(socket.native_handle(), mark, ec);
        if (ec)
        {
            LOG_WARN("set mark failed target {}:{} error {}", endpoint.address().to_string(), endpoint.port(), ec.message());
            boost::system::error_code close_ec;
            close_ec = socket.close(close_ec);
            (void)close_ec;
            return;
        }
    }
}

}    // namespace

static connect_options build_connect_options(const config& cfg)
{
    connect_options options;
    options.sni = cfg.reality.sni;
    options.remote_host = cfg.outbound.host;
    options.remote_port = std::to_string(cfg.outbound.port);
    options.max_handshake_records = cfg.limits.max_handshake_records;
    options.connect_mark = cfg.tproxy.enabled ? cfg.tproxy.mark : 0U;
    boost::algorithm::unhex(cfg.reality.public_key, std::back_inserter(options.server_pub_key));
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(options.short_id_bytes));
    options.fingerprint_type = parse_fingerprint_type(cfg.reality.fingerprint);
    return options;
}

client_tunnel_pool::client_tunnel_pool(io_context_pool& pool, const config& cfg) : cfg_(cfg), pool_(pool), tunnel_pool_(cfg.limits.max_connections) {}

void client_tunnel_pool::start()
{
    LOG_INFO("client pool starting target {} port {} with {} connections", cfg_.outbound.host, cfg_.outbound.port, cfg_.limits.max_connections);
    auto self = shared_from_this();
    for (uint32_t i = 0; i < cfg_.limits.max_connections; ++i)
    {
        auto& worker = pool_.get_io_worker();
        worker.group.spawn([self, i, worker = &worker]() -> boost::asio::awaitable<void> { co_await self->connect_remote_loop(i, *worker); });
    }
}

void client_tunnel_pool::stop()
{
    if (stop_.exchange(true))
    {
        return;
    }

    std::vector<std::shared_ptr<mux_connection>> tunnels;
    {
        const std::scoped_lock lock(tunnel_mutex_);
        for (auto&& tunnel : tunnel_pool_)
        {
            tunnels.push_back(tunnel);
            tunnel.reset();
        }
    }

    for (const auto& tunnel : tunnels)
    {
        if (tunnel != nullptr)
        {
            tunnel->stop();
        }
    }
}

std::shared_ptr<mux_connection> client_tunnel_pool::select_tunnel()
{
    const std::scoped_lock<std::mutex> lock(tunnel_mutex_);
    if (tunnel_pool_.empty())
    {
        return nullptr;
    }

    const auto pool_size = tunnel_pool_.size();
    const auto start_index = static_cast<std::size_t>(next_tunnel_index_.fetch_add(1, std::memory_order_relaxed) % pool_size);
    for (std::size_t i = 0; i < pool_size; ++i)
    {
        const auto slot = (start_index + i) % pool_size;
        const auto tunnel = tunnel_pool_[slot];
        if (tunnel == nullptr)
        {
            continue;
        }
        return tunnel;
    }

    return nullptr;
}

static boost::asio::awaitable<void> run_real_certificate_fallback(const config& cfg,
                                                                  const auto& options,
                                                                  boost::asio::ip::tcp::socket& socket,
                                                                  const reality::client_handshake_result& handshake_ret,
                                                                  uint32_t conn_id)
{
    if (!handshake_ret.negotiated.negotiated_alpn.empty() && handshake_ret.negotiated.negotiated_alpn != "http/1.1")
    {
        LOG_INFO("event {} conn_id {} sni {} stage skip_request negotiated_alpn {}",
                 log_event::kFallback,
                 conn_id,
                 options.sni,
                 handshake_ret.negotiated.negotiated_alpn);
        co_return;
    }

    boost::system::error_code ec;
    auto record_context = reality::build_reality_record_context(handshake_ret, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} sni {} stage build_session error {}", log_event::kFallback, conn_id, options.sni, ec.message());
        co_return;
    }

    reality::lightweight_http_visit_options visit_options;
    visit_options.host = options.sni;
    visit_options.write_timeout_sec = cfg.timeout.write;
    visit_options.read_timeout_sec = cfg.timeout.read;

    const auto visit_result = co_await reality::run_lightweight_http_visit(socket, std::move(record_context), visit_options, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} sni {} stage {} error {}",
                 log_event::kFallback,
                 conn_id,
                 options.sni,
                 visit_result.error_stage,
                 ec.message());
        co_return;
    }

    const auto tx_bytes = visit_result.tx_plain_bytes;
    const auto rx_bytes = visit_result.rx_plain_bytes;

    if (visit_result.saw_application_data)
    {
        LOG_INFO("event {} conn_id {} sni {} stage lightweight_visit_complete status \"{}\" tx_plain {}B rx_plain {}B header_complete {} alert {}",
                 log_event::kFallback,
                 conn_id,
                 options.sni,
                 visit_result.status_line.empty() ? "unknown" : visit_result.status_line,
                 tx_bytes,
                 rx_bytes,
                 visit_result.header_complete,
                 visit_result.saw_alert);
    }
    else
    {
        LOG_WARN("event {} conn_id {} sni {} stage lightweight_visit_no_response tx_plain {}B alert {}",
                 log_event::kFallback,
                 conn_id,
                 options.sni,
                 tx_bytes,
                 visit_result.saw_alert);
    }
    co_return;
}

static boost::asio::awaitable<reality::client_handshake_result> perform_reality_handshake_with_timeout(
    const config& cfg, const auto& options, boost::asio::ip::tcp::socket& socket, uint32_t conn_id, boost::system::error_code& ec)
{
    const reality::client_handshaker handshaker(
        cfg, options.sni, options.server_pub_key, options.short_id_bytes, options.fingerprint_type, options.max_handshake_records);
    auto handshake_res = co_await handshaker.run(socket, conn_id, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} sni {} stage handshake target {}:{} error {}",
                  log_event::kHandshake,
                  conn_id,
                  options.sni,
                  options.remote_host,
                  options.remote_port,
                  ec.message());
    }
    co_return handshake_res;
}

static boost::asio::awaitable<void> wait_retry(uint32_t index, io_worker& worker, const std::chrono::steady_clock::duration delay)
{
    const auto wait_ec = co_await net::wait_for(worker.io_context, delay);
    if (wait_ec == boost::asio::error::operation_aborted)
    {
        co_return;
    }
    if (wait_ec)
    {
        LOG_ERROR("wait retry {} error {}", index, wait_ec.message());
    }
}

static boost::asio::awaitable<void> tcp_connect_remote(
    const config& cfg, const auto& options, boost::asio::ip::tcp::socket& socket, uint32_t conn_id, boost::system::error_code& ec)
{
    const auto timeout_sec = cfg.timeout.connect;
    boost::asio::ip::tcp::resolver resolver(socket.get_executor());
    const auto resolve_endpoints =
        co_await net::wait_resolve_with_timeout(resolver, options.remote_host, options.remote_port, timeout_sec, ec);
    if (ec)
    {
        co_return;
    }

    for (const auto& entry : resolve_endpoints)
    {
        const auto endpoint = entry.endpoint();
        prepare_socket_for_connect(socket, endpoint, options.connect_mark, ec);
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
        LOG_ERROR("event {} conn_id {} stage connect target {}:{} timeout {}s",
                  log_event::kConnInit,
                  conn_id,
                  options.remote_host,
                  options.remote_port,
                  timeout_sec);
    }
    else
    {
        LOG_ERROR("event {} conn_id {} stage connect target {}:{} error {}",
                  log_event::kConnInit,
                  conn_id,
                  options.remote_host,
                  options.remote_port,
                  ec.message());
    }
}

static boost::asio::awaitable<std::shared_ptr<mux_connection>> connect_remote_once(const config& cfg,
                                                                                   const auto& options,
                                                                                   uint32_t index,
                                                                                   io_worker& worker,
                                                                                   uint32_t cid,
                                                                                   boost::system::error_code& ec)
{
    LOG_INFO("event {} conn_id {} init conn {}/{} to {} {}",
             log_event::kConnInit,
             cid,
             index + 1,
             cfg.limits.max_connections,
             options.remote_host,
             options.remote_port);

    boost::asio::ip::tcp::socket socket(worker.io_context);
    co_await tcp_connect_remote(cfg, options, socket, cid, ec);
    if (ec)
    {
        co_return nullptr;
    }

    auto handshake_ret = co_await perform_reality_handshake_with_timeout(cfg, options, socket, cid, ec);
    if (ec)
    {
        co_return nullptr;
    }

    LOG_INFO("event {} conn_id {} sni {} handshake success cipher 0x{:04x} key share group 0x{:04x} {}",
             log_event::kHandshake,
             cid,
             options.sni,
             handshake_ret.negotiated.cipher_suite,
             handshake_ret.negotiated.key_share_group,
             tls::named_group_name(handshake_ret.negotiated.key_share_group));
    if (handshake_ret.auth_mode == reality::client_auth_mode::kRealCertificateFallback)
    {
        LOG_WARN("event {} conn_id {} received real certificate fallback run lightweight visit", log_event::kHandshake, cid);
        co_await run_real_certificate_fallback(cfg, options, socket, handshake_ret, cid);
        boost::system::error_code close_ec;
        close_ec = socket.close(close_ec);
        if (close_ec)
        {
            LOG_WARN("event {} conn_id {} close failed {}", log_event::kConnClose, cid, close_ec.message());
        }
        co_return nullptr;
    }

    auto record_context = reality::build_reality_record_context(handshake_ret, ec);
    if (ec)
    {
        LOG_ERROR("build client reality session failed {}", ec.message());
        co_return nullptr;
    }

    co_return std::make_shared<mux_connection>(std::move(socket), worker, std::move(record_context), cfg, cid);
}

boost::asio::awaitable<void> client_tunnel_pool::connect_remote_loop(uint32_t index, io_worker& worker)
{
    const connect_options options = build_connect_options(cfg_);
    boost::system::error_code ec;
    while (!stop_)
    {
        const uint32_t cid = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
        auto tunnel = co_await connect_remote_once(cfg_, options, index, worker, cid, ec);
        if (ec == boost::asio::error::operation_aborted)
        {
            break;
        }
        if (stop_)
        {
            break;
        }
        if (tunnel == nullptr)
        {
            co_await wait_retry(index, worker, std::chrono::seconds(constants::mux::kReconnectRetryIntervalSec));
            continue;
        }

        tunnel->start();
        {
            const std::scoped_lock<std::mutex> lock(tunnel_mutex_);
            tunnel_pool_[index] = tunnel;
        }

        co_await tunnel->async_wait_stopped();

        {
            const std::scoped_lock<std::mutex> lock(tunnel_mutex_);
            if (tunnel_pool_[index] == tunnel)
            {
                tunnel_pool_[index].reset();
            }
        }
        if (stop_)
        {
            break;
        }

        co_await wait_retry(index, worker, std::chrono::seconds(constants::mux::kReconnectRetryIntervalSec));
    }

    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

}    // namespace mux
