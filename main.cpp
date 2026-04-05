#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "net_utils.h"
#if SOCKS_HAS_TUN
#include "tun_client.h"
#endif
#include "scoped_exit.h"
#include "context_pool.h"
#include "socks_client.h"
#include "remote_server.h"
#if SOCKS_HAS_TPROXY
#include "tproxy_client.h"
#endif
#include "tls/crypto_util.h"
#include "client_tunnel_pool.h"
namespace
{

struct runtime_services
{
    std::shared_ptr<mux::remote_server> server = nullptr;
    std::shared_ptr<mux::client_tunnel_pool> tunnel_pool = nullptr;
    std::shared_ptr<mux::socks_client> socks = nullptr;
#if SOCKS_HAS_TUN
    std::shared_ptr<mux::tun_client> tun = nullptr;
#endif
#if SOCKS_HAS_TPROXY
    std::shared_ptr<mux::tproxy_client> tproxy = nullptr;
#endif
};

void print_usage(std::string_view prog)
{
    std::cout << "Usage:\n"
              << prog << " -c <config>  Run with configuration file\n"
              << prog << " x25519       Generate key pair for kX25519 key exchange\n"
              << prog << " probe-connect <host> <port> [timeout]  Probe a TCP connect from this binary\n"
              << prog << " probe-connect-thread <host> <port> [timeout]  Probe a TCP connect from a worker thread\n"
              << prog << " config       Dump default configuration\n";
}

void dump_x25519()
{
    uint8_t public_key[32];
    uint8_t private_key[32];
    if (!tls::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        std::fputs("failed to generate keypair\n", stdout);
        return;
    }
    const std::vector<uint8_t> vec_private_key(private_key, private_key + 32);
    const std::vector<uint8_t> vec_public_key(public_key, public_key + 32);
    const std::string private_key_hex = tls::crypto_util::bytes_to_hex(vec_private_key);
    const std::string public_key_hex = tls::crypto_util::bytes_to_hex(vec_public_key);
    std::cout << "private key: " << private_key_hex << '\n' << "public key:  " << public_key_hex << '\n';
}

boost::asio::awaitable<int> run_probe_connect_async(std::string host, uint16_t port, uint32_t timeout_sec)
{
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::ip::tcp::socket socket(executor);
    boost::system::error_code ec;

    const auto addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        std::cout << "parse_ec=" << ec.value() << " msg=" << ec.message() << '\n';
        co_return 1;
    }

    const boost::asio::ip::tcp::endpoint endpoint(addr, port);
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        std::cout << "open_ec=" << ec.value() << " msg=" << ec.message() << '\n';
        co_return 1;
    }

    co_await mux::net::wait_connect_with_timeout(socket, endpoint, timeout_sec, ec);
    std::cout << "connect_ec=" << ec.value() << " msg=" << ec.message();

    boost::system::error_code local_ep_ec;
    const auto local_ep = socket.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        std::cout << " local=unavailable(" << local_ep_ec.message() << ')';
    }
    else
    {
        std::cout << " local=" << local_ep.address().to_string() << ':' << local_ep.port();
    }

    std::cout << " open=" << socket.is_open() << '\n';
    co_return ec ? 1 : 0;
}

boost::asio::awaitable<void> run_probe_connect_task(std::string host, uint16_t port, uint32_t timeout_sec, int& rc)
{
    rc = co_await run_probe_connect_async(std::move(host), port, timeout_sec);
}

int run_probe_connect(const char* host, const char* port_str, const char* timeout_str)
{
    const auto port_raw = std::strtoul(port_str, nullptr, 10);
    const auto timeout_raw = timeout_str != nullptr ? std::strtoul(timeout_str, nullptr, 10) : 5UL;
    if (port_raw > 65535UL)
    {
        std::cout << "invalid port=" << port_raw << '\n';
        return 1;
    }

    boost::asio::io_context io_context;
    int rc = 1;
    boost::asio::co_spawn(
        io_context, run_probe_connect_task(host, static_cast<uint16_t>(port_raw), static_cast<uint32_t>(timeout_raw), rc), boost::asio::detached);
    io_context.run();
    return rc;
}

int run_probe_connect_thread(const char* host, const char* port_str, const char* timeout_str)
{
    int rc = 1;
    std::thread worker([&]() { rc = run_probe_connect(host, port_str, timeout_str); });
    worker.join();
    return rc;
}

int register_signal(boost::asio::signal_set& signals, int signal, const char* signal_name)
{
    boost::system::error_code ec;
    ec = signals.add(signal, ec);
    if (ec)
    {
        LOG_ERROR("event {} stage register_signal signal {} error {}", mux::log_event::kConnInit, signal_name, ec.message());
        return -1;
    }
    return 0;
}

uint32_t resolve_worker_threads(const mux::config& cfg)
{
    if (cfg.workers > 0)
    {
        return cfg.workers;
    }

    const auto threads_count = std::thread::hardware_concurrency();
    if (threads_count > 0)
    {
        return threads_count;
    }
    return 4;
}

runtime_services start_services(mux::io_context_pool& pool, const mux::config& cfg)
{
    runtime_services services;
    const bool is_client_mode = (cfg.mode == "client");
    bool has_client_inbound = false;

    if (cfg.mode == "server")
    {
        services.server = std::make_shared<mux::remote_server>(pool, cfg);
        services.server->start();
    }

    if (is_client_mode && cfg.socks.enabled)
    {
        has_client_inbound = true;
    }
#if SOCKS_HAS_TUN
    if (is_client_mode && cfg.tun.enabled)
    {
        has_client_inbound = true;
    }
#endif
#if SOCKS_HAS_TPROXY
    if (is_client_mode && cfg.tproxy.enabled)
    {
        has_client_inbound = true;
    }
#endif
    if (has_client_inbound)
    {
        services.tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg);
        services.tunnel_pool->start();
    }

    if (is_client_mode && cfg.socks.enabled)
    {
        services.socks = std::make_shared<mux::socks_client>(pool, cfg, services.tunnel_pool);
        services.socks->start();
    }
#if SOCKS_HAS_TUN
    if (is_client_mode && cfg.tun.enabled)
    {
        services.tun = std::make_shared<mux::tun_client>(pool, cfg, services.tunnel_pool);
        services.tun->start();
    }
#endif
#if SOCKS_HAS_TPROXY
    if (is_client_mode && cfg.tproxy.enabled)
    {
        services.tproxy = std::make_shared<mux::tproxy_client>(pool, cfg, services.tunnel_pool);
        services.tproxy->start();
    }
#endif
    return services;
}

void stop_services(const runtime_services& services, const mux::io_context_pool& pool)
{
    if (services.socks != nullptr)
    {
        services.socks->stop();
    }
#if SOCKS_HAS_TUN
    if (services.tun != nullptr)
    {
        services.tun->stop();
    }
#endif
#if SOCKS_HAS_TPROXY
    if (services.tproxy != nullptr)
    {
        services.tproxy->stop();
    }
#endif
    if (services.tunnel_pool != nullptr)
    {
        services.tunnel_pool->stop();
    }
    if (services.server != nullptr)
    {
        services.server->stop();
    }

    pool.emit_all(boost::asio::cancellation_type::all);
}

boost::asio::awaitable<void> wait_services_stopped(mux::io_context_pool& pool)
{
    co_await pool.async_wait_all();
    pool.shutdown();
}

int run_with_config(const char* prog, const char* config_path)
{
    auto usage = make_scoped_exit([prog]() { print_usage(prog); });
    auto cfg = mux::parse_config(config_path);
    if (!cfg.has_value())
    {
        return -1;
    }
    usage.cancel();

    init_log(cfg->log.file);
    set_level(cfg->log.level);
    DEFER(shutdown_log());

    if (cfg->mode != "client" && cfg->mode != "server")
    {
        LOG_ERROR("event {} stage start invalid_mode {}", mux::log_event::kConnInit, cfg->mode);
        return -1;
    }
    mux::io_context_pool pool(resolve_worker_threads(*cfg));

    auto services = start_services(pool, *cfg);
    auto& signal_worker = pool.get_io_worker();
    auto& signal_io = signal_worker.io_context;
    boost::asio::signal_set signals(signal_io);
    int ret = register_signal(signals, SIGINT, "sigint");
    if (ret != 0)
    {
        return ret;
    }
    ret = register_signal(signals, SIGTERM, "sigterm");
    if (ret != 0)
    {
        return ret;
    }
    signals.async_wait(
        [&](boost::system::error_code, int)
        {
            stop_services(services, pool);
            boost::asio::co_spawn(signal_io, wait_services_stopped(pool), boost::asio::detached);
        });

    pool.run();
    LOG_INFO("event {} mode {} shutdown", mux::log_event::kConnClose, cfg->mode);
    return 0;
}

}    // namespace

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    const char* mode = argv[1];
    if (std::strcmp(mode, "x25519") == 0)
    {
        dump_x25519();
        return 0;
    }

    if (std::strcmp(mode, "config") == 0)
    {
        const std::string default_config = mux::dump_default_config();
        std::fputs(default_config.c_str(), stdout);
        std::fputc('\n', stdout);
        return 0;
    }

    if (std::strcmp(mode, "probe-connect") == 0)
    {
        if (argc < 4)
        {
            print_usage(argv[0]);
            return 1;
        }
        return run_probe_connect(argv[2], argv[3], argc > 4 ? argv[4] : nullptr);
    }

    if (std::strcmp(mode, "probe-connect-thread") == 0)
    {
        if (argc < 4)
        {
            print_usage(argv[0]);
            return 1;
        }
        return run_probe_connect_thread(argv[2], argv[3], argc > 4 ? argv[4] : nullptr);
    }

    if (std::strcmp(mode, "-c") != 0)
    {
        print_usage(argv[0]);
        return -1;
    }

    if (argc <= 2)
    {
        print_usage(argv[0]);
        return -1;
    }
    return run_with_config(argv[0], argv[2]);
}
