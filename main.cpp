#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string_view>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/signal_set.hpp>

#include "log.h"
#include "config.h"
#include "scoped_exit.h"
#include "context_pool.h"
#include "socks_client.h"
#include "remote_server.h"
#include "tls/crypto_util.h"

#if SOCKS_HAS_TPROXY
#include "tproxy_client.h"

#endif
namespace
{

struct runtime_services
{
    std::shared_ptr<mux::remote_server> server = nullptr;
    std::shared_ptr<mux::socks_client> socks = nullptr;
#if SOCKS_HAS_TPROXY
    std::shared_ptr<mux::tproxy_client> tproxy = nullptr;
#endif
};

void print_usage(std::string_view prog)
{
    std::cout << "Usage:\n"
              << prog << " -c <config>  Run with configuration file\n"
              << prog << " x25519       Generate key pair for kX25519 key exchange\n"
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

int register_signal(boost::asio::signal_set& signals, int signal, const char* signal_name)
{
    boost::system::error_code ec;
    ec = signals.add(signal, ec);
    if (ec)
    {
        LOG_ERROR("fatal failed to register {} error {}", signal_name, ec.message());
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

    if (cfg.mode == "server")
    {
        services.server = std::make_shared<mux::remote_server>(pool, cfg);
        services.server->start();
    }

    if (is_client_mode && cfg.socks.enabled)
    {
        services.socks = std::make_shared<mux::socks_client>(pool, cfg);
        services.socks->start();
    }
#if SOCKS_HAS_TPROXY
    if (is_client_mode && cfg.tproxy.enabled)
    {
        services.tproxy = std::make_shared<mux::tproxy_client>(pool, cfg);
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
#if SOCKS_HAS_TPROXY
    if (services.tproxy != nullptr)
    {
        services.tproxy->stop();
    }
#endif
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
        LOG_ERROR("not supported mode {}", cfg->mode);
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
    LOG_INFO("{} shutdown", cfg->mode);
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
