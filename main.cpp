#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>

#include <boost/system/errc.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/system/detail/errc.hpp>

#include "log.h"
#include "config.h"
#include "statistics.h"
#include "scoped_exit.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"
#include "remote_server.h"

#if SOCKS_HAS_TPROXY
#include "tproxy_client.h"

#endif
#include "monitor_server.h"

namespace
{

struct runtime_services
{
    std::shared_ptr<mux::remote_server> server = nullptr;
    std::shared_ptr<mux::socks_client> socks = nullptr;
#if SOCKS_HAS_TPROXY
    std::shared_ptr<mux::tproxy_client> tproxy = nullptr;
#endif
    std::shared_ptr<mux::monitor_server> monitor = nullptr;
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
    std::uint8_t pub[32];
    std::uint8_t priv[32];
    if (!reality::crypto_util::generate_x25519_keypair(pub, priv))
    {
        std::fputs("failed to generate keypair\n", stdout);
        return;
    }
    const std::vector<std::uint8_t> vec_priv(priv, priv + 32);
    const std::vector<std::uint8_t> vec_pub(pub, pub + 32);
    const std::string priv_hex = reality::crypto_util::bytes_to_hex(vec_priv);
    const std::string pub_hex = reality::crypto_util::bytes_to_hex(vec_pub);
    std::cout << "private key: " << priv_hex << '\n' << "public key:  " << pub_hex << '\n';
}

int parse_config_from_file(const std::string& file, mux::config& cfg)
{
    const auto parsed = mux::parse_config_with_error(file);
    if (!parsed)
    {
        const auto& error = parsed.error();
        std::cerr << "parse config failed path " << error.path << " reason " << error.reason << '\n';
        return -1;
    }
    cfg = *parsed;
    return 0;
}

int register_signal(boost::asio::signal_set& signals, const int signal, const char* signal_name)
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

std::uint32_t resolve_worker_threads(const mux::config& cfg)
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

int run_services(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (cfg.monitor.enabled)
    {
        services.monitor = std::make_shared<mux::monitor_server>(pool.get_io_context(), cfg.monitor.port);
        services.monitor->start();
    }
    else
    {
        LOG_INFO("monitor disabled");
    }
    if (cfg.mode == "server")
    {
        services.server = std::make_shared<mux::remote_server>(pool, cfg);
        services.server->start();
    }

    if (cfg.socks.enabled)
    {
        services.socks = std::make_shared<mux::socks_client>(pool, cfg);
        services.socks->start();
    }
#if SOCKS_HAS_TPROXY
    if (cfg.tproxy.enabled)
    {
        services.tproxy = std::make_shared<mux::tproxy_client>(pool, cfg);
        services.tproxy->start();
    }
#endif
    return 0;
}

void stop_services(runtime_services& services)
{
    if (services.monitor != nullptr)
    {
        services.monitor->stop();
    }
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
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}
int run_with_config(const char* prog, const char* config_path)
{
    mux::config cfg;
    auto usage = make_scoped_exit([prog]() { print_usage(prog); });
    if (parse_config_from_file(config_path, cfg) != 0)
    {
        return -1;
    }
    usage.cancel();

    init_log(cfg.log.file);
    set_level(cfg.log.level);
    DEFER(shutdown_log());

    if (cfg.mode != "client" && cfg.mode != "server")
    {
        LOG_ERROR("not supported mode {}", cfg.mode);
        return -1;
    }

    mux::statistics::instance().start_time();

    mux::io_context_pool pool(resolve_worker_threads(cfg));

    runtime_services services;
    int ret = run_services(pool, cfg, services);
    if (ret != 0)
    {
        return ret;
    }
    boost::asio::signal_set signals(pool.get_io_context());
    ret = register_signal(signals, SIGINT, "sigint");
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
            stop_services(services);
            pool.stop();
        });

    pool.run();
    LOG_INFO("{} shutdown", cfg.mode);
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
