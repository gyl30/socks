#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <system_error>

#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>

#include "log.h"
#include "config.h"
#include "statistics.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"
#include "remote_server.h"
#ifdef __linux__
#include "tproxy_client.h"
#endif
#include "monitor_server.h"

namespace
{

struct runtime_services
{
    std::shared_ptr<mux::remote_server> server = nullptr;
    std::shared_ptr<mux::socks_client> socks = nullptr;
#ifdef __linux__
    std::shared_ptr<mux::tproxy_client> tproxy = nullptr;
#endif
    std::shared_ptr<mux::monitor_server> monitor = nullptr;
};

static void print_usage(const char* prog)
{
    std::cout << "Usage:\n";
    std::cout << prog << " -c <config>  Run with configuration file\n";
    std::cout << prog << " x25519       Generate key pair for kX25519 key exchange\n";
    std::cout << prog << " config       Dump default configuration\n";
}

static void dump_x25519()
{
    std::uint8_t pub[32];
    std::uint8_t priv[32];
    if (!reality::crypto_util::generate_x25519_keypair(pub, priv))
    {
        std::cout << "failed to generate keypair\n";
        return;
    }
    const std::vector<std::uint8_t> vec_priv(priv, priv + 32);
    const std::vector<std::uint8_t> vec_pub(pub, pub + 32);
    std::cout << "private key: " << reality::crypto_util::bytes_to_hex(vec_priv) << '\n';
    std::cout << "public key:  " << reality::crypto_util::bytes_to_hex(vec_pub) << '\n';
}

static int parse_config_from_file(const std::string& file, mux::config& cfg)
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

bool start_runtime_services(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (cfg.monitor.enabled)
    {
        services.monitor = std::make_shared<mux::monitor_server>(
            pool.get_io_context(), cfg.monitor.port, cfg.monitor.token, cfg.monitor.min_interval_ms);
        services.monitor->start();
        if (!services.monitor->running())
        {
            LOG_ERROR("monitor server start failed");
            return false;
        }
    }

    if (cfg.mode == "server")
    {
        services.server = std::make_shared<mux::remote_server>(pool, cfg);
        services.server->start();
        if (!services.server->running())
        {
            LOG_ERROR("remote server start failed");
            return false;
        }
        return true;
    }

    const bool has_socks_inbound = cfg.socks.enabled;
#ifdef __linux__
    const bool has_tproxy_inbound = cfg.tproxy.enabled;
#else
    const bool has_tproxy_inbound = false;
#endif
    if (!has_socks_inbound && !has_tproxy_inbound)
    {
        LOG_ERROR("no client inbound enabled");
        return false;
    }

    if (cfg.socks.enabled)
    {
        services.socks = std::make_shared<mux::socks_client>(pool, cfg);
        services.socks->start();
        if (!services.socks->running())
        {
            LOG_ERROR("socks client start failed");
            return false;
        }
    }
#ifdef __linux__
    if (cfg.tproxy.enabled)
    {
        services.tproxy = std::make_shared<mux::tproxy_client>(pool, cfg);
        services.tproxy->start();
        if (!services.tproxy->running())
        {
            LOG_ERROR("tproxy client start failed");
            return false;
        }
    }
#endif
    return true;
}

bool register_signal(asio::signal_set& signals, const int signal, const char* signal_name)
{
    std::error_code ec;
    ec = signals.add(signal, ec);
    if (!ec)
    {
        return true;
    }
    LOG_ERROR("fatal failed to register {} error {}", signal_name, ec.message());
    return false;
}

void stop_runtime_services(mux::io_context_pool& pool, const runtime_services& services)
{
    if (services.monitor != nullptr)
    {
        services.monitor->stop();
    }
    if (services.socks != nullptr)
    {
        services.socks->stop();
    }
#ifdef __linux__
    if (services.tproxy != nullptr)
    {
        services.tproxy->stop();
    }
#endif
    if (services.server != nullptr)
    {
        services.server->stop();
    }
    pool.shutdown();
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

bool is_supported_runtime_mode(const std::string& mode)
{
    return mode == "client" || mode == "server";
}

bool register_shutdown_signals(asio::signal_set& signals, mux::io_context_pool& pool, const runtime_services& services)
{
    if (!register_signal(signals, SIGINT, "sigint"))
    {
        return false;
    }
    if (!register_signal(signals, SIGTERM, "sigterm"))
    {
        return false;
    }

    signals.async_wait(
        [&pool, services](const std::error_code& error, int)
        {
            if (error)
            {
                return;
            }
            stop_runtime_services(pool, services);
        });
    return true;
}

int run_with_config(const char* prog, const std::string& config_path)
{
    mux::config cfg;
    if (parse_config_from_file(config_path, cfg) != 0)
    {
        print_usage(prog);
        return -1;
    }

    init_log(cfg.log.file);
    set_level(cfg.log.level);
    mux::statistics::instance().start_time();

    mux::io_context_pool pool(resolve_worker_threads(cfg));

    if (!is_supported_runtime_mode(cfg.mode))
    {
        print_usage(prog);
        shutdown_log();
        return 1;
    }

    runtime_services services;
    if (!start_runtime_services(pool, cfg, services))
    {
        stop_runtime_services(pool, services);
        shutdown_log();
        return 1;
    }
    asio::signal_set signals(pool.get_io_context());
    if (!register_shutdown_signals(signals, pool, services))
    {
        stop_runtime_services(pool, services);
        shutdown_log();
        return 1;
    }

    pool.run();
    LOG_INFO("{} {} shutdown", prog, cfg.mode);
    shutdown_log();
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

    const std::string mode = argv[1];
    if (mode == "x25519")
    {
        dump_x25519();
        return 0;
    }

    if (mode == "config")
    {
        std::cout << mux::dump_default_config() << '\n';
        return 0;
    }

    if (mode != "-c")
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
