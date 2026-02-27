#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <cstdio>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>

#include <boost/system/errc.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/system/detail/errc.hpp>

#include "log.h"
#include "config.h"
#include "statistics.h"
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

struct shutdown_state
{
    std::atomic<bool> stop_requested = {false};
    std::atomic<bool> force_stopped = {false};
    std::atomic<bool> shutdown_completed = {false};
    std::atomic<bool> watchdog_started = {false};
    std::thread watchdog_thread;
};

void print_usage(const char* prog)
{
    std::fputs("Usage:\n", stdout);
    std::fprintf(stdout, "%s -c <config>  Run with configuration file\n", prog);
    std::fprintf(stdout, "%s x25519       Generate key pair for kX25519 key exchange\n", prog);
    std::fprintf(stdout, "%s config       Dump default configuration\n", prog);
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
    std::fprintf(stdout, "private key: %s\n", priv_hex.c_str());
    std::fprintf(stdout, "public key:  %s\n", pub_hex.c_str());
}

int parse_config_from_file(const std::string& file, mux::config& cfg)
{
    const auto parsed = mux::parse_config_with_error(file);
    if (!parsed)
    {
        const auto& error = parsed.error();
        std::fprintf(stderr, "parse config failed path %s reason %s\n", error.path.c_str(), error.reason.c_str());
        return -1;
    }
    cfg = *parsed;
    return 0;
}

bool start_monitor_if_enabled(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (!cfg.monitor.enabled)
    {
        return true;
    }
    services.monitor = std::make_shared<mux::monitor_server>(pool.get_io_context(), cfg.monitor.port);
    services.monitor->start();
    if (!services.monitor->running())
    {
        LOG_ERROR("monitor server start failed");
        return false;
    }
    return true;
}

bool start_server_mode(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
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

bool has_client_inbound_enabled(const mux::config& cfg)
{
#if SOCKS_HAS_TPROXY
    return cfg.socks.enabled || cfg.tproxy.enabled;
#else
    return cfg.socks.enabled;
#endif
}

bool start_socks_inbound_if_enabled(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (!cfg.socks.enabled)
    {
        return true;
    }
    services.socks = std::make_shared<mux::socks_client>(pool, cfg);
    services.socks->start();
    if (!services.socks->running())
    {
        LOG_ERROR("socks client start failed");
        return false;
    }
    return true;
}

#if SOCKS_HAS_TPROXY
bool start_tproxy_inbound_if_enabled(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (!cfg.tproxy.enabled)
    {
        return true;
    }
    services.tproxy = std::make_shared<mux::tproxy_client>(pool, cfg);
    services.tproxy->start();
    if (!services.tproxy->running())
    {
        LOG_ERROR("tproxy client start failed");
        return false;
    }
    return true;
}
#endif

bool start_client_mode(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (!start_socks_inbound_if_enabled(pool, cfg, services))
    {
        return false;
    }
#if SOCKS_HAS_TPROXY
    if (!start_tproxy_inbound_if_enabled(pool, cfg, services))
    {
        return false;
    }
#endif
    return true;
}

bool start_runtime_services(mux::io_context_pool& pool, const mux::config& cfg, runtime_services& services)
{
    if (!start_monitor_if_enabled(pool, cfg, services))
    {
        return false;
    }

    if (cfg.mode == "server")
    {
        return start_server_mode(pool, cfg, services);
    }

    if (!has_client_inbound_enabled(cfg))
    {
        LOG_ERROR("no client inbound enabled");
        return false;
    }
    return start_client_mode(pool, cfg, services);
}

bool register_signal(boost::asio::signal_set& signals, const int signal, const char* signal_name)
{
    auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
    ec = signals.add(signal, ec);
    if (!ec)
    {
        return true;
    }
    LOG_ERROR("fatal failed to register {} error {}", signal_name, ec.message());
    return false;
}

void request_stop_runtime_services(const runtime_services& services)
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
}

void start_shutdown_watchdog(mux::io_context_pool& pool, shutdown_state& state)
{
    bool expected = false;
    if (!state.watchdog_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    state.watchdog_thread = std::thread(
        [&pool, &state]()
        {
            constexpr auto k_step = std::chrono::milliseconds(100);
            constexpr std::uint32_t k_step_count = 100;
            for (std::uint32_t i = 0; i < k_step_count; ++i)
            {
                if (state.shutdown_completed.load(std::memory_order_acquire))
                {
                    return;
                }
                std::this_thread::sleep_for(k_step);
            }
            if (state.shutdown_completed.load(std::memory_order_acquire))
            {
                return;
            }
            state.force_stopped.store(true, std::memory_order_release);
            LOG_ERROR("graceful shutdown timeout exceeded forcing stop");
            pool.stop();
        });
}

void begin_runtime_shutdown(mux::io_context_pool& pool, const runtime_services& services, shutdown_state& state)
{
    bool expected = false;
    if (!state.stop_requested.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    request_stop_runtime_services(services);
    pool.shutdown();
    start_shutdown_watchdog(pool, state);
}

void complete_runtime_shutdown(shutdown_state& state)
{
    state.shutdown_completed.store(true, std::memory_order_release);
    if (state.watchdog_started.load(std::memory_order_acquire) && state.watchdog_thread.joinable())
    {
        state.watchdog_thread.join();
    }
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

bool is_supported_runtime_mode(const std::string& mode) { return mode == "client" || mode == "server"; }

bool register_shutdown_signals(boost::asio::signal_set& signals,
                               mux::io_context_pool& pool,
                               const runtime_services& services,
                               shutdown_state& state)
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
        [&pool, services, &state](const auto& error, int)
        {
            if (error)
            {
                return;
            }
            if (state.stop_requested.load(std::memory_order_acquire))
            {
                state.force_stopped.store(true, std::memory_order_release);
                LOG_ERROR("received extra shutdown signal forcing stop");
                pool.stop();
                return;
            }
            begin_runtime_shutdown(pool, services, state);
        });
    return true;
}

int run_with_config(const char* prog, const char* config_path)
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
    shutdown_state state;

    if (!is_supported_runtime_mode(cfg.mode))
    {
        print_usage(prog);
        shutdown_log();
        return 1;
    }

    runtime_services services;
    if (!start_runtime_services(pool, cfg, services))
    {
        begin_runtime_shutdown(pool, services, state);
        pool.run();
        complete_runtime_shutdown(state);
        shutdown_log();
        return state.force_stopped.load(std::memory_order_acquire) ? 2 : 1;
    }
    boost::asio::signal_set signals(pool.get_io_context());
    if (!register_shutdown_signals(signals, pool, services, state))
    {
        begin_runtime_shutdown(pool, services, state);
        pool.run();
        complete_runtime_shutdown(state);
        shutdown_log();
        return state.force_stopped.load(std::memory_order_acquire) ? 2 : 1;
    }

    pool.run();
    complete_runtime_shutdown(state);
    LOG_INFO("{} {} shutdown", prog, cfg.mode);
    shutdown_log();
    return state.force_stopped.load(std::memory_order_acquire) ? 2 : 0;
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
