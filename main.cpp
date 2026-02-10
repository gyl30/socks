#include <chrono>
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
#include "tproxy_client.h"
#include "remote_server.h"
#include "monitor_server.h"

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
    const auto c = mux::parse_config(file);
    if (!c.has_value())
    {
        return -1;
    }
    cfg = c.value();
    return 0;
}

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

    mux::config cfg;
    if (parse_config_from_file(argv[2], cfg) != 0)
    {
        print_usage(argv[0]);
        return -1;
    }

    init_log(cfg.log.file);
    set_level(cfg.log.level);

    mux::statistics::instance().start_time();

    const auto threads_count = std::thread::hardware_concurrency();
    std::error_code ec;
    mux::io_context_pool pool(threads_count > 0 ? threads_count : 4, ec);
    if (ec)
    {
        LOG_ERROR("fatal failed to create io context pool error {}", ec.message());
        return 1;
    }

    if (cfg.mode != "client" && cfg.mode != "server")
    {
        print_usage(argv[0]);
        return 1;
    }

    std::shared_ptr<mux::remote_server> server = nullptr;
    std::shared_ptr<mux::socks_client> socks = nullptr;
    std::shared_ptr<mux::tproxy_client> tproxy = nullptr;
    std::shared_ptr<mux::monitor_server> monitor = nullptr;

    if (cfg.monitor.enabled)
    {
        monitor = std::make_shared<mux::monitor_server>(pool.get_io_context(),
                                                        cfg.monitor.port,
                                                        cfg.monitor.token,
                                                        cfg.monitor.min_interval_ms);
        monitor->start();
    }

    if (cfg.mode == "server")
    {
        server = std::make_shared<mux::remote_server>(pool, cfg);
        server->start();
    }
    else if (cfg.mode == "client")
    {
        if (cfg.socks.enabled)
        {
            socks = std::make_shared<mux::socks_client>(pool, cfg);
            socks->start();
        }
        if (cfg.tproxy.enabled)
        {
            tproxy = std::make_shared<mux::tproxy_client>(pool, cfg);
            tproxy->start();
        }
    }

    asio::io_context& signal_ctx = pool.get_io_context();
    asio::signal_set signals(signal_ctx);
    ec = signals.add(SIGINT, ec);
    if (ec)
    {
        LOG_ERROR("fatal failed to register sigint error {}", ec.message());
        return 1;
    }
    ec = signals.add(SIGTERM, ec);
    if (ec)
    {
        LOG_ERROR("fatal failed to register sigterm error {}", ec.message());
        return 1;
    }

    signals.async_wait(
        [&pool, server, socks, tproxy](const std::error_code& error, int)
        {
            if (!error)
            {
                if (socks != nullptr)
                {
                    socks->stop();
                }
                if (tproxy != nullptr)
                {
                    tproxy->stop();
                }
                if (server != nullptr)
                {
                    server->stop();
                }

                pool.stop();
            }
        });

    pool.run();
    LOG_INFO("{} {} shutdown", argv[0], cfg.mode);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    shutdown_log();
    return 0;
}
