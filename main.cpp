#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <asio.hpp>
#include "log.h"
#include "config.h"
#include "crypto_util.h"
#include "local_client.h"
#include "context_pool.h"
#include "remote_server.h"

static void print_usage(const char* prog)
{
    std::cout << "Usage:\n";
    std::cout << prog << "x25519        Generate key pair for X25519 key exchange\n";
}

static void dump_x25519()
{
    uint8_t pub[32];
    uint8_t priv[32];
    if (!reality::crypto_util::generate_x25519_keypair(pub, priv))
    {
        fmt::print("Failed to generate keypair\n");
        return;
    }
    const std::vector<uint8_t> vec_priv(priv, priv + 32);
    const std::vector<uint8_t> vec_pub(pub, pub + 32);
    std::cout << "Private Key: " << reality::crypto_util::bytes_to_hex(vec_priv) << '\n';
    std::cout << "Public Key:  " << reality::crypto_util::bytes_to_hex(vec_pub) << '\n';
}

static int parse_config_from_file(const std::string& file, config& cfg)
{
    auto c = parse_config(file);
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
        std::cout << dump_default_config() << '\n';
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
    config cfg;
    if (parse_config_from_file(argv[2], cfg) != 0)
    {
        print_usage(argv[0]);
        return -1;
    }

    init_log(cfg.log.file);
    set_level(cfg.log.level);

    const auto threads_count = std::thread::hardware_concurrency();
    std::error_code ec;
    io_context_pool pool(threads_count > 0 ? threads_count : 4, ec);
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

    std::shared_ptr<mux::remote_server> server;
    std::shared_ptr<mux::local_client> client;

    if (cfg.mode == "server")
    {
        server = std::make_shared<mux::remote_server>(pool, cfg.inbound.port, cfg.fallbacks, cfg.reality.private_key, cfg.timeout, cfg.limits);
        server->start();
    }
    else if (cfg.mode == "client")
    {
        client = std::make_shared<mux::local_client>(pool,
                                                     cfg.outbound.host,
                                                     std::to_string(cfg.outbound.port),
                                                     cfg.socks.port,
                                                     cfg.reality.public_key,
                                                     cfg.reality.sni,
                                                     cfg.timeout,
                                                     cfg.socks,
                                                     cfg.limits);
        client->start();
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
        [&pool, server, client](const std::error_code& error, int)
        {
            if (!error)
            {
                if (client)
                {
                    client->stop();
                }
                if (server)
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
