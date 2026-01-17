#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <asio.hpp>
#include "log.h"
#include "local_client.h"
#include "remote_server.h"
#include "context_pool.h"
#include "crypto_util.h"

static void print_usage(const char* prog)
{
    std::cout << "usage\n";
    std::cout << "  run as local client " << prog << " -c <remote_host> <remote_port> <local_port> <auth_key_hex> <sni>\n";
    std::cout << "  run as remote server " << prog << " -s <bind_port> <fallback_host> <fallback_port> <auth_key_hex>\n";
    std::cout << "  generate key pair    " << prog << " -g\n";
}

int main(int argc, char** argv)
{
    const std::string app_name(argv[0]);

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    const std::string mode = argv[1];

    if (mode == "-g")
    {
        uint8_t pub[32];
        uint8_t priv[32];
        reality::crypto_util::generate_x25519_keypair(pub, priv);
        const std::vector<uint8_t> vec_priv(priv, priv + 32);
        const std::vector<uint8_t> vec_pub(pub, pub + 32);

        std::cout << "Generated X25519 Keypair (Hex):" << std::endl;
        std::cout << "----------------------------------------------------------------" << std::endl;
        std::cout << "Private Key: " << reality::crypto_util::bytes_to_hex(vec_priv) << std::endl;
        std::cout << "Public Key:  " << reality::crypto_util::bytes_to_hex(vec_pub) << std::endl;
        std::cout << "----------------------------------------------------------------" << std::endl;
        std::cout << "Usage:" << std::endl;
        std::cout << "  Server: Use 'Private Key' for authentication." << std::endl;
        std::cout << "  Client: Use 'Public Key' to connect." << std::endl;

        return 0;
    }

    init_log(app_name + ".log");

    const auto threads_count = std::thread::hardware_concurrency();
    std::error_code ec;
    io_context_pool pool(threads_count > 0 ? threads_count : 4, ec);

    if (ec)
    {
        LOG_ERROR("fatal failed to create io context pool error {}", ec.message());
        return 1;
    }

    std::shared_ptr<mux::remote_server> server;
    std::shared_ptr<mux::local_client> client;

    if (mode == "-s")
    {
        if (argc < 6)
        {
            print_usage(argv[0]);
            return 1;
        }
        const uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
        server = std::make_shared<mux::remote_server>(pool, port, argv[3], argv[4], argv[5]);
        server->start();
    }
    else if (mode == "-c")
    {
        if (argc < 7)
        {
            print_usage(argv[0]);
            return 1;
        }
        const uint16_t l_port = static_cast<uint16_t>(std::stoi(argv[4]));
        client = std::make_shared<mux::local_client>(pool, argv[2], argv[3], l_port, argv[5], argv[6]);
        client->start();
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }

    asio::io_context& signal_ctx = pool.get_io_context();
    asio::signal_set signals(signal_ctx);
    ec = signals.add(SIGINT, ec);
    if (ec)
    {
        LOG_ERROR("fatal failed to register SIGINT error {}", ec.message());
        return 1;
    }
    ec = signals.add(SIGTERM, ec);
    if (ec)
    {
        LOG_ERROR("fatal failed to register SIGTERM error {}", ec.message());
        return 1;
    }

    signals.async_wait(
        [&pool, server, client](const std::error_code& error, int signal_number)
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
    std::this_thread::sleep_for(std::chrono::seconds(1));
    shutdown_log();
    return 0;
}
