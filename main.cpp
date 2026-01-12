#include <iostream>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include "log.h"
#include "local_client.h"
#include "remote_server.h"
#include "context_pool.h"

static void print_usage(const char* prog)
{
    std::cout << "usage\n";
    std::cout << "  run as local client " << prog << " -c <remote_host> <remote_port> <local_port> <auth_key_hex> <sni>\n";
    std::cout << "  run as remote server " << prog << " -s <bind_port> <fallback_host> <fallback_port> <auth_key_hex>\n";
}
static void stop_handle(int sig) { LOG_INFO("received signal {} stopping io context pool...", sig); }
int main(int argc, char** argv)
{
    const std::string app_name(argv[0]);
    init_log(app_name + ".log");

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    const std::string mode = argv[1];
    const auto threads_count = std::thread::hardware_concurrency();
    boost::system::error_code ec;
    io_context_pool pool(threads_count > 0 ? threads_count : 4, ec);

    if (ec)
    {
        LOG_ERROR("fatal failed to create io context pool error {}", ec.message());
        return 1;
    }

    boost::asio::io_context& signal_ctx = pool.get_io_context();
    boost::asio::signal_set signals(signal_ctx);
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
        [&pool](const boost::system::error_code& error, int signal_number)
        {
            if (!error)
            {
                stop_handle(signal_number);
                pool.stop();
            }
        });
    if (mode == "-s")
    {
        if (argc < 6)
        {
            print_usage(argv[0]);
            return 1;
        }
        const uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
        auto server = std::make_shared<mux::remote_server>(pool, port, argv[3], argv[4], argv[5], ec);
        if (ec)
        {
            LOG_ERROR("fatal failed to create remote server error {}", ec.message());
            return 1;
        }
        server->start();
        pool.run();
    }
    else if (mode == "-c")
    {
        if (argc < 7)
        {
            print_usage(argv[0]);
            return 1;
        }
        const uint16_t l_port = static_cast<uint16_t>(std::stoi(argv[4]));
        auto client = std::make_shared<mux::local_client>(pool, argv[2], argv[3], l_port, argv[5], argv[6], ec);
        if (ec)
        {
            LOG_ERROR("fatal failed to create local client error {}", ec.message());
            return 1;
        }
        client->start();
        pool.run();
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }

    shutdown_log();
    return 0;
}
