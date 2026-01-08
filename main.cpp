#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <boost/asio.hpp>
#include "log.h"
#include "local_client.h"
#include "remote_server.h"
#include "context_pool.h"

void print_usage(const char* prog)
{
    std::cout << "usage:\n";
    std::cout << "  run as local client " << prog << " -c <remote_host> <remote_port> <local_port> <auth_key_hex>\n";
    std::cout << "  run as remote server " << prog << " -s <bind_port> <fallback_host> <fallback_port> <auth_key_hex>\n";
}

int main(int argc, char** argv)
{
    const std::string app_name(argv[0]);
    init_log(app_name + ".log");

    set_level("trace");

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    const std::string mode = argv[1];

    try
    {
        const auto threads_count = std::thread::hardware_concurrency();
        io_context_pool pool(threads_count > 0 ? threads_count : 4);

        if (mode == "-s")
        {
            if (argc < 6)
            {
                print_usage(argv[0]);
                return 1;
            }
            std::uint16_t port = static_cast<std::uint16_t>(std::stoi(argv[2]));
            std::string fb_host = argv[3];
            std::string fb_port = argv[4];
            std::string auth_key = argv[5];

            mux::remote_server server(pool, port, fb_host, fb_port, auth_key);
            server.start();

            pool.run();
        }
        else if (mode == "-c")
        {
            if (argc < 6)
            {
                print_usage(argv[0]);
                return 1;
            }
            std::string r_host = argv[2];
            std::string r_port = argv[3];
            std::uint16_t l_port = static_cast<std::uint16_t>(std::stoi(argv[4]));
            std::string auth_key = argv[5];

            mux::local_client client(pool, r_host, r_port, l_port, auth_key);
            client.start();

            pool.run();
        }
        else
        {
            print_usage(argv[0]);
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("fatal {}", e.what());
        return 1;
    }

    return 0;
}
