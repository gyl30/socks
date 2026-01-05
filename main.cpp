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
    std::cout << "Usage:\n";
    std::cout << "  Run as Local Client: " << prog << " -c <remote_ip> <remote_port> <local_port>\n";
    std::cout << "  Run as Remote Server: " << prog << " -s <bind_port>\n";
}

int main(int argc, char** argv)
{
    const std::string app_name(argv[0]);
    init_log(app_name + ".log");

    set_level("info");

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    try
    {
        const auto threads_count = std::thread::hardware_concurrency();
        io_context_pool pool(threads_count > 0 ? threads_count : 4);

        if (mode == "-s")
        {
            if (argc < 3)
            {
                print_usage(argv[0]);
                return 1;
            }
            std::uint16_t port = std::stoi(argv[2]);

            mux::RemoteServer server(pool, port);
            server.start();

            pool.run();
        }
        else if (mode == "-c")
        {
            if (argc < 5)
            {
                print_usage(argv[0]);
                return 1;
            }
            std::string r_ip = argv[2];
            std::string r_port = argv[3];
            std::uint16_t l_port = std::stoi(argv[4]);

            mux::LocalClient client(pool.get_io_context(), r_ip, r_port, l_port);
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
        LOG_ERROR("Fatal: {}", e.what());
        return 1;
    }

    return 0;
}
