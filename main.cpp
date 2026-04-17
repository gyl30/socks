#include <cstdio>
#include <memory>
#include <string>
#include <vector>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string_view>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "app_runtime.h"
#include "scoped_exit.h"
#include "tls/crypto_util.h"

namespace
{

void print_usage(const std::string_view prog)
{
    std::cout << "Usage:\n"
              << prog << " -c <config>  Run with configuration file\n"
              << prog << " x25519       Generate key pair for kX25519 key exchange\n"
              << prog << " config       Dump default configuration\n";
}

void dump_x25519()
{
    uint8_t public_key[32] = {0};
    uint8_t private_key[32] = {0};
    if (!tls::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        std::fputs("failed to generate keypair\n", stdout);
        return;
    }

    const std::vector<uint8_t> private_bytes(private_key, private_key + 32);
    const std::vector<uint8_t> public_bytes(public_key, public_key + 32);
    const std::string private_key_hex = tls::crypto_util::bytes_to_hex(private_bytes);
    const std::string public_key_hex = tls::crypto_util::bytes_to_hex(public_bytes);
    std::cout << "private key: " << private_key_hex << '\n' << "public key:  " << public_key_hex << '\n';
}

[[nodiscard]] int register_signal(boost::asio::signal_set& signals, const int signal, const char* signal_name)
{
    boost::system::error_code ec;
    ec = signals.add(signal, ec);
    if (ec)
    {
        LOG_ERROR("{} stage register_signal signal {} error {}", relay::log_event::kConnInit, signal_name, ec.message());
        return -1;
    }
    return 0;
}

int run_with_config(const char* prog, const char* config_path)
{
    auto cfg = relay::parse_config(config_path);
    if (!cfg.has_value())
    {
        return 1;
    }
    (void)prog;

    init_log(cfg->log.file);
    set_level(cfg->log.level);
    DEFER(shutdown_log());

    relay::app_runtime runtime(*cfg);
    try
    {
        runtime.start();
    }
    catch (const std::exception& ex)
    {
        LOG_ERROR("{} stage runtime_start config {} exception {}", relay::log_event::kConnInit, config_path, ex.what());
        return 1;
    }
    catch (...)
    {
        LOG_ERROR("{} stage runtime_start config {} exception unknown", relay::log_event::kConnInit, config_path);
        return 1;
    }

    auto& signal_worker = runtime.pool().get_io_worker();
    boost::asio::signal_set signals(signal_worker.io_context);
    int ret = register_signal(signals, SIGINT, "sigint");
    if (ret != 0)
    {
        runtime.stop();
        return ret;
    }
    ret = register_signal(signals, SIGTERM, "sigterm");
    if (ret != 0)
    {
        runtime.stop();
        return ret;
    }

    signals.async_wait(
        [&](const boost::system::error_code&, const int)
        {
            runtime.stop();
            boost::asio::co_spawn(signal_worker.io_context, runtime.async_wait_stopped(), boost::asio::detached);
        });

    try
    {
        runtime.pool().run();
    }
    catch (const std::exception& ex)
    {
        LOG_ERROR("{} stage runtime_run config {} exception {}", relay::log_event::kConnClose, config_path, ex.what());
        runtime.stop();
        return 1;
    }
    catch (...)
    {
        LOG_ERROR("{} stage runtime_run config {} exception unknown", relay::log_event::kConnClose, config_path);
        runtime.stop();
        return 1;
    }
    LOG_INFO("{} stage shutdown complete", relay::log_event::kConnClose);
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
        const std::string default_config = relay::dump_default_config();
        std::fputs(default_config.c_str(), stdout);
        std::fputc('\n', stdout);
        return 0;
    }

    if (std::strcmp(mode, "-c") != 0 || argc <= 2)
    {
        print_usage(argv[0]);
        return -1;
    }

    return run_with_config(argv[0], argv[2]);
}
