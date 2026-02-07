#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <mutex>
#include <memory>
#include <vector>
#include <string>
#include <utility>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/experimental/concurrent_channel.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "config.h"
#include "router.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "log_context.h"
#include "context_pool.h"
#include "reality_core.h"
#include "reality_messages.h"

namespace mux
{

class local_client : public std::enable_shared_from_this<local_client>
{
   public:
    local_client(io_context_pool& pool,
                 std::string host,
                 std::string port,
                 std::uint16_t l_port,
                 const std::string& key_hex,
                 std::string sni,
                 const std::string& short_id_hex = "",
                 const std::string& verify_key_hex = "",
                 const config::timeout_t& timeout_cfg = {},
                 config::socks_t socks_cfg = {},
                 const config::limits_t& limits_cfg = {});

    void start();

    void stop();

    [[nodiscard]] std::uint16_t listen_port() const { return listen_port_; }

   private:
    struct handshake_result
    {
        std::vector<std::uint8_t> c_app_secret;
        std::vector<std::uint8_t> s_app_secret;
        std::uint16_t cipher_suite = 0;
        const EVP_MD* md = nullptr;
        const EVP_CIPHER* cipher = nullptr;
    };

    asio::awaitable<void> connect_remote_loop(std::uint32_t index);

    [[nodiscard]] asio::awaitable<bool> tcp_connect(asio::ip::tcp::socket& socket, std::error_code& ec) const;

    [[nodiscard]] asio::awaitable<std::pair<bool, handshake_result>> perform_reality_handshake(asio::ip::tcp::socket& socket,
                                                                                               std::error_code& ec) const;

    [[nodiscard]] asio::awaitable<bool> generate_and_send_client_hello(asio::ip::tcp::socket& socket,
                                                                       const std::uint8_t* public_key,
                                                                       const std::uint8_t* private_key,
                                                                       reality::transcript& trans,
                                                                       std::error_code& ec) const;

    struct server_hello_res
    {
        bool ok = false;
        reality::handshake_keys hs_keys;
        const EVP_MD* negotiated_md = nullptr;
        const EVP_CIPHER* negotiated_cipher = nullptr;
        std::uint16_t cipher_suite = 0;
    };

    [[nodiscard]] static asio::awaitable<server_hello_res> process_server_hello(asio::ip::tcp::socket& socket,
                                                                                const std::uint8_t* private_key,
                                                                                reality::transcript& trans,
                                                                                std::error_code& ec);

    [[nodiscard]] static asio::awaitable<std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>> handshake_read_loop(
        asio::ip::tcp::socket& socket,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
        const reality::handshake_keys& hs_keys,
        reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        const std::vector<std::uint8_t>& verify_pub_key,
        std::error_code& ec);

    [[nodiscard]] static bool process_certificate_verify(const std::vector<std::uint8_t>& msg_data,
                                                         const std::vector<std::uint8_t>& verify_pub_key,
                                                         const std::vector<std::uint8_t>& handshake_hash,
                                                         std::error_code& ec);

    [[nodiscard]] static asio::awaitable<bool> send_client_finished(asio::ip::tcp::socket& socket,
                                                                    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                                    const std::vector<std::uint8_t>& c_hs_secret,
                                                                    const reality::transcript& trans,
                                                                    const EVP_CIPHER* cipher,
                                                                    const EVP_MD* md,
                                                                    std::error_code& ec);

    asio::awaitable<void> wait_remote_retry();

    asio::awaitable<void> wait_stop();

    asio::awaitable<void> accept_local_loop();

   private:
    bool stop_ = false;
    std::string remote_host_;
    std::string remote_port_;
    std::uint16_t listen_port_;
    std::string sni_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::vector<std::uint8_t> verify_pub_key_;
    bool auth_config_valid_ = true;
    io_context_pool& pool_;
    std::vector<std::uint8_t> server_pub_key_;
    std::vector<std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> tunnel_pool_;
    std::mutex pool_mutex_;
    std::uint32_t next_tunnel_index_{0};
    std::uint32_t next_conn_id_{1};
    std::uint32_t next_session_id_{1};
    asio::steady_timer remote_timer_;
    asio::ip::tcp::acceptor acceptor_;

    std::shared_ptr<mux::router> router_;

    asio::experimental::concurrent_channel<void(std::error_code, int)> stop_channel_;
    config::timeout_t timeout_config_;
    config::socks_t socks_config_;
    config::limits_t limits_config_;
};

}    // namespace mux

#endif
