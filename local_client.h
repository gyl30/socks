#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <utility>
#include <vector>
#include <memory>
#include <asio.hpp>

#include "log.h"
#include "router.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "log_context.h"
#include "context_pool.h"
#include "reality_core.h"
#include "socks_session.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_key_schedule.h"
#include "reality_fingerprint.h"
#include "constants.h"

namespace mux
{

class local_client : public std::enable_shared_from_this<local_client>
{
   public:
    local_client(io_context_pool& pool,
                 std::string host,
                 std::string port,
                 uint16_t l_port,
                 const std::string& key_hex,
                 std::string sni,
                 const config::timeout_t& timeout_cfg = {},
                 config::socks_t socks_cfg = {},
                 const config::limits_t& limits_cfg = {});

    void start();

    void stop();

   private:
    struct handshake_result
    {
        std::vector<uint8_t> c_app_secret;
        std::vector<uint8_t> s_app_secret;
        uint16_t cipher_suite;
        const EVP_MD* md;
        const EVP_CIPHER* cipher;
    };

    asio::awaitable<void> connect_remote_loop(uint32_t index);

    asio::awaitable<bool> tcp_connect(asio::ip::tcp::socket& socket, std::error_code& ec) const;

    asio::awaitable<std::pair<bool, handshake_result>> perform_reality_handshake(asio::ip::tcp::socket& socket, std::error_code& ec) const;

    asio::awaitable<bool> generate_and_send_client_hello(
        asio::ip::tcp::socket& socket, const uint8_t* public_key, const uint8_t* private_key, reality::transcript& trans, std::error_code& ec) const;

    struct server_hello_res
    {
        bool ok;
        reality::handshake_keys hs_keys;
        const EVP_MD* negotiated_md;
        const EVP_CIPHER* negotiated_cipher;
        uint16_t cipher_suite;
    };

    static asio::awaitable<server_hello_res> process_server_hello(asio::ip::tcp::socket& socket,
                                                                  const uint8_t* private_key,
                                                                  reality::transcript& trans,
                                                                  std::error_code& ec);

    static asio::awaitable<std::pair<bool, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>> handshake_read_loop(
        asio::ip::tcp::socket& socket,
        const std::pair<std::vector<uint8_t>, std::vector<uint8_t>>& s_hs_keys,
        const reality::handshake_keys& hs_keys,
        reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        std::error_code& ec);

    static asio::awaitable<bool> send_client_finished(asio::ip::tcp::socket& socket,
                                                      const std::pair<std::vector<uint8_t>, std::vector<uint8_t>>& c_hs_keys,
                                                      const std::vector<uint8_t>& c_hs_secret,
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
    uint16_t listen_port_;
    std::string sni_;
    io_context_pool& pool_;
    std::vector<uint8_t> server_pub_key_;
    std::vector<std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> tunnel_pool_;
    std::mutex pool_mutex_;
    uint32_t next_tunnel_index_{0};
    uint32_t next_conn_id_{1};
    uint32_t next_session_id_{1};
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
