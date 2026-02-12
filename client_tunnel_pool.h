#ifndef CLIENT_TUNNEL_POOL_H
#define CLIENT_TUNNEL_POOL_H

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "config.h"
#include "mux_tunnel.h"
#include "context_pool.h"
#include "reality_core.h"
#include "reality_messages.h"

namespace reality
{
class transcript;
}

namespace mux
{

class client_tunnel_pool : public std::enable_shared_from_this<client_tunnel_pool>
{
   public:
    client_tunnel_pool(io_context_pool& pool, const config& cfg, std::uint32_t mark);

    void start();

    void stop();

    [[nodiscard]] bool valid() const { return auth_config_valid_; }

    [[nodiscard]] std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> select_tunnel();

    [[nodiscard]] std::uint32_t next_session_id();

   private:
    struct handshake_result
    {
        std::vector<std::uint8_t> c_app_secret;
        std::vector<std::uint8_t> s_app_secret;
        std::uint16_t cipher_suite = 0;
        const EVP_MD* md = nullptr;
        const EVP_CIPHER* cipher = nullptr;
    };

    asio::awaitable<void> connect_remote_loop(std::uint32_t index, asio::io_context& io_context);

    [[nodiscard]] asio::awaitable<bool> establish_tunnel_for_connection(
        std::uint32_t index,
        asio::io_context& io_context,
        std::uint32_t cid,
        const std::string& trace_id,
        const std::shared_ptr<asio::ip::tcp::socket>& socket,
        std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel);

    asio::awaitable<void> handle_connection_failure(std::uint32_t index,
                                                    const std::shared_ptr<asio::ip::tcp::socket>& socket,
                                                    const std::error_code& ec,
                                                    const char* stage,
                                                    asio::io_context& io_context);

    [[nodiscard]] asio::awaitable<bool> tcp_connect(asio::io_context& io_context, asio::ip::tcp::socket& socket, std::error_code& ec) const;
    [[nodiscard]] asio::awaitable<bool> try_connect_endpoint(asio::ip::tcp::socket& socket,
                                                             const asio::ip::tcp::endpoint& endpoint,
                                                             std::error_code& ec) const;

    [[nodiscard]] asio::awaitable<std::pair<bool, handshake_result>> perform_reality_handshake(asio::ip::tcp::socket& socket,
                                                                                               std::error_code& ec) const;

    [[nodiscard]] std::shared_ptr<asio::ip::tcp::socket> create_pending_socket(asio::io_context& io_context, std::uint32_t index);
    void clear_pending_socket_if_match(std::uint32_t index, const std::shared_ptr<asio::ip::tcp::socket>& socket);
    void close_pending_socket(std::size_t index, std::shared_ptr<asio::ip::tcp::socket> pending_socket);
    void release_all_pending_sockets();
    void release_all_tunnels();
    void publish_tunnel(std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel);
    void clear_tunnel_if_match(std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel);
    [[nodiscard]] std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> build_tunnel(
        asio::ip::tcp::socket socket, asio::io_context& io_context, std::uint32_t cid, const handshake_result& handshake_ret, const std::string& trace_id) const;

    [[nodiscard]] asio::awaitable<bool> generate_and_send_client_hello(asio::ip::tcp::socket& socket,
                                                                       const std::uint8_t* public_key,
                                                                       const std::uint8_t* private_key,
                                                                       const reality::fingerprint_spec& spec,
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
        const bool strict_cert_verify,
        reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        std::error_code& ec);

    [[nodiscard]] static asio::awaitable<bool> send_client_finished(asio::ip::tcp::socket& socket,
                                                                    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                                    const std::vector<std::uint8_t>& c_hs_secret,
                                                                    const reality::transcript& trans,
                                                                    const EVP_CIPHER* cipher,
                                                                    const EVP_MD* md,
                                                                    std::error_code& ec);

    asio::awaitable<void> wait_remote_retry(asio::io_context& io_context);

   private:
    std::atomic<bool> stop_{false};
    std::uint32_t mark_ = 0;
    std::string remote_host_;
    std::string remote_port_;
    std::string sni_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::array<std::uint8_t, 3> client_ver_{1, 0, 0};
    bool auth_config_valid_ = true;
    bool strict_cert_verify_ = false;
    std::optional<reality::fingerprint_type> fingerprint_type_;
    io_context_pool& pool_;
    std::vector<std::uint8_t> server_pub_key_;
    std::vector<std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> tunnel_pool_;
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> pending_sockets_;
    std::vector<asio::io_context*> tunnel_io_contexts_;
    std::atomic<std::uint32_t> next_tunnel_index_{0};
    std::atomic<std::uint32_t> next_conn_id_{1};
    std::atomic<std::uint32_t> next_session_id_{1};
    config::timeout_t timeout_config_;
    config::limits_t limits_config_;
    config::heartbeat_t heartbeat_config_;
};

}    // namespace mux

#endif
