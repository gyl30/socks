#ifndef CLIENT_TUNNEL_POOL_H
#define CLIENT_TUNNEL_POOL_H

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <expected>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

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

class connection_context;

class client_tunnel_pool : public std::enable_shared_from_this<client_tunnel_pool>
{
   public:
    client_tunnel_pool(io_context_pool& pool, const config& cfg, std::uint32_t mark);

    void start();

    void stop();

    [[nodiscard]] bool valid() const { return auth_config_valid_; }

    [[nodiscard]] std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> select_tunnel();

    [[nodiscard]] std::uint32_t next_session_id();

   private:
    enum class connect_loop_action
    {
        kRunTunnel,
        kRetryLater,
        kStopLoop,
    };

    struct handshake_result
    {
        std::vector<std::uint8_t> c_app_secret;
        std::vector<std::uint8_t> s_app_secret;
        std::uint16_t cipher_suite = 0;
        const EVP_MD* md = nullptr;
        const EVP_CIPHER* cipher = nullptr;
    };

    boost::asio::awaitable<void> connect_remote_loop(std::uint32_t index, boost::asio::io_context& io_context);
    [[nodiscard]] connect_loop_action prepare_tunnel_for_run(std::uint32_t index,
                                                             const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                             const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel);

    [[nodiscard]] boost::asio::awaitable<bool> establish_tunnel_for_connection(
        std::uint32_t index,
        boost::asio::io_context& io_context,
        std::uint32_t cid,
        const std::string& trace_id,
        const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
        std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel);

    boost::asio::awaitable<void> handle_connection_failure(std::uint32_t index,
                                                    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                    const boost::system::error_code& ec,
                                                    const char* stage,
                                                    const connection_context& ctx,
                                                    boost::asio::io_context& io_context);

    [[nodiscard]] boost::asio::awaitable<std::expected<void, boost::system::error_code>> tcp_connect(
        boost::asio::io_context& io_context, boost::asio::ip::tcp::socket& socket, const connection_context& ctx) const;
    [[nodiscard]] boost::asio::awaitable<std::expected<void, boost::system::error_code>> tcp_connect(
        boost::asio::io_context& io_context, boost::asio::ip::tcp::socket& socket) const;
    [[nodiscard]] boost::asio::awaitable<std::expected<void, boost::system::error_code>> try_connect_endpoint(boost::asio::ip::tcp::socket& socket,
                                                                                             const boost::asio::ip::tcp::endpoint& endpoint) const;

    [[nodiscard]] boost::asio::awaitable<std::expected<handshake_result, boost::system::error_code>> perform_reality_handshake(boost::asio::ip::tcp::socket& socket) const;
    [[nodiscard]] boost::asio::awaitable<std::expected<handshake_result, boost::system::error_code>> perform_reality_handshake_with_timeout(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const connection_context& ctx) const;
    [[nodiscard]] boost::asio::awaitable<std::expected<handshake_result, boost::system::error_code>> perform_reality_handshake_with_timeout(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const;
    [[nodiscard]] std::shared_ptr<boost::asio::ip::tcp::socket> create_pending_socket(boost::asio::io_context& io_context, std::uint32_t index);
    void clear_pending_socket_if_match(std::uint32_t index, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket);
    void close_pending_socket(std::size_t index, std::shared_ptr<boost::asio::ip::tcp::socket> pending_socket);
    void release_all_pending_sockets();
    void release_all_tunnels();
    [[nodiscard]] bool publish_tunnel(std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel);
    void clear_tunnel_if_match(std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel);
    [[nodiscard]] std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> build_tunnel(
        boost::asio::ip::tcp::socket socket, boost::asio::io_context& io_context, std::uint32_t cid, const handshake_result& handshake_ret, const std::string& trace_id) const;

    [[nodiscard]] boost::asio::awaitable<std::expected<void, boost::system::error_code>> generate_and_send_client_hello(boost::asio::ip::tcp::socket& socket,
                                                                       const std::uint8_t* public_key,
                                                                       const std::uint8_t* private_key,
                                                                       const reality::fingerprint_spec& spec,
                                                                       reality::transcript& trans) const;

    struct server_hello_res
    {
        bool ok = false;
        reality::handshake_keys hs_keys;
        const EVP_MD* negotiated_md = nullptr;
        const EVP_CIPHER* negotiated_cipher = nullptr;
        std::uint16_t cipher_suite = 0;
    };

    [[nodiscard]] static boost::asio::awaitable<std::expected<server_hello_res, boost::system::error_code>> process_server_hello(boost::asio::ip::tcp::socket& socket,
                                                                                const std::uint8_t* private_key,
                                                                                reality::transcript& trans);

    [[nodiscard]] static boost::asio::awaitable<std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code>> handshake_read_loop(
        boost::asio::ip::tcp::socket& socket,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
        const reality::handshake_keys& hs_keys,
        const bool strict_cert_verify,
        const std::string& sni,
        reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md);

    [[nodiscard]] static boost::asio::awaitable<std::expected<void, boost::system::error_code>> send_client_finished(boost::asio::ip::tcp::socket& socket,
                                                                    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                                    const std::vector<std::uint8_t>& c_hs_secret,
                                                                    const reality::transcript& trans,
                                                                    const EVP_CIPHER* cipher,
                                                                    const EVP_MD* md);

    boost::asio::awaitable<void> wait_remote_retry(boost::asio::io_context& io_context);

   private:
    std::atomic<bool> stop_{false};
    std::uint32_t mark_ = 0;
    std::string remote_host_;
    std::string remote_port_;
    std::string sni_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::array<std::uint8_t, 3> client_ver_{1, 0, 0};
    bool auth_config_valid_ = true;
    bool strict_cert_verify_ = true;
    std::optional<reality::fingerprint_type> fingerprint_type_;
    io_context_pool& pool_;
    std::vector<std::uint8_t> server_pub_key_;
    std::vector<std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>> tunnel_pool_;
    std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> pending_sockets_;
    std::vector<boost::asio::io_context*> tunnel_io_contexts_;
    std::atomic<std::uint32_t> next_tunnel_index_{0};
    std::atomic<std::uint32_t> next_conn_id_{1};
    std::atomic<std::uint32_t> next_session_id_{1};
    config::timeout_t timeout_config_;
    config::limits_t limits_config_;
    config::heartbeat_t heartbeat_config_;
};

}    // namespace mux

#endif
