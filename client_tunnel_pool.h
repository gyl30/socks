#ifndef CLIENT_TUNNEL_POOL_H
#define CLIENT_TUNNEL_POOL_H

#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <utility>
#include <expected>
#include <optional>

#include <openssl/types.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "reality_fingerprint.h"

extern "C"
{
}

#include "config.h"
#include "mux_tunnel.h"
#include "task_group.h"
#include "context_pool.h"
#include "reality_core.h"

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
    client_tunnel_pool(io_context_pool& pool, const config& cfg, task_group& group);

    void start();

    void stop() {};

    [[nodiscard]] std::shared_ptr<mux_tunnel_impl> select_tunnel();
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<mux_tunnel_impl>> wait_for_tunnel(boost::asio::io_context& io_context,
                                                                                            boost::system::error_code& ec);

    [[nodiscard]] std::uint32_t next_session_id();

   private:
    enum class connect_loop_action : std::uint8_t
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
    [[nodiscard]] boost::asio::awaitable<bool> establish_tunnel_for_connection(std::uint32_t index,
                                                                               boost::asio::io_context& io_context,
                                                                               std::uint32_t cid,
                                                                               const std::string& trace_id,
                                                                               const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                               std::shared_ptr<mux_tunnel_impl>& tunnel);

    [[nodiscard]] boost::asio::awaitable<void> tcp_connect_remote(boost::asio::io_context& io_context,
                                                                  boost::asio::ip::tcp::socket& socket,
                                                                  const connection_context& ctx,
                                                                  boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::awaitable<handshake_result> perform_reality_handshake(boost::asio::ip::tcp::socket& socket,
                                                                                     boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::awaitable<handshake_result> perform_reality_handshake_with_timeout(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const connection_context& ctx, boost::system::error_code& ec) const;
    [[nodiscard]] std::shared_ptr<mux_tunnel_impl> build_tunnel(boost::asio::ip::tcp::socket socket,
                                                                boost::asio::io_context& io_context,
                                                                std::uint32_t cid,
                                                                const handshake_result& handshake_ret,
                                                                const std::string& trace_id) const;

    [[nodiscard]] boost::asio::awaitable<void> generate_and_send_client_hello(
        boost::asio::ip::tcp::socket& socket,
        const std::uint8_t* public_key,
        const std::uint8_t* private_key,
        const reality::fingerprint_spec& spec,
        reality::transcript& trans,
        std::vector<std::uint8_t>& auth_key,
        boost::system::error_code& ec) const;

    struct server_hello_res
    {
        reality::handshake_keys hs_keys;
        const EVP_MD* negotiated_md = nullptr;
        const EVP_CIPHER* negotiated_cipher = nullptr;
        std::uint16_t cipher_suite = 0;
    };

    [[nodiscard]] boost::asio::awaitable<server_hello_res> process_server_hello(
        boost::asio::ip::tcp::socket& socket, const std::uint8_t* private_key, reality::transcript& trans, boost::system::error_code& ec) const;

    [[nodiscard]] static boost::asio::awaitable<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> handshake_read_loop(
        boost::asio::ip::tcp::socket& socket,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
        const reality::handshake_keys& hs_keys,
        const std::vector<std::uint8_t>& auth_key,
        const std::string& sni,
        reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        std::uint32_t max_handshake_records,
        std::uint32_t read_timeout_sec,
        boost::system::error_code& ec);

    [[nodiscard]] static boost::asio::awaitable<void> send_client_finished(
        boost::asio::ip::tcp::socket& socket,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
        const std::vector<std::uint8_t>& c_hs_secret,
        const reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        std::uint32_t write_timeout_sec,
        boost::system::error_code& ec);

   private:
    std::string sni_;
    std::string remote_host_;
    std::string remote_port_;
    const config& cfg_;
    task_group& group_;
    io_context_pool& pool_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::atomic<std::uint32_t> next_tunnel_index_{0};
    std::atomic<std::uint32_t> next_conn_id_{1};
    std::atomic<std::uint32_t> next_session_id_{1};
    std::uint32_t max_handshake_records_ = 256;
    std::vector<std::uint8_t> server_pub_key_;
    std::optional<reality::fingerprint_type> fingerprint_type_;
    std::mutex tunnel_mutex_;
    std::vector<std::shared_ptr<mux_tunnel_impl>> tunnel_pool_;
};

}    // namespace mux

#endif
