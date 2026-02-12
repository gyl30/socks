#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <array>
#include <atomic>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <optional>
#include <system_error>
#include <unordered_set>

#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "config.h"
#include "protocol.h"
#include "ch_parser.h"
#include "constants.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "key_rotator.h"
#include "log_context.h"
#include "cert_fetcher.h"
#include "cert_manager.h"
#include "context_pool.h"
#include "replay_cache.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"

namespace mux
{

class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    remote_server(io_context_pool& pool, const config& cfg);

    virtual ~remote_server();

    void start();

    void stop();

    [[nodiscard]] std::uint16_t listen_port() const { return acceptor_.local_endpoint().port(); }

    void set_certificate(std::string sni,
                         std::vector<std::uint8_t> cert_msg,
                         reality::server_fingerprint fp,
                         const std::string& trace_id = "");

   private:
    struct server_handshake_res;

    asio::awaitable<void> accept_loop();

    asio::awaitable<void> handle(std::shared_ptr<asio::ip::tcp::socket> s, const std::uint32_t conn_id);

    [[nodiscard]] bool derive_application_traffic_keys(
        const server_handshake_res& sh_res,
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_app_keys,
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_app_keys,
        std::error_code& ec) const;
    asio::awaitable<bool> reject_connection_if_over_limit(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                          const std::vector<std::uint8_t>& initial_buf,
                                                          const connection_context& ctx);
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> create_tunnel(
        const std::shared_ptr<asio::ip::tcp::socket>& s,
        const server_handshake_res& sh_res,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_app_keys,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_app_keys,
        std::uint32_t conn_id,
        const connection_context& ctx);
    void install_syn_callback(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel, const connection_context& ctx);

    asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel,
                                                 const connection_context& ctx,
                                                 const std::uint32_t stream_id,
                                                 std::vector<std::uint8_t> payload,
                                                 asio::io_context& io_context) const;

    [[nodiscard]] static asio::awaitable<bool> read_initial_and_validate(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                         const connection_context& ctx,
                                                                         std::vector<std::uint8_t>& buf);

    [[nodiscard]] bool authenticate_client(const client_hello_info& info, const std::vector<std::uint8_t>& buf, const connection_context& ctx);

    struct selected_key_share
    {
        std::uint16_t group = 0;
        std::vector<std::uint8_t> x25519_pub;
    };

    [[nodiscard]] std::optional<selected_key_share> select_key_share(const client_hello_info& info, const connection_context& ctx) const;

    struct server_handshake_res
    {
        bool ok = false;
        reality::handshake_keys hs_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_hs_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_hs_keys;
        const EVP_CIPHER* cipher = nullptr;
        const EVP_MD* negotiated_md = nullptr;
        std::vector<std::uint8_t> handshake_hash;
    };

    struct certificate_target
    {
        std::string cert_sni;
        std::string fetch_host;
        std::uint16_t fetch_port = 443;
    };

    struct certificate_material
    {
        std::vector<std::uint8_t> cert_msg;
        reality::server_fingerprint fingerprint;
    };

    asio::awaitable<server_handshake_res> negotiate_reality(std::shared_ptr<asio::ip::tcp::socket> s,
                                                            const connection_context& ctx,
                                                            std::vector<std::uint8_t>& initial_buf);

    asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                     const client_hello_info& info,
                                                                     reality::transcript& trans,
                                                                     const connection_context& ctx,
                                                                     std::error_code& ec);
    [[nodiscard]] static connection_context build_connection_context(const std::shared_ptr<asio::ip::tcp::socket>& s, std::uint32_t conn_id);
    [[nodiscard]] static connection_context build_stream_context(const connection_context& ctx, const syn_payload& syn);
    [[nodiscard]] static client_hello_info parse_client_hello(const std::vector<std::uint8_t>& initial_buf, std::string& client_sni);
    [[nodiscard]] bool init_handshake_transcript(const std::vector<std::uint8_t>& initial_buf,
                                                 reality::transcript& trans,
                                                 const connection_context& ctx) const;
    asio::awaitable<server_handshake_res> delay_and_fallback(std::shared_ptr<asio::ip::tcp::socket> s,
                                                             const std::vector<std::uint8_t>& initial_buf,
                                                             const connection_context& ctx,
                                                             const std::string& client_sni) const;
    asio::awaitable<void> send_stream_reset(const std::shared_ptr<mux_connection>& connection, std::uint32_t stream_id) const;
    asio::awaitable<void> reject_stream_for_limit(const std::shared_ptr<mux_connection>& connection,
                                                  const connection_context& ctx,
                                                  std::uint32_t stream_id) const;
    asio::awaitable<void> handle_tcp_connect_stream(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel,
                                                    const connection_context& stream_ctx,
                                                    std::uint32_t stream_id,
                                                    const syn_payload& syn,
                                                    std::size_t payload_size,
                                                    asio::io_context& io_context) const;
    asio::awaitable<void> handle_udp_associate_stream(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel,
                                                      const connection_context& stream_ctx,
                                                      std::uint32_t stream_id,
                                                      asio::io_context& io_context) const;
    [[nodiscard]] bool derive_server_key_share(const client_hello_info& info,
                                               const std::uint8_t* public_key,
                                               const std::uint8_t* private_key,
                                               const connection_context& ctx,
                                               std::vector<std::uint8_t>& sh_shared,
                                               std::vector<std::uint8_t>& key_share_data,
                                               std::uint16_t& key_share_group,
                                               std::error_code& ec) const;
    [[nodiscard]] certificate_target resolve_certificate_target(const client_hello_info& info) const;
    asio::awaitable<std::optional<certificate_material>> load_certificate_material(const certificate_target& target,
                                                                                   const connection_context& ctx);
    asio::awaitable<bool> send_server_hello_flight(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                   const std::vector<std::uint8_t>& sh_msg,
                                                   const std::vector<std::uint8_t>& flight2_enc,
                                                   const connection_context& ctx,
                                                   std::error_code& ec) const;

    [[nodiscard]] static asio::awaitable<bool> verify_client_finished(
        std::shared_ptr<asio::ip::tcp::socket> s,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
        const reality::handshake_keys& hs_keys,
        const reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        const connection_context& ctx,
        std::error_code& ec);

    [[nodiscard]] std::pair<std::string, std::string> find_fallback_target_by_sni(const std::string& sni) const;

    static asio::awaitable<void> fallback_failed_timer(std::uint32_t conn_id, asio::io_context& io_context);

    static asio::awaitable<void> fallback_failed(const std::shared_ptr<asio::ip::tcp::socket>& s);

    asio::awaitable<void> handle_fallback(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                          const std::vector<std::uint8_t>& buf,
                                          const connection_context& ctx,
                                          const std::string& sni) const;

   private:
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::vector<std::uint8_t> private_key_;
    std::vector<std::uint8_t> short_id_bytes_;
    bool auth_config_valid_ = true;
    reality::cert_manager cert_manager_;
    std::atomic<std::uint32_t> next_conn_id_{1};
    replay_cache replay_cache_;
    reality::key_rotator key_rotator_;
    std::vector<config::fallback_entry> fallbacks_;
    std::string fallback_dest_host_;
    std::string fallback_dest_port_;
    std::string fallback_type_;
    bool fallback_dest_valid_ = false;
    config::timeout_t timeout_config_;
    std::vector<std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> active_tunnels_;
    config::limits_t limits_config_;
    config::heartbeat_t heartbeat_config_;
    std::atomic<bool> started_{false};
    std::atomic<bool> stop_{false};
};

}    // namespace mux

#endif
