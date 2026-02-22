#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <expected>
#include <optional>
#include <unordered_map>

#include <openssl/types.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include "config.h"
#include "ch_parser.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "key_rotator.h"
#include "log_context.h"
#include "cert_manager.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "reality_core.h"
#include "replay_cache.h"
#include "mux_connection.h"
#include "reality_messages.h"

namespace mux
{

class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    using tunnel_t = mux_tunnel_impl<boost::asio::ip::tcp::socket>;
    using tunnel_ptr_t = std::shared_ptr<tunnel_t>;
    using tunnel_list_t = std::vector<std::weak_ptr<tunnel_t>>;

    remote_server(io_context_pool& pool, const config& cfg);

    virtual ~remote_server();

    void start();

    void drain();

    void stop();

    [[nodiscard]] std::uint16_t listen_port() const
    {
        boost::system::error_code ec;
        const auto ep = acceptor_.local_endpoint(ec);
        if (ec)
        {
            return 0;
        }
        return ep.port();
    }
    [[nodiscard]] bool running() const
    {
        return started_.load(std::memory_order_acquire) && !stop_.load(std::memory_order_acquire) && acceptor_.is_open();
    }

    void set_certificate(const std::string& sni,
                         std::vector<std::uint8_t> cert_msg,
                         reality::server_fingerprint fp,
                         const std::string& trace_id = "");

   private:
    struct server_handshake_res;

    [[nodiscard]] bool ensure_acceptor_open();
    void stop_local(bool close_tunnels);
    [[nodiscard]] std::shared_ptr<tunnel_list_t> snapshot_active_tunnels() const;
    [[nodiscard]] std::size_t prune_expired_tunnels();
    [[nodiscard]] std::size_t active_tunnel_count() const;
    [[nodiscard]] std::shared_ptr<tunnel_list_t> detach_active_tunnels();
    void append_active_tunnel(const tunnel_ptr_t& tunnel);
    void track_connection_socket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket);
    void untrack_connection_socket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket);
    [[nodiscard]] std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> snapshot_tracked_connection_sockets();
    [[nodiscard]] std::size_t close_tracked_connection_sockets();

    boost::asio::awaitable<void> accept_loop();

    boost::asio::awaitable<void> handle(std::shared_ptr<boost::asio::ip::tcp::socket> s, std::uint32_t conn_id, std::string source_key);

    [[nodiscard]] bool try_reserve_connection_slot(const std::string& source_key);
    void release_connection_slot(const std::string& source_key);

    struct app_keys
    {
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_app_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_app_keys;
    };

    [[nodiscard]] static std::expected<app_keys, boost::system::error_code> derive_application_traffic_keys(const server_handshake_res& sh_res);

    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> create_tunnel(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& s,
        const server_handshake_res& sh_res,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_app_keys,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_app_keys,
        std::uint32_t conn_id,
        const connection_context& ctx);
    void install_syn_callback(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel, const connection_context& ctx);

    boost::asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel,
                                                        const connection_context& ctx,
                                                        std::uint32_t stream_id,
                                                        std::vector<std::uint8_t> payload,
                                                        boost::asio::io_context& io_context) const;

    struct initial_read_res
    {
        bool ok = false;
        bool allow_fallback = false;
        boost::system::error_code ec;
    };

    [[nodiscard]] boost::asio::awaitable<initial_read_res> read_initial_and_validate(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                                     const connection_context& ctx,
                                                                                     std::vector<std::uint8_t>& buf);

    [[nodiscard]] bool authenticate_client(const client_hello_info& info, const std::vector<std::uint8_t>& buf, const connection_context& ctx);

    struct selected_key_share
    {
        std::uint16_t group = 0;
        std::vector<std::uint8_t> x25519_pub;
    };

    [[nodiscard]] static std::optional<selected_key_share> select_key_share(const client_hello_info& info, const connection_context& ctx);

    struct server_handshake_res
    {
        bool ok = false;
        boost::system::error_code ec;
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

    boost::asio::awaitable<server_handshake_res> negotiate_reality(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                   const connection_context& ctx,
                                                                   std::vector<std::uint8_t>& initial_buf);

    [[nodiscard]] static connection_context build_connection_context(const std::shared_ptr<boost::asio::ip::tcp::socket>& s, std::uint32_t conn_id);
    [[nodiscard]] static connection_context build_stream_context(const connection_context& ctx, const syn_payload& syn);
    [[nodiscard]] static client_hello_info parse_client_hello(const std::vector<std::uint8_t>& initial_buf, std::string& client_sni);
    [[nodiscard]] static bool init_handshake_transcript(const std::vector<std::uint8_t>& initial_buf,
                                                        reality::transcript& trans,
                                                        const connection_context& ctx);
    boost::asio::awaitable<server_handshake_res> delay_and_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                    const std::vector<std::uint8_t>& initial_buf,
                                                                    const connection_context& ctx,
                                                                    const std::string& client_sni);
    static boost::asio::awaitable<void> send_stream_reset(const std::shared_ptr<mux_connection>& connection, std::uint32_t stream_id);
    static boost::asio::awaitable<void> reject_stream_for_limit(const std::shared_ptr<mux_connection>& connection,
                                                                const connection_context& ctx,
                                                                std::uint32_t stream_id);
    static boost::asio::awaitable<void> handle_tcp_connect_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                                  const connection_context& stream_ctx,
                                                                  std::uint32_t stream_id,
                                                                  const syn_payload& syn,
                                                                  std::size_t payload_size,
                                                                  boost::asio::io_context& io_context);
    boost::asio::awaitable<void> handle_udp_associate_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                             const connection_context& stream_ctx,
                                                             std::uint32_t stream_id,
                                                             boost::asio::io_context& io_context) const;

    struct key_share_result
    {
        std::vector<std::uint8_t> sh_shared;
        std::vector<std::uint8_t> key_share_data;
        std::uint16_t key_share_group;
    };

    [[nodiscard]] static std::expected<key_share_result, boost::system::error_code> derive_server_key_share(const client_hello_info& info,
                                                                                                            const std::uint8_t* public_key,
                                                                                                            const std::uint8_t* private_key,
                                                                                                            const connection_context& ctx);

    boost::asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                            const client_hello_info& info,
                                                                            reality::transcript& trans,
                                                                            const connection_context& ctx);
    [[nodiscard]] certificate_target resolve_certificate_target(const client_hello_info& info) const;
    boost::asio::awaitable<std::optional<certificate_material>> load_certificate_material(const certificate_target& target,
                                                                                          const connection_context& ctx);
    static boost::asio::awaitable<boost::system::error_code> send_server_hello_flight(const std::shared_ptr<boost::asio::ip::tcp::socket>& s,
                                                                                      const std::vector<std::uint8_t>& sh_msg,
                                                                                      const std::vector<std::uint8_t>& flight2_enc,
                                                                                      const connection_context& ctx,
                                                                                      std::uint32_t timeout_sec = 0);

    [[nodiscard]] static boost::asio::awaitable<boost::system::error_code> verify_client_finished(
        std::shared_ptr<boost::asio::ip::tcp::socket> s,
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
        const reality::handshake_keys& hs_keys,
        const reality::transcript& trans,
        const EVP_CIPHER* cipher,
        const EVP_MD* md,
        const connection_context& ctx,
        std::uint32_t timeout_sec = 0);

    [[nodiscard]] std::pair<std::string, std::string> find_fallback_target_by_sni(const std::string& sni) const;

    boost::asio::awaitable<void> handle_fallback(const std::shared_ptr<boost::asio::ip::tcp::socket>& s,
                                                 const std::vector<std::uint8_t>& buf,
                                                 const connection_context& ctx,
                                                 const std::string& sni);

    struct fallback_guard_state;

    [[nodiscard]] bool consume_fallback_token(const connection_context& ctx);
    void record_fallback_result(const connection_context& ctx, bool success);
    void cleanup_fallback_guard_state_locked(const std::chrono::steady_clock::time_point& now);
    void evict_fallback_guard_source_if_needed_locked(const std::string& source_key);
    [[nodiscard]] fallback_guard_state& get_or_init_fallback_guard_state_locked(const std::string& source_key,
                                                                                const std::chrono::steady_clock::time_point& now);
    void refill_fallback_tokens_locked(fallback_guard_state& state, const std::chrono::steady_clock::time_point& now) const;
    [[nodiscard]] static bool fallback_guard_allows_request_locked(fallback_guard_state& state, const std::chrono::steady_clock::time_point& now);
    [[nodiscard]] static std::string fallback_guard_key(const connection_context& ctx);
    [[nodiscard]] std::string connection_limit_source_key(const std::shared_ptr<boost::asio::ip::tcp::socket>& s) const;

   private:
    struct fallback_guard_state
    {
        double tokens = 0;
        std::uint32_t consecutive_failures = 0;
        std::chrono::steady_clock::time_point last_refill;
        std::chrono::steady_clock::time_point last_seen;
        std::chrono::steady_clock::time_point circuit_open_until;
    };

    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::endpoint inbound_endpoint_;
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
    config::reality_t::fallback_guard_t fallback_guard_config_;
    std::mutex fallback_guard_mu_;
    std::unordered_map<std::string, fallback_guard_state> fallback_guard_states_;
    config::timeout_t timeout_config_;
    config::queues_t queues_config_;
    std::atomic<std::uint32_t> active_connection_slots_{0};
    std::mutex connection_slot_mu_;
    std::unordered_map<std::string, std::uint32_t> active_source_connection_slots_;
    std::mutex tracked_connection_socket_mu_;
    std::unordered_map<boost::asio::ip::tcp::socket*, std::weak_ptr<boost::asio::ip::tcp::socket>> tracked_connection_sockets_;
    std::shared_ptr<tunnel_list_t> active_tunnels_ = std::make_shared<tunnel_list_t>();
    config::limits_t limits_config_;
    config::heartbeat_t heartbeat_config_;
    std::atomic<bool> started_{false};
    std::atomic<bool> stop_{false};
};

}    // namespace mux

#endif
