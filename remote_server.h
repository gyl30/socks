#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <vector>
#include <mutex>
#include <random>

#include "config.h"
#include "log_context.h"
#include "protocol.h"
#include "ch_parser.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "key_rotator.h"
#include "replay_cache.h"
#include "cert_fetcher.h"
#include "cert_manager.h"
#include "context_pool.h"
#include "remote_session.h"
#include "tls_record_layer.h"
#include "tls_key_schedule.h"
#include "reality_messages.h"
#include "reality_messages.h"
#include "remote_udp_session.h"
#include "constants.h"

namespace mux
{
class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    remote_server(io_context_pool &pool,
                  uint16_t port,
                  std::vector<config::fallback_entry> fbs,
                  const std::string &key,
                  const config::timeout_t &timeout_cfg = {});

    ~remote_server();

    void start();

    void stop();

   private:
    asio::awaitable<void> accept_loop();

    asio::awaitable<void> handle(std::shared_ptr<asio::ip::tcp::socket> s, uint32_t conn_id);

    asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel,
                                                 const connection_context &ctx,
                                                 uint32_t stream_id,
                                                 std::vector<uint8_t> payload) const;

    static asio::awaitable<bool> read_initial_and_validate(std::shared_ptr<asio::ip::tcp::socket> s,
                                                           const connection_context &ctx,
                                                           std::vector<uint8_t> &buf);

    std::pair<bool, std::vector<uint8_t>> authenticate_client(const client_hello_info_t &info,
                                                              const std::vector<uint8_t> &buf,
                                                              const connection_context &ctx);

    struct server_handshake_res
    {
        bool ok;
        reality::handshake_keys hs_keys;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> s_hs_keys;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_hs_keys;
        const EVP_CIPHER *cipher;
        const EVP_MD *negotiated_md;
    };
    asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                     const client_hello_info_t &info,
                                                                     reality::transcript &trans,
                                                                     const std::vector<uint8_t> &auth_key,
                                                                     const connection_context &ctx,
                                                                     std::error_code &ec);

    static asio::awaitable<bool> verify_client_finished(std::shared_ptr<asio::ip::tcp::socket> s,
                                                        const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &c_hs_keys,
                                                        const reality::handshake_keys &hs_keys,
                                                        const reality::transcript &trans,
                                                        const EVP_CIPHER *cipher,
                                                        const EVP_MD *md,
                                                        const connection_context &ctx,
                                                        std::error_code &ec);
    std::pair<std::string, std::string> find_fallback_target_by_sni(const std::string &sni) const;
    static asio::awaitable<void> fallback_failed_timer(uint32_t conn_id, asio::any_io_executor ex);

    static asio::awaitable<void> fallback_failed(const std::shared_ptr<asio::ip::tcp::socket> &s);

    asio::awaitable<void> handle_fallback(const std::shared_ptr<asio::ip::tcp::socket> &s,
                                          std::vector<uint8_t> buf,
                                          const connection_context &ctx,
                                          const std::string &sni);

   private:
    io_context_pool &pool_;
    asio::ip::tcp::acceptor acceptor_;
    std::vector<uint8_t> private_key_;
    reality::cert_manager cert_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
    replay_cache replay_cache_;
    reality::key_rotator key_rotator_;
    std::mutex tunnels_mutex_;
    std::vector<config::fallback_entry> fallbacks_;
    config::timeout_t timeout_config_;
    std::vector<std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> active_tunnels_;
};
}    // namespace mux
#endif
