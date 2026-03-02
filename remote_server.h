#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <openssl/types.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include "config.h"
#include "ch_parser.h"
#include "task_group.h"
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
    remote_server(io_context_pool& pool, const config& cfg);
    virtual ~remote_server();

   public:
    void start();
    void stop();

   private:
    struct server_handshake_res
    {
        reality::handshake_keys hs_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_hs_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_hs_keys;
        const EVP_CIPHER* cipher = nullptr;
        const EVP_MD* negotiated_md = nullptr;
        std::vector<std::uint8_t> handshake_hash;
    };

   private:
    boost::asio::awaitable<void> accept_loop();
    boost::asio::awaitable<void> handle(std::shared_ptr<boost::asio::ip::tcp::socket> s, std::uint32_t conn_id);

    boost::asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                            const client_hello_info& info,
                                                                            reality::transcript& trans,
                                                                            const connection_context& ctx,
                                                                            boost::system::error_code& ec);

    boost::asio::awaitable<void> verify_client_finished(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                        const server_handshake_res& response,
                                                        const reality::transcript& trans,
                                                        const connection_context& ctx,
                                                        boost::system::error_code& ec) const;

    boost::asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl> tunnel,
                                                        const connection_context& ctx,
                                                        mux_frame frame) const;
    std::pair<std::string, std::string> find_fallback_target_by_sni(const std::string& sni) const;

   private:
    const config& cfg_;
    io_context_pool& pool_;
    boost::asio::io_context& io_context_;
    task_group group_{io_context_};
    std::vector<std::uint8_t> private_key_;
    std::vector<std::uint8_t> short_id_bytes_;
    std::uint32_t next_conn_id_{1};
    replay_cache replay_cache_;
    reality::key_rotator key_rotator_;
    reality::cert_manager cert_manager_;
};

}    // namespace mux

#endif
