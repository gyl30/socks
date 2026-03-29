#ifndef CLIENT_TUNNEL_POOL_H
#define CLIENT_TUNNEL_POOL_H

#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <optional>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

namespace reality
{

enum class client_auth_mode : std::uint8_t;
struct client_handshake_result;
enum class fingerprint_type : std::uint8_t;

}    // namespace reality

namespace mux
{

struct config;
struct io_worker;
class io_context_pool;
class connection_context;
class mux_connection;

struct client_tunnel_connect_options
{
    std::string sni;
    std::string remote_host;
    std::string remote_port;
    std::vector<std::uint8_t> server_pub_key;
    std::vector<std::uint8_t> short_id_bytes;
    std::optional<reality::fingerprint_type> fingerprint_type;
    std::uint32_t max_handshake_records = 256;
    std::uint32_t tunnel_connections = 1;
    std::uint32_t connect_mark = 0;
};

class client_tunnel_pool : public std::enable_shared_from_this<client_tunnel_pool>
{
   public:
    client_tunnel_pool(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::shared_ptr<mux_connection> select_tunnel();
    [[nodiscard]] std::uint32_t next_session_id();

   private:
    [[nodiscard]] static client_tunnel_connect_options build_connect_options(const config& cfg);
    boost::asio::awaitable<void> connect_remote_loop(std::uint32_t index, io_worker& worker);

   private:
    const config& cfg_;
    io_context_pool& pool_;
    client_tunnel_connect_options options_;
    std::atomic<std::uint32_t> next_tunnel_index_{0};
    std::atomic<std::uint32_t> next_conn_id_{1};
    std::atomic<std::uint32_t> next_session_id_{1};
    std::mutex tunnel_mutex_;
    std::vector<std::shared_ptr<mux_connection>> tunnel_pool_;
    std::atomic<bool> stop_ = false;
};

}    // namespace mux

#endif
