#ifndef CLIENT_TUNNEL_POOL_H
#define CLIENT_TUNNEL_POOL_H

#include <mutex>
#include <atomic>
#include <memory>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

namespace mux
{

struct config;
struct io_worker;
class io_context_pool;
class connection_context;
class mux_connection;

class client_tunnel_pool : public std::enable_shared_from_this<client_tunnel_pool>
{
   public:
    client_tunnel_pool(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::shared_ptr<mux_connection> select_tunnel();

   private:
    boost::asio::awaitable<void> connect_remote_loop(uint32_t index, io_worker& worker);

   private:
    const config& cfg_;
    io_context_pool& pool_;
    std::atomic<uint32_t> next_tunnel_index_{0};
    std::atomic<uint32_t> next_conn_id_{1};
    std::mutex tunnel_mutex_;
    std::vector<std::shared_ptr<mux_connection>> tunnel_pool_;
    std::atomic<bool> stop_ = false;
};

}    // namespace mux

#endif
