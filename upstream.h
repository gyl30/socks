#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <memory>
#include <string>
#include <vector>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "mux_connection.h"
#include "client_tunnel_pool.h"

namespace mux
{

struct upstream_connect_result
{
    boost::system::error_code ec;
    boost::asio::ip::address bind_addr;
    uint16_t bind_port = 0;
    uint8_t socks_rep = 0;
    bool has_bind_endpoint = false;
};

class upstream
{
   public:
    virtual ~upstream() = default;

   public:
    virtual boost::asio::awaitable<void> close() = 0;
    virtual boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) = 0;
    [[nodiscard]] virtual boost::asio::awaitable<upstream_connect_result> connect(const std::string& host, uint16_t port) = 0;
    virtual boost::asio::awaitable<void> write(const std::vector<uint8_t>& data, boost::system::error_code& ec) = 0;
    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> read(std::vector<uint8_t>& buf, boost::system::error_code& ec) = 0;
};

[[nodiscard]] std::shared_ptr<upstream> make_direct_upstream(const boost::asio::any_io_executor& executor, connection_context ctx, const config& cfg);
[[nodiscard]] std::shared_ptr<upstream> make_proxy_upstream(std::shared_ptr<mux_connection> tunnel, connection_context ctx, const config& cfg);
[[nodiscard]] std::shared_ptr<upstream> make_proxy_upstream(std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                                            connection_context ctx,
                                                            const config& cfg);

}    // namespace mux

#endif
