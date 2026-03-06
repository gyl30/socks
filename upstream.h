#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "protocol.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"

namespace mux
{

class client_tunnel_pool;

class upstream
{
   public:
    virtual ~upstream() = default;

   public:
    virtual boost::asio::awaitable<void> close() = 0;
    virtual boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) = 0;
    virtual boost::asio::awaitable<void> connect(const std::string& host, std::uint16_t port, boost::system::error_code& ec) = 0;
    virtual boost::asio::awaitable<void> write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec) = 0;
    [[nodiscard]] virtual boost::asio::awaitable<std::size_t> read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec) = 0;
    [[nodiscard]] virtual bool get_bind_endpoint(boost::asio::ip::address& addr, std::uint16_t& port, boost::system::error_code& ec) const = 0;
    [[nodiscard]] virtual std::uint8_t suggested_socks_rep(const boost::system::error_code& ec) const = 0;
};

class direct_upstream : public upstream
{
   public:
    explicit direct_upstream(boost::asio::io_context& io_context, connection_context ctx, const config& cfg)
        : cfg_(cfg), ctx_(std::move(ctx)), socket_(io_context), resolver_(io_context)
    {
    }

   public:
    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> connect(const std::string& host, std::uint16_t port, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec) override;
    [[nodiscard]] bool get_bind_endpoint(boost::asio::ip::address& addr, std::uint16_t& port, boost::system::error_code& ec) const override;
    [[nodiscard]] std::uint8_t suggested_socks_rep(const boost::system::error_code& ec) const override;

   private:
    const config& cfg_;
    connection_context ctx_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
};

class proxy_upstream : public upstream
{
   public:
    explicit proxy_upstream(std::shared_ptr<mux_tunnel_impl> tunnel, boost::asio::io_context& io_context, connection_context ctx);
    explicit proxy_upstream(std::shared_ptr<client_tunnel_pool> tunnel_pool, boost::asio::io_context& io_context, connection_context ctx);

   public:
    boost::asio::awaitable<void> close() override;
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override;
    boost::asio::awaitable<void> connect(const std::string& host, std::uint16_t port, boost::system::error_code& ec) override;
    boost::asio::awaitable<void> write(const std::vector<std::uint8_t>& data, boost::system::error_code& ec) override;
    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::vector<std::uint8_t>& buf, boost::system::error_code& ec) override;
    [[nodiscard]] bool get_bind_endpoint(boost::asio::ip::address& addr, std::uint16_t& port, boost::system::error_code& ec) const override;
    [[nodiscard]] std::uint8_t suggested_socks_rep(const boost::system::error_code& ec) const override;

   private:
    boost::asio::awaitable<void> send_syn_request(const std::shared_ptr<mux_stream>& stream,
                                                  const std::string& host,
                                                  std::uint16_t port,
                                                  boost::system::error_code& ec);
    boost::asio::awaitable<bool> wait_connect_ack(const std::shared_ptr<mux_stream>& stream, const std::string& host, std::uint16_t port);

   private:
    connection_context ctx_;
    std::shared_ptr<mux_stream> stream_;
    boost::asio::io_context& io_context_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<mux_tunnel_impl> tunnel_;
    boost::asio::ip::address bind_addr_;
    std::uint16_t bind_port_ = 0;
    bool fin_sent_ = false;
    bool reset_received_ = false;
    std::uint8_t last_remote_rep_ = socks::kRepSuccess;
    bool has_bind_endpoint_ = false;
    using channel_type =
        boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::pair<frame_header, std::vector<uint8_t>>)>;
    std::unique_ptr<channel_type> recv_channel_;
};

}    // namespace mux

#endif
