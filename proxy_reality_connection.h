#ifndef PROXY_REALITY_CONNECTION_H
#define PROXY_REALITY_CONNECTION_H

#include <span>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "reality/session/session.h"
#include "reality/session/engine.h"

namespace mux
{

class proxy_reality_connection
{
   public:
    proxy_reality_connection(boost::asio::ip::tcp::socket socket,
                             reality::reality_record_context record_context,
                             const config& cfg,
                             uint32_t conn_id);

    [[nodiscard]] static boost::asio::awaitable<std::shared_ptr<proxy_reality_connection>> connect(
        const boost::asio::any_io_executor& executor, const config& cfg, uint32_t conn_id, boost::system::error_code& ec);

    [[nodiscard]] std::string_view local_host() const { return local_host_; }
    [[nodiscard]] uint16_t local_port() const { return local_port_; }
    [[nodiscard]] std::string_view remote_host() const { return remote_host_; }
    [[nodiscard]] uint16_t remote_port() const { return remote_port_; }

    boost::asio::awaitable<void> write(std::span<const uint8_t> data, boost::system::error_code& ec);
    boost::asio::awaitable<void> write_packet(const std::vector<uint8_t>& packet, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> read_some(std::vector<uint8_t>& buffer, uint32_t timeout_sec, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::vector<uint8_t>> read_packet(uint32_t timeout_sec, boost::system::error_code& ec);
    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);
    void close(boost::system::error_code& ec);

   private:
    [[nodiscard]] boost::asio::awaitable<bool> ensure_plaintext_available(uint32_t timeout_sec, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> read_exact(std::vector<uint8_t>& out,
                                                          std::size_t size,
                                                          uint32_t timeout_sec,
                                                          boost::system::error_code& ec);
    [[nodiscard]] std::size_t consume_plaintext(std::span<uint8_t> output);

   private:
    const config& cfg_;
    uint32_t conn_id_ = 0;
    std::string local_host_ = "unknown";
    uint16_t local_port_ = 0;
    std::string remote_host_ = "unknown";
    uint16_t remote_port_ = 0;
    boost::asio::ip::tcp::socket socket_;
    reality_engine reality_engine_;
    std::vector<uint8_t> pending_plaintext_;
};

}    // namespace mux

#endif
