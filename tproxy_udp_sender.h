#ifndef TPROXY_UDP_SENDER_H
#define TPROXY_UDP_SENDER_H

#include <mutex>
#include <memory>
#include <vector>
#include <cstdint>
#include <unordered_map>

#include <asio/ip/udp.hpp>
#include <asio/awaitable.hpp>
#include <asio/any_io_executor.hpp>

namespace mux
{

class tproxy_udp_sender
{
   public:
    tproxy_udp_sender(const asio::any_io_executor& ex, std::uint32_t mark);

    asio::awaitable<void> send_to_client(const asio::ip::udp::endpoint& client_ep,
                                         const asio::ip::udp::endpoint& src_ep,
                                         const std::vector<std::uint8_t>& payload);

   private:
    struct endpoint_key
    {
        asio::ip::address addr;
        std::uint16_t port = 0;
    };

    class endpoint_key_equal
    {
       public:
        bool operator()(const endpoint_key& lhs, const endpoint_key& rhs) const { return lhs.addr == rhs.addr && lhs.port == rhs.port; }
    };

    class endpoint_hash
    {
       public:
        std::size_t operator()(const endpoint_key& key) const;
    };

    std::shared_ptr<asio::ip::udp::socket> get_socket(const asio::ip::udp::endpoint& src_ep);

   private:
    asio::any_io_executor ex_;
    std::uint32_t mark_ = 0;
    std::mutex socket_mutex_;
    std::unordered_map<endpoint_key, std::shared_ptr<asio::ip::udp::socket>, endpoint_hash, endpoint_key_equal> sockets_;
};

}    // namespace mux

#endif
