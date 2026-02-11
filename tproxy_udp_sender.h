#ifndef TPROXY_UDP_SENDER_H
#define TPROXY_UDP_SENDER_H

#include <memory>
#include <vector>
#include <cstdint>
#include <unordered_map>

#include <asio/ip/udp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>

namespace mux
{

class tproxy_udp_sender
{
   public:
    tproxy_udp_sender(asio::io_context& io_context, std::uint32_t mark);

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

    struct cached_socket
    {
        std::shared_ptr<asio::ip::udp::socket> socket;
        std::uint64_t last_used_ms = 0;
    };

    std::shared_ptr<asio::ip::udp::socket> get_socket(const asio::ip::udp::endpoint& src_ep);
    void prune_sockets(std::uint64_t now_ms);
    void evict_oldest_socket();

   private:
    asio::io_context& io_context_;
    std::uint32_t mark_ = 0;
    std::unordered_map<endpoint_key, cached_socket, endpoint_hash, endpoint_key_equal> sockets_;
};

}    // namespace mux

#endif
