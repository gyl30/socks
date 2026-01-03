#ifndef SESSION_H
#define SESSION_H

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <memory>
#include <vector>
#include <array>
#include <string>
#include <cstring>
#include <stdexcept>
#include <set>
#include <atomic>
#include <optional>
#include "protocol.h"
#include "log.h"

class session : public std::enable_shared_from_this<session>
{
   public:
    explicit session(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket)), resolver_(socket_.get_executor()) { id_ = next_id_++; }

    [[nodiscard]] boost::asio::awaitable<void> start()
    {
        auto self = shared_from_this();
        const auto remote_ep = socket_.remote_endpoint();
        LOG_INFO("session {} started new connection from {}", id_, remote_ep.address().to_string());

        try
        {
            co_await handshake();
            co_await authenticate();
            co_await read_request();
            co_await dispatch_command();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("session {} error {}", id_, e.what());
        }
        catch (...)
        {
            LOG_ERROR("session {} unknown error", id_);
        }

        LOG_INFO("session {} ended", id_);
    }

   private:
    struct UdpState
    {
        boost::asio::ip::udp::endpoint client_ep;
        bool client_known = false;
        std::set<boost::asio::ip::udp::endpoint> valid_remotes;
    };

    [[nodiscard]] boost::asio::awaitable<void> handshake()
    {
        LOG_DEBUG("session {} starting handshake", id_);
        std::uint8_t version;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&version, 1), boost::asio::use_awaitable);

        if (version != socks::VER)
        {
            LOG_WARN("session {} invalid protocol version {}", id_, version);
            throw std::runtime_error("invalid protocol version");
        }

        std::uint8_t nmethods;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&nmethods, 1), boost::asio::use_awaitable);

        std::vector<std::uint8_t> methods(nmethods);
        co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::use_awaitable);

        bool support_no_auth = false;
        bool support_pass_auth = false;

        for (const auto m : methods)
        {
            if (m == socks::METHOD_NO_AUTH)
            {
                support_no_auth = true;
            }
            else if (m == socks::METHOD_PASSWORD)
            {
                support_pass_auth = true;
            }
        }

        if (support_no_auth)
        {
            LOG_INFO("session {} selected no auth method", id_);
            auth_method_ = socks::METHOD_NO_AUTH;
            const std::uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
        }
        else if (support_pass_auth)
        {
            LOG_INFO("session {} selected password auth method", id_);
            auth_method_ = socks::METHOD_PASSWORD;
            const std::uint8_t resp[] = {socks::VER, socks::METHOD_PASSWORD};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
        }
        else
        {
            LOG_WARN("session {} no acceptable authentication method", id_);
            const std::uint8_t resp[] = {socks::VER, socks::METHOD_NO_ACCEPTABLE};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
            throw std::runtime_error("no acceptable authentication method");
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> authenticate()
    {
        if (auth_method_ == socks::METHOD_NO_AUTH)
        {
            co_return;
        }

        LOG_DEBUG("session {} waiting for credentials", id_);
        std::uint8_t ver;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&ver, 1), boost::asio::use_awaitable);

        std::uint8_t ulen;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&ulen, 1), boost::asio::use_awaitable);
        std::string username(ulen, '\0');
        co_await boost::asio::async_read(socket_, boost::asio::buffer(username), boost::asio::use_awaitable);

        std::uint8_t plen;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&plen, 1), boost::asio::use_awaitable);
        std::string password(plen, '\0');
        co_await boost::asio::async_read(socket_, boost::asio::buffer(password), boost::asio::use_awaitable);

        LOG_DEBUG("session {} auth attempt user {}", id_, username);

        if (username == "user" && password == "pass")
        {
            const std::uint8_t resp[] = {0x01, 0x00};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
            LOG_INFO("session {} auth success for user {}", id_, username);
        }
        else
        {
            const std::uint8_t resp[] = {0x01, 0xFF};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
            LOG_WARN("session {} auth failed for user {}", id_, username);
            throw std::runtime_error("authentication failed");
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> read_request()
    {
        LOG_DEBUG("session {} reading request header", id_);
        std::uint8_t head[4];
        co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::use_awaitable);

        if (head[0] != socks::VER)
        {
            LOG_WARN("session {} invalid version in request", id_);
            throw std::runtime_error("invalid version in request");
        }

        command_ = head[1];

        co_await read_address(head[3]);

        LOG_INFO("session {} received command {} target {} {}", id_, command_, target_host_, target_port_);
    }

    [[nodiscard]] boost::asio::awaitable<void> dispatch_command()
    {
        if (command_ == socks::CMD_CONNECT)
        {
            co_await do_connect();
        }
        else if (command_ == socks::CMD_BIND)
        {
            co_await do_bind();
        }
        else if (command_ == socks::CMD_UDP_ASSOCIATE)
        {
            co_await do_udp_associate();
        }
        else
        {
            LOG_WARN("session {} command not supported {}", id_, command_);
            co_await reply(socks::REP_CMD_NOT_SUPPORTED, boost::asio::ip::tcp::endpoint());
            throw std::runtime_error("command not supported");
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> read_address(std::uint8_t atyp)
    {
        if (atyp == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type bytes;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::use_awaitable);
            target_host_ = boost::asio::ip::address_v4(bytes).to_string();
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::use_awaitable);
            target_host_ = boost::asio::ip::address_v6(bytes).to_string();
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            std::uint8_t len;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::use_awaitable);
            target_host_.resize(len);
            co_await boost::asio::async_read(socket_, boost::asio::buffer(target_host_), boost::asio::use_awaitable);
        }
        else
        {
            throw std::runtime_error("invalid atyp");
        }

        std::uint16_t port;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&port, 2), boost::asio::use_awaitable);
        target_port_ = std::to_string(ntohs(port));
    }

    [[nodiscard]] boost::asio::awaitable<void> reply(std::uint8_t rep, const boost::asio::ip::tcp::endpoint& bound_ep)
    {
        LOG_DEBUG("session {} sending reply {} bound {}", id_, rep, bound_ep.port());
        std::vector<std::uint8_t> resp;
        resp.push_back(socks::VER);
        resp.push_back(rep);
        resp.push_back(0x00);

        if (bound_ep.address().is_v4())
        {
            resp.push_back(socks::ATYP_IPV4);
            const auto bytes = bound_ep.address().to_v4().to_bytes();
            resp.insert(resp.end(), bytes.begin(), bytes.end());
        }
        else
        {
            resp.push_back(socks::ATYP_IPV6);
            const auto bytes = bound_ep.address().to_v6().to_bytes();
            resp.insert(resp.end(), bytes.begin(), bytes.end());
        }

        std::uint16_t port = htons(bound_ep.port());
        const auto* p = reinterpret_cast<const std::uint8_t*>(&port);
        resp.push_back(p[0]);
        resp.push_back(p[1]);

        co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
    }
    [[nodiscard]] boost::asio::awaitable<void> transfer(boost::asio::ip::tcp::socket& from,
                                                        boost::asio::ip::tcp::socket& to,
                                                        std::string_view direction)
    {
        LOG_DEBUG("session {} start transfer {}", id_, direction);
        std::array<char, 8192> data;
        try
        {
            while (true)
            {
                const std::size_t n = co_await from.async_read_some(boost::asio::buffer(data), boost::asio::use_awaitable);
                co_await boost::asio::async_write(to, boost::asio::buffer(data, n), boost::asio::use_awaitable);
            }
        }
        catch (const boost::system::system_error& e)
        {
            if (e.code() == boost::asio::error::eof || e.code() == boost::asio::error::connection_reset ||
                e.code() == boost::asio::error::broken_pipe)
            {
                LOG_DEBUG("session {} transfer {} completed", id_, direction);
            }
            else if (e.code() == boost::asio::error::operation_aborted)
            {
                LOG_DEBUG("session {} transfer {} canceled", id_, direction);
            }
            else
            {
                LOG_ERROR("session {} transfer {} error {}", id_, direction, e.what());
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("session {} transfer {} exception {}", id_, direction, e.what());
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> do_connect()
    {
        using boost::asio::experimental::awaitable_operators::operator&&;

        boost::asio::ip::tcp::socket remote(socket_.get_executor());
        bool connected = false;

        try
        {
            LOG_DEBUG("session {} resolving target {}", id_, target_host_);
            const auto eps = co_await resolver_.async_resolve(target_host_, target_port_, boost::asio::use_awaitable);
            LOG_DEBUG("session {} connecting to target", id_);
            co_await boost::asio::async_connect(remote, eps, boost::asio::use_awaitable);
            connected = true;
            LOG_INFO("session {} connected to target {} {}", id_, target_host_, target_port_);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("session {} failed to connect target {} {} {}", id_, target_host_, target_port_, e.what());
        }

        if (connected)
        {
            co_await reply(socks::REP_SUCCESS, remote.local_endpoint());
            LOG_INFO("session {} starting tcp tunnel", id_);
            co_await (transfer(socket_, remote, "upstream") && transfer(remote, socket_, "downstream"));
        }
        else
        {
            co_await reply(socks::REP_HOST_UNREACH, boost::asio::ip::tcp::endpoint());
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> do_bind()
    {
        using boost::asio::experimental::awaitable_operators::operator&&;

        boost::asio::ip::tcp::acceptor acceptor(socket_.get_executor(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
        co_await reply(socks::REP_SUCCESS, acceptor.local_endpoint());
        LOG_INFO("session {} bind waiting on port {}", id_, acceptor.local_endpoint().port());

        try
        {
            boost::asio::ip::tcp::socket incoming = co_await acceptor.async_accept(boost::asio::use_awaitable);
            LOG_INFO("session {} bind accepted from {}", id_, incoming.remote_endpoint().address().to_string());
            co_await reply(socks::REP_SUCCESS, incoming.remote_endpoint());
            co_await (transfer(socket_, incoming, "bind_upstream") && transfer(incoming, socket_, "bind_downstream"));
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("session {} bind error {}", id_, e.what());
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> do_udp_associate()
    {
        auto executor = socket_.get_executor();
        auto udp_sock = std::make_shared<boost::asio::ip::udp::socket>(executor, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));

        boost::asio::ip::address bind_addr = socket_.local_endpoint().address();
        if (bind_addr.is_v6() && bind_addr.to_v6().is_v4_mapped())
        {
            bind_addr = boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, bind_addr.to_v6());
        }

        const boost::asio::ip::tcp::endpoint tcp_bound(bind_addr, udp_sock->local_endpoint().port());
        co_await reply(socks::REP_SUCCESS, tcp_bound);
        LOG_INFO("session {} udp associate established on port {}", id_, udp_sock->local_endpoint().port());

        boost::asio::co_spawn(
            executor,
            [self = shared_from_this(), udp_sock]() -> boost::asio::awaitable<void> { co_await self->run_udp_relay(udp_sock); },
            boost::asio::detached);

        try
        {
            char dump;
            while (true)
            {
                co_await boost::asio::async_read(socket_, boost::asio::buffer(&dump, 1), boost::asio::use_awaitable);
            }
        }
        catch (...)
        {
            LOG_INFO("session {} tcp control closed closing udp socket", id_);
            udp_sock->close();
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> run_udp_relay(std::shared_ptr<boost::asio::ip::udp::socket> udp_sock)
    {
        UdpState state;
        std::array<char, 65536> buf;
        boost::asio::ip::udp::endpoint sender;

        try
        {
            while (true)
            {
                const std::size_t len = co_await udp_sock->async_receive_from(boost::asio::buffer(buf), sender, boost::asio::use_awaitable);

                if (!state.client_known)
                {
                    state.client_ep = sender;
                    state.client_known = true;
                    LOG_DEBUG("session {} udp client identified {}", id_, state.client_ep.address().to_string());
                }

                if (sender == state.client_ep)
                {
                    co_await handle_udp_from_client(udp_sock, state, buf.data(), len);
                }
                else
                {
                    co_await handle_udp_from_remote(udp_sock, state, buf.data(), len, sender);
                }
            }
        }
        catch (const boost::system::system_error& e)
        {
            if (e.code() != boost::asio::error::operation_aborted)
            {
                LOG_ERROR("session {} udp loop error {}", id_, e.what());
            }
            else
            {
                LOG_DEBUG("session {} udp loop stopped", id_);
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("session {} udp loop error {}", id_, e.what());
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> handle_udp_from_client(const std::shared_ptr<boost::asio::ip::udp::socket>& udp_sock,
                                                                      UdpState& state,
                                                                      const char* buf,
                                                                      std::size_t len)
    {
        if (len < 3 || buf[2] != 0x00)
        {
            LOG_WARN("session {} invalid udp header from client", id_);
            co_return;
        }

        const auto [target_ep, payload_offset] = co_await parse_udp_target(udp_sock, buf, len);
        if (!target_ep.has_value())
        {
            co_return;
        }

        state.valid_remotes.insert(*target_ep);
        co_await udp_sock->async_send_to(boost::asio::buffer(buf + payload_offset, len - payload_offset), *target_ep, boost::asio::use_awaitable);
    }

    [[nodiscard]] boost::asio::awaitable<void> handle_udp_from_remote(const std::shared_ptr<boost::asio::ip::udp::socket>& udp_sock,
                                                                      const UdpState& state,
                                                                      const char* buf,
                                                                      std::size_t len,
                                                                      const boost::asio::ip::udp::endpoint& sender)
    {
        if (state.valid_remotes.find(sender) == state.valid_remotes.end())
        {
            LOG_WARN("session {} dropped udp packet from unknown remote {}", id_, sender.address().to_string());
            co_return;
        }

        std::vector<std::uint8_t> head;
        head.push_back(0);
        head.push_back(0);
        head.push_back(0);

        if (sender.address().is_v4())
        {
            head.push_back(socks::ATYP_IPV4);
            const auto b = sender.address().to_v4().to_bytes();
            head.insert(head.end(), b.begin(), b.end());
        }
        else
        {
            head.push_back(socks::ATYP_IPV6);
            const auto b = sender.address().to_v6().to_bytes();
            head.insert(head.end(), b.begin(), b.end());
        }

        std::uint16_t p = htons(sender.port());
        const auto* pp = reinterpret_cast<const std::uint8_t*>(&p);
        head.push_back(pp[0]);
        head.push_back(pp[1]);

        head.insert(head.end(), buf, buf + len);
        co_await udp_sock->async_send_to(boost::asio::buffer(head), state.client_ep, boost::asio::use_awaitable);
    }

    [[nodiscard]] boost::asio::awaitable<std::pair<std::optional<boost::asio::ip::udp::endpoint>, std::size_t>> parse_udp_target(
        const std::shared_ptr<boost::asio::ip::udp::socket>& udp_sock, const char* buf, std::size_t len)
    {
        std::size_t header_len = 0;
        boost::asio::ip::udp::endpoint target;
        const auto atyp = static_cast<std::uint8_t>(buf[3]);

        if (atyp == socks::ATYP_IPV4)
        {
            if (len < 10)
            {
                co_return std::make_pair(std::nullopt, 0);
            }
            header_len = 10;
            boost::asio::ip::address_v4::bytes_type b;
            std::memcpy(b.data(), &buf[4], 4);
            std::uint16_t p;
            std::memcpy(&p, &buf[8], 2);
            target = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(b), ntohs(p));
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            if (len < 22)
            {
                co_return std::make_pair(std::nullopt, 0);
            }
            header_len = 22;
            boost::asio::ip::address_v6::bytes_type b;
            std::memcpy(b.data(), &buf[4], 16);
            std::uint16_t p;
            std::memcpy(&p, &buf[20], 2);
            target = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6(b), ntohs(p));
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            const auto dlen = static_cast<std::uint8_t>(buf[4]);
            if (len < 5 + static_cast<std::size_t>(dlen) + 2)
            {
                co_return std::make_pair(std::nullopt, 0);
            }
            header_len = 5 + dlen + 2;
            std::string domain(&buf[5], dlen);
            std::uint16_t p;
            std::memcpy(&p, &buf[5 + dlen], 2);

            boost::asio::ip::tcp::resolver res(udp_sock->get_executor());
            const auto results = co_await res.async_resolve(domain, std::to_string(ntohs(p)), boost::asio::use_awaitable);
            if (results.empty())
            {
                LOG_WARN("session {} failed to resolve udp target {}", id_, domain);
                co_return std::make_pair(std::nullopt, 0);
            }
            const auto& tcp_entry = *results.begin();
            target = boost::asio::ip::udp::endpoint(tcp_entry.endpoint().address(), ntohs(p));
        }
        else
        {
            LOG_WARN("session {} unsupported udp address type {}", id_, atyp);
            co_return std::make_pair(std::nullopt, 0);
        }

        co_return std::make_pair(target, header_len);
    }

   private:
    inline static std::atomic<std::uint64_t> next_id_ = 1;
    std::uint64_t id_ = 0;

    std::uint8_t auth_method_ = socks::METHOD_NO_ACCEPTABLE;
    std::uint8_t command_ = 0;
    std::string target_host_;
    std::string target_port_;

    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
};

#endif
