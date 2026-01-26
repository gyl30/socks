#ifndef SOCKS_SESSION_H
#define SOCKS_SESSION_H

#include <vector>
#include <array>
#include <memory>
#include <asio.hpp>

#include "log.h"

#include "protocol.h"
#include "mux_tunnel.h"
#include "ip_matcher.h"

namespace mux
{

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager, uint32_t sid)
        : sid_(sid), socket_(std::move(socket)), tunnel_manager_(std::move(tunnel_manager))
    {
    }

    void set_ip_matcher(std::shared_ptr<ip_matcher> matcher) { matcher_ = std::move(matcher); }

    void start()
    {
        auto self = shared_from_this();
        asio::co_spawn(socket_.get_executor(), [self]() mutable -> asio::awaitable<void> { co_await self->run(); }, asio::detached);
    }

   private:
    asio::awaitable<void> run()
    {
        std::error_code ec;
        auto ep = socket_.remote_endpoint(ec);
        std::string remote_addr = ec ? "unknown" : ep.address().to_string() + ":" + std::to_string(ep.port());
        LOG_INFO("socks {} session started from {}", sid_, remote_addr);

        ec = socket_.set_option(asio::ip::tcp::no_delay(true), ec);
        (void)ec;
        if (!co_await handshake_socks5())
        {
            LOG_WARN("socks {} handshake failed", sid_);
            co_return;
        }

        auto [ok, host, port, cmd] = co_await read_request_header();
        if (!ok)
        {
            LOG_WARN("socks {} request header invalid", sid_);
            co_return;
        }

        co_await dispatch_request(cmd, host, port);
    }

    [[nodiscard]] asio::awaitable<bool> handshake_socks5()
    {
        uint8_t ver_nmethods[2];
        auto [e1, n1] = co_await asio::async_read(socket_, asio::buffer(ver_nmethods, 2), asio::as_tuple(asio::use_awaitable));

        if (e1 || ver_nmethods[0] != socks::VER)
        {
            LOG_ERROR("socks {} invalid version {} or read error {}", sid_, ver_nmethods[0], e1.message());
            co_return false;
        }

        std::vector<uint8_t> methods(ver_nmethods[1]);
        auto [e2, n2] = co_await asio::async_read(socket_, asio::buffer(methods), asio::as_tuple(asio::use_awaitable));

        if (e2)
        {
            LOG_ERROR("socks {} methods read error {}", sid_, e2.message());
            co_return false;
        }

        std::string methods_str;
        for (auto m : methods)
        {
            methods_str += std::to_string(m) + " ";
        }
        LOG_DEBUG("socks {} client offered methods: [ {}]", sid_, methods_str);

        uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        auto [e3, n3] = co_await asio::async_write(socket_, asio::buffer(resp), asio::as_tuple(asio::use_awaitable));

        if (e3)
        {
            LOG_ERROR("socks {} auth resp write error {}", sid_, e3.message());
            co_return false;
        }
        co_return true;
    }

    struct request_info_t
    {
        bool ok;
        std::string host;
        uint16_t port;
        uint8_t cmd;
    };

    [[nodiscard]] asio::awaitable<std::pair<bool, std::string>> read_socks_address(uint8_t atyp)
    {
        std::string host;
        if (atyp == socks::ATYP_IPV4)
        {
            asio::ip::address_v4::bytes_type b;
            auto [e, n] = co_await asio::async_read(socket_, asio::buffer(b), asio::as_tuple(asio::use_awaitable));
            if (e)
            {
                co_return std::make_pair(false, "");
            }
            host = asio::ip::address_v4(b).to_string();
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            uint8_t len;
            auto [e, n] = co_await asio::async_read(socket_, asio::buffer(&len, 1), asio::as_tuple(asio::use_awaitable));
            if (e)
            {
                co_return std::make_pair(false, "");
            }
            host.resize(len);
            auto [e2, n2] = co_await asio::async_read(socket_, asio::buffer(host), asio::as_tuple(asio::use_awaitable));
            if (e2)
            {
                co_return std::make_pair(false, "");
            }
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            asio::ip::address_v6::bytes_type b;
            auto [e, n] = co_await asio::async_read(socket_, asio::buffer(b), asio::as_tuple(asio::use_awaitable));
            if (e)
            {
                co_return std::make_pair(false, "");
            }
            host = asio::ip::address_v6(b).to_string();
        }
        else
        {
            LOG_WARN("socks {} address type {} not supported", sid_, atyp);
            co_return std::make_pair(false, "");
        }
        co_return std::make_pair(true, host);
    }

    [[nodiscard]] asio::awaitable<request_info_t> read_request_header()
    {
        uint8_t head[4];
        auto [e, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));

        if (e)
        {
            LOG_ERROR("socks {} request header read error {}", sid_, e.message());
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        auto [addr_ok, host] = co_await read_socks_address(head[3]);
        if (!addr_ok)
        {
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        uint16_t port_n;
        auto [e2, n2] = co_await asio::async_read(socket_, asio::buffer(&port_n, 2), asio::as_tuple(asio::use_awaitable));
        if (e2)
        {
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        const uint16_t port = ntohs(port_n);
        LOG_DEBUG("socks {} parsed request cmd {} addr {} port {}", sid_, head[1], host, port);
        co_return request_info_t{.ok = true, .host = host, .port = port, .cmd = head[1]};
    }

    asio::awaitable<void> dispatch_request(uint8_t cmd, std::string host, uint16_t port)
    {
        if (cmd == socks::CMD_CONNECT)
        {
            LOG_INFO("socks {} cmd connect target {} port {}", sid_, host, port);
            bool use_direct = false;
            std::string target_ip_str = host;
            if (matcher_)
            {
                std::error_code ec;
                auto addr = asio::ip::make_address(host, ec);

                if (!ec)
                {
                    if (matcher_->match(addr))
                    {
                        use_direct = true;
                    }
                }
                else
                {
                    asio::ip::tcp::resolver resolver(socket_.get_executor());
                    auto [res_ec, eps] = co_await resolver.async_resolve(host, "", asio::as_tuple(asio::use_awaitable));
                    if (!res_ec && !eps.empty())
                    {
                        for (const auto &ep : eps)
                        {
                            if (matcher_->match(ep.endpoint().address()))
                            {
                                use_direct = true;
                                target_ip_str = ep.endpoint().address().to_string();
                                break;
                            }
                        }
                    }
                }
            }

            if (use_direct)
            {
                LOG_INFO("socks {} direct connect to {}:{}", sid_, host, port);
                co_await run_direct_tcp(host, port);
            }
            else
            {
                LOG_INFO("socks {} proxy connect to {}:{}", sid_, host, port);
                co_await run_tcp(host, port);
            }
        }
        else if (cmd == socks::CMD_UDP_ASSOCIATE)
        {
            LOG_INFO("socks {} cmd udp associate", sid_);
            co_await run_udp(host, port);
        }
        else
        {
            LOG_WARN("socks {} cmd {} not supported", sid_, cmd);
            uint8_t err[] = {socks::VER, socks::REP_CMD_NOT_SUPPORTED, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
        }
    }
    static asio::awaitable<void> transfer(asio::ip::tcp::socket &from, asio::ip::tcp::socket &to)
    {
        std::array<char, 8192> buf;
        for (;;)
        {
            auto [ec, n] = co_await from.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (ec || n == 0)
            {
                break;
            }

            auto [wec, wn] = co_await asio::async_write(to, asio::buffer(buf, n), asio::as_tuple(asio::use_awaitable));
            if (wec)
            {
                break;
            }
        }
        std::error_code ignore;
        ignore = from.shutdown(asio::ip::tcp::socket::shutdown_receive, ignore);
        ignore = to.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
    }
    asio::awaitable<void> run_direct_tcp(std::string host, uint16_t port)
    {
        asio::ip::tcp::socket target_socket(socket_.get_executor());
        asio::ip::tcp::resolver resolver(socket_.get_executor());

        auto [res_ec, eps] = co_await resolver.async_resolve(host, std::to_string(port), asio::as_tuple(asio::use_awaitable));
        if (res_ec)
        {
            LOG_WARN("socks {} direct resolve failed {}", sid_, res_ec.message());
            uint8_t err[] = {socks::VER, socks::REP_HOST_UNREACH, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
            co_return;
        }

        auto [conn_ec, ep] = co_await asio::async_connect(target_socket, eps, asio::as_tuple(asio::use_awaitable));
        if (conn_ec)
        {
            LOG_WARN("socks {} direct connect failed {}", sid_, conn_ec.message());
            uint8_t err[] = {socks::VER, socks::REP_CONN_REFUSED, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
            co_return;
        }

        target_socket.set_option(asio::ip::tcp::no_delay(true));

        uint8_t rep[] = {socks::VER, socks::REP_SUCCESS, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        auto [write_ec, n] = co_await asio::async_write(socket_, asio::buffer(rep), asio::as_tuple(asio::use_awaitable));
        if (write_ec)
        {
            co_return;
        }

        using asio::experimental::awaitable_operators::operator&&;
        co_await (transfer(socket_, target_socket) && transfer(target_socket, socket_));
    }
    asio::awaitable<void> run_tcp(std::string host, uint16_t port)
    {
        auto stream = tunnel_manager_->create_stream();
        if (stream == nullptr)
        {
            LOG_ERROR("socks {} failed to create stream tunnel not ready", sid_);
            co_return;
        }

        LOG_DEBUG("socks {} sending syn to mux stream {}", sid_, stream->id());
        const syn_payload syn{.socks_cmd = socks::CMD_CONNECT, .addr = host, .port = port};
        if (auto ec = co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_SYN, mux_codec::encode_syn(syn)))
        {
            LOG_ERROR("socks {} stream syn failed {}", sid_, ec.message());
            co_await stream->close();
            co_return;
        }

        auto [ack_ec, ack_data] = co_await stream->async_read_some();
        if (ack_ec)
        {
            LOG_ERROR("socks {} stream ack read failed {}", sid_, ack_ec.message());
            co_await stream->close();
            co_return;
        }

        ack_payload ack_pl;
        if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep != socks::REP_SUCCESS)
        {
            LOG_WARN("socks {} stream remote rejected connection rep {}", sid_, ack_pl.socks_rep);
            uint8_t err[] = {socks::VER, socks::REP_CONN_REFUSED, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
            co_await stream->close();
            co_return;
        }

        LOG_INFO("socks {} stream established id {}", sid_, stream->id());

        uint8_t rep[] = {socks::VER, socks::REP_SUCCESS, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        if (auto [e, n] = co_await asio::async_write(socket_, asio::buffer(rep), asio::as_tuple(asio::use_awaitable)); e)
        {
            co_await stream->close();
            co_return;
        }

        using asio::experimental::awaitable_operators::operator&&;
        co_await (upstream_tcp(stream) && downstream_tcp(stream));
        co_await stream->close();
        LOG_INFO("socks {} finished", sid_);
    }

    asio::awaitable<void> upstream_tcp(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        uint64_t total = 0;
        for (;;)
        {
            std::error_code e;
            auto n = co_await socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, e));
            if (e || n == 0)
            {
                break;
            }
            total += n;
            e = co_await stream->async_write_some(buf.data(), n);
            if (e)
            {
                break;
            }
        }
        LOG_DEBUG("socks {} upstream finished total bytes {}", sid_, total);
        co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_FIN, {});
    }

    asio::awaitable<void> downstream_tcp(std::shared_ptr<mux_stream> stream)
    {
        uint64_t total = 0;
        for (;;)
        {
            auto [e, data] = co_await stream->async_read_some();
            if (e || data.empty())
            {
                std::error_code ignore;
                ignore = socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
                (void)ignore;
                break;
            }
            total += data.size();
            auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
        LOG_DEBUG("socks {} downstream finished total bytes {}", sid_, total);
    }

    asio::awaitable<void> run_udp(std::string host, uint16_t port)
    {
        auto ex = socket_.get_executor();
        std::error_code ec;

        auto tcp_local_ep = socket_.local_endpoint(ec);
        if (ec)
        {
            LOG_ERROR("socks {} failed to get tcp local endpoint {}", sid_, ec.message());
            co_return;
        }

        auto local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());

        asio::ip::udp::socket udp_sock(ex);
        auto udp_protocol = local_addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4();

        ec = udp_sock.open(udp_protocol, ec);
        if (!ec)
        {
            if (local_addr.is_v6())
            {
                ec = udp_sock.set_option(asio::ip::v6_only(false), ec);
            }
            ec = udp_sock.bind(asio::ip::udp::endpoint(local_addr, 0), ec);
        }

        if (ec)
        {
            LOG_ERROR("socks {} tcp-associated udp bind failed {}", sid_, ec.message());
            uint8_t err[] = {socks::VER, socks::REP_GEN_FAIL, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
            co_return;
        }

        auto udp_local_ep = udp_sock.local_endpoint(ec);
        uint16_t udp_bind_port = udp_local_ep.port();
        LOG_INFO("socks {} tcp-associated udp socket bound at {}:{}", sid_, local_addr.to_string(), udp_bind_port);

        auto stream = tunnel_manager_->create_stream();
        if (stream == nullptr)
        {
            LOG_ERROR("socks {} failed to create stream for udp association", sid_);
            co_return;
        }

        const syn_payload syn{.socks_cmd = socks::CMD_UDP_ASSOCIATE, .addr = "0.0.0.0", .port = 0};
        ec = co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_SYN, mux_codec::encode_syn(syn));
        if (ec)
        {
            LOG_ERROR("socks {} udp syn failed {}", sid_, ec.message());
            co_await stream->close();
            co_return;
        }

        auto [ack_ec, ack_data] = co_await stream->async_read_some();
        if (ack_ec)
        {
            LOG_ERROR("socks {} udp ack wait failed {}", sid_, ack_ec.message());
            co_await stream->close();
            co_return;
        }

        LOG_INFO("socks {} stream {} udp tunnel established", sid_, stream->id());

        std::vector<uint8_t> final_rep;
        final_rep.reserve(22);
        final_rep.push_back(socks::VER);
        final_rep.push_back(socks::REP_SUCCESS);
        final_rep.push_back(0x00);

        if (local_addr.is_v4())
        {
            final_rep.push_back(socks::ATYP_IPV4);
            auto bytes = local_addr.to_v4().to_bytes();
            final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
        }
        else
        {
            final_rep.push_back(socks::ATYP_IPV6);
            auto bytes = local_addr.to_v6().to_bytes();
            final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
        }

        final_rep.push_back(static_cast<uint8_t>((udp_bind_port >> 8) & 0xFF));
        final_rep.push_back(static_cast<uint8_t>(udp_bind_port & 0xFF));

        auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(final_rep), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_ERROR("socks {} failed to send udp response header", sid_);
            co_await stream->close();
            co_return;
        }

        auto client_ep_ptr = std::make_shared<asio::ip::udp::endpoint>();

        using asio::experimental::awaitable_operators::operator||;

        co_await (udp_sock_to_stream(udp_sock, stream, client_ep_ptr, sid_) || stream_to_udp_sock(udp_sock, stream, client_ep_ptr, sid_) ||
                  keep_tcp_alive());

        co_await stream->close();
        LOG_INFO("socks {} tcp control channel closed, terminating udp association", sid_);
    }

    static asio::awaitable<void> udp_sock_to_stream(asio::ip::udp::socket &udp_sock,
                                                    std::shared_ptr<mux_stream> stream,
                                                    std::shared_ptr<asio::ip::udp::endpoint> client_ep,
                                                    uint32_t sid)
    {
        std::vector<uint8_t> buf(65535);
        asio::ip::udp::endpoint sender;
        for (;;)
        {
            auto [ec, n] = co_await udp_sock.async_receive_from(asio::buffer(buf), sender, asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                LOG_WARN("socks {} udp local receive error {}", sid, ec.message());
                break;
            }
            *client_ep = sender;

            socks_udp_header h;
            if (socks_codec::decode_udp_header(buf.data(), n, h))
            {
                LOG_DEBUG("socks {} tcp jinked udp fwd {} bytes target {}:{}", sid, n, h.addr, h.port);
            }
            else
            {
                LOG_WARN("socks {} tcp linked udp invalid header size {}", sid, n);
            }
            if (h.frag != 0x00)
            {
                LOG_WARN("socks {} dropping fragmented udp packet as not supported", sid);
                continue;
            }
            ec = co_await stream->async_write_some(buf.data(), n);
            if (ec)
            {
                LOG_ERROR("socks {} udp tunnel write error {}", sid, ec.message());
                break;
            }
        }
    }

    static asio::awaitable<void> stream_to_udp_sock(asio::ip::udp::socket &udp_sock,
                                                    std::shared_ptr<mux_stream> stream,
                                                    std::shared_ptr<asio::ip::udp::endpoint> client_ep,
                                                    uint32_t sid)
    {
        for (;;)
        {
            auto [ec, data] = co_await stream->async_read_some();
            if (ec || data.empty())
            {
                if (ec != asio::error::operation_aborted)
                {
                    LOG_WARN("socks {} udp tunnel read error {}", sid, ec.message());
                }
                break;
            }

            if (client_ep->port() == 0)
            {
                LOG_TRACE("socks {} udp drop packet, client unknown (no outgoing packet yet)", sid);
                continue;
            }

            socks_udp_header h;
            if (socks_codec::decode_udp_header(data.data(), data.size(), h))
            {
                LOG_DEBUG("socks {} [tcp-linked] udp return packet from {}:{} size {}", sid, h.addr, h.port, data.size());
            }

            auto [se, sn] = co_await udp_sock.async_send_to(asio::buffer(data), *client_ep, asio::as_tuple(asio::use_awaitable));
            if (se)
            {
                LOG_WARN("socks {} udp local send error {}", sid, se.message());
            }
        }
    }

    asio::awaitable<void> keep_tcp_alive()
    {
        char b[1];
        auto [ec, n] = co_await socket_.async_read_some(asio::buffer(b), asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            LOG_INFO("socks {} tcp control channel closed ({})", sid_, ec.message());
        }
    }

   private:
    uint32_t sid_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<ip_matcher> matcher_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux

#endif
