#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <boost/asio.hpp>
#include <vector>
#include <array>
#include <atomic>
#include <memory>

#include "reality_core.h"
#include "reality_messages.h"
#include "reality_engine.h"
#include "mux_tunnel.h"
#include "log.h"
#include "context_pool.h"
#include "protocol.h"

namespace mux
{

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(boost::asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager, uint32_t sid)
        : socket_(std::move(socket)), tunnel_manager_(std::move(tunnel_manager)), sid_(sid)
    {
    }

    void start()
    {
        auto self = shared_from_this();
        boost::asio::co_spawn(
            socket_.get_executor(), [self]() mutable -> boost::asio::awaitable<void> { co_await self->run(); }, boost::asio::detached);
    }

   private:
    boost::asio::awaitable<void> run()
    {
        boost::system::error_code ec;
        auto ep = socket_.remote_endpoint(ec);
        std::string remote_addr = ec ? "unknown" : ep.address().to_string() + ":" + std::to_string(ep.port());
        LOG_INFO("socks {} session started from {}", sid_, remote_addr);

        ec = socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
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

    [[nodiscard]] boost::asio::awaitable<bool> handshake_socks5()
    {
        uint8_t ver_nmethods[2];
        auto [e1, n1] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(ver_nmethods, 2), boost::asio::as_tuple(boost::asio::use_awaitable));

        if (e1 || ver_nmethods[0] != socks::VER)
        {
            LOG_ERROR("socks {} invalid version {} or read error {}", sid_, ver_nmethods[0], e1.message());
            co_return false;
        }

        std::vector<uint8_t> methods(ver_nmethods[1]);
        auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::as_tuple(boost::asio::use_awaitable));

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
        auto [e3, n3] = co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::as_tuple(boost::asio::use_awaitable));

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

    [[nodiscard]] boost::asio::awaitable<std::pair<bool, std::string>> read_socks_address(uint8_t atyp)
    {
        std::string host;
        if (atyp == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type b;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
            {
                co_return std::make_pair(false, "");
            }
            host = boost::asio::ip::address_v4(b).to_string();
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            uint8_t len;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
            {
                co_return std::make_pair(false, "");
            }
            host.resize(len);
            auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(host), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
            {
                co_return std::make_pair(false, "");
            }
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type b;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
            {
                co_return std::make_pair(false, "");
            }
            host = boost::asio::ip::address_v6(b).to_string();
        }
        else
        {
            LOG_WARN("socks {} address type {} not supported", sid_, atyp);
            co_return std::make_pair(false, "");
        }
        co_return std::make_pair(true, host);
    }

    [[nodiscard]] boost::asio::awaitable<request_info_t> read_request_header()
    {
        uint8_t head[4];
        auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::as_tuple(boost::asio::use_awaitable));

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
        auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&port_n, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e2)
        {
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        const uint16_t port = ntohs(port_n);
        LOG_DEBUG("socks {} parsed request cmd {} addr {} port {}", sid_, head[1], host, port);
        co_return request_info_t{.ok = true, .host = host, .port = port, .cmd = head[1]};
    }

    boost::asio::awaitable<void> dispatch_request(uint8_t cmd, std::string host, uint16_t port)
    {
        if (cmd == socks::CMD_CONNECT)
        {
            LOG_INFO("socks {} cmd connect target {} port {}", sid_, host, port);
            co_await run_tcp(host, port);
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
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
        }
    }

    boost::asio::awaitable<void> run_tcp(std::string host, uint16_t port)
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
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_await stream->close();
            co_return;
        }

        LOG_INFO("socks {} stream established id {}", sid_, stream->id());

        uint8_t rep[] = {socks::VER, socks::REP_SUCCESS, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        if (auto [e, n] = co_await boost::asio::async_write(socket_, boost::asio::buffer(rep), boost::asio::as_tuple(boost::asio::use_awaitable)); e)
        {
            co_await stream->close();
            co_return;
        }

        using boost::asio::experimental::awaitable_operators::operator&&;
        co_await (upstream_tcp(stream) && downstream_tcp(stream));
        co_await stream->close();
        LOG_INFO("socks {} finished", sid_);
    }

    boost::asio::awaitable<void> upstream_tcp(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        uint64_t total = 0;
        for (;;)
        {
            boost::system::error_code e;
            auto n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, e));
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

    boost::asio::awaitable<void> downstream_tcp(std::shared_ptr<mux_stream> stream)
    {
        uint64_t total = 0;
        for (;;)
        {
            auto [e, data] = co_await stream->async_read_some();
            if (e || data.empty())
            {
                boost::system::error_code ignore;
                ignore = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
                (void)ignore;
                break;
            }
            total += data.size();
            auto [we, wn] = co_await boost::asio::async_write(socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
        LOG_DEBUG("socks {} downstream finished total bytes {}", sid_, total);
    }

    boost::asio::awaitable<void> run_udp(std::string host, uint16_t port)
    {
        auto ex = socket_.get_executor();
        boost::asio::ip::udp::socket udp_sock(ex);
        boost::system::error_code ec;

        ec = udp_sock.open(boost::asio::ip::udp::v4(), ec);
        ec = udp_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        if (ec)
        {
            LOG_ERROR("socks {} tcp-associated udp bind failed {}", sid_, ec.message());
            uint8_t err[] = {socks::VER, socks::REP_GEN_FAIL, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_return;
        }

        auto local_ep = udp_sock.local_endpoint(ec);
        LOG_INFO("socks {} tcp-associated udp socket bound at {}", sid_, local_ep.address().to_string());

        auto stream = tunnel_manager_->create_stream();
        if (stream == nullptr)
        {
            LOG_ERROR("socks {} failed to create stream for udp association", sid_);
            co_return;
        }

        LOG_INFO("socks {} associating tcp control with udp {} via mux stream {}", sid_, local_ep.address().to_string(), stream->id());

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

        uint8_t final_rep[10];
        final_rep[0] = socks::VER;
        final_rep[1] = socks::REP_SUCCESS;
        final_rep[2] = 0x00;
        final_rep[3] = socks::ATYP_IPV4;
        auto bytes = boost::asio::ip::make_address_v4("127.0.0.1").to_bytes();
        std::memcpy(final_rep + 4, bytes.data(), 4);
        final_rep[8] = static_cast<uint8_t>((local_ep.port() >> 8) & 0xFF);
        final_rep[9] = static_cast<uint8_t>(local_ep.port() & 0xFF);

        co_await boost::asio::async_write(socket_, boost::asio::buffer(final_rep, 10), boost::asio::as_tuple(boost::asio::use_awaitable));

        auto client_ep_ptr = std::make_shared<boost::asio::ip::udp::endpoint>();
        using boost::asio::experimental::awaitable_operators::operator||;

        co_await (udp_sock_to_stream(udp_sock, stream, client_ep_ptr, sid_) || stream_to_udp_sock(udp_sock, stream, client_ep_ptr, sid_) ||
                  keep_tcp_alive());

        co_await stream->close();
        LOG_INFO("socks {} tcp control closed, terminating udp association", sid_);
    }

    static boost::asio::awaitable<void> udp_sock_to_stream(boost::asio::ip::udp::socket &udp_sock,
                                                           std::shared_ptr<mux_stream> stream,
                                                           std::shared_ptr<boost::asio::ip::udp::endpoint> client_ep,
                                                           uint32_t sid)
    {
        std::vector<uint8_t> buf(65535);
        boost::asio::ip::udp::endpoint sender;
        for (;;)
        {
            auto [ec, n] = co_await udp_sock.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_WARN("socks {} udp local receive error {}", sid, ec.message());
                break;
            }
            *client_ep = sender;

            socks_udp_header h;
            if (socks_codec::decode_udp_header(buf.data(), n, h))
            {
                LOG_DEBUG("socks {} [tcp-linked] udp fwd {} bytes target {}:{}", sid, n, h.addr, h.port);
            }
            else
            {
                LOG_WARN("socks {} [tcp-linked] udp invalid header size {}", sid, n);
            }

            ec = co_await stream->async_write_some(buf.data(), n);
            if (ec)
            {
                LOG_ERROR("socks {} udp tunnel write error {}", sid, ec.message());
                break;
            }
        }
    }

    static boost::asio::awaitable<void> stream_to_udp_sock(boost::asio::ip::udp::socket &udp_sock,
                                                           std::shared_ptr<mux_stream> stream,
                                                           std::shared_ptr<boost::asio::ip::udp::endpoint> client_ep,
                                                           uint32_t sid)
    {
        for (;;)
        {
            auto [ec, data] = co_await stream->async_read_some();
            if (ec || data.empty())
            {
                if (ec != boost::asio::error::operation_aborted)
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

            auto [se, sn] = co_await udp_sock.async_send_to(boost::asio::buffer(data), *client_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (se)
            {
                LOG_WARN("socks {} udp local send error {}", sid, se.message());
            }
        }
    }

    boost::asio::awaitable<void> keep_tcp_alive()
    {
        char b[1];
        auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_INFO("socks {} tcp control channel closed ({})", sid_, ec.message());
        }
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    uint32_t sid_;
};

class local_client : public std::enable_shared_from_this<local_client>
{
   public:
    local_client(io_context_pool &pool,
                 std::string host,
                 std::string port,
                 uint16_t l_port,
                 const std::string &key_hex,
                 std::string sni,
                 boost::system::error_code &ec)
        : r_host_(std::move(host)), r_port_(std::move(port)), l_port_(l_port), sni_(std::move(sni)), pool_(pool)
    {
        server_pub_key_ = reality::crypto_util::hex_to_bytes(key_hex, ec);
    }

    void start()
    {
        LOG_INFO("client starting target {} port {} listening {}", r_host_, r_port_, l_port_);
        auto &io = pool_.get_io_context();
        boost::asio::co_spawn(io, [this, self = shared_from_this()]() { return connect_remote_loop(); }, boost::asio::detached);
        boost::asio::co_spawn(io, [this, self = shared_from_this()]() { return accept_local_loop(); }, boost::asio::detached);
    }

   private:
    class transcript_t
    {
       public:
        transcript_t() : ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { EVP_DigestInit(ctx_.get(), EVP_sha256()); }
        void update(const std::vector<uint8_t> &data) const { EVP_DigestUpdate(ctx_.get(), data.data(), data.size()); }
        [[nodiscard]] std::vector<uint8_t> finish() const
        {
            const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            EVP_MD_CTX_copy(c.get(), ctx_.get());
            std::vector<uint8_t> h(EVP_MD_size(EVP_sha256()));
            unsigned int l;
            EVP_DigestFinal(c.get(), h.data(), &l);
            h.resize(l);
            return h;
        }

       private:
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
    };

    struct handshake_result
    {
        std::vector<uint8_t> c_app_secret;
        std::vector<uint8_t> s_app_secret;
    };

    boost::asio::awaitable<void> connect_remote_loop()
    {
        for (;;)
        {
            uint32_t cid = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
            LOG_INFO("reality handshake initiating conn_id {}", cid);

            boost::system::error_code ec;
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool_.get_io_context());

            if (!co_await tcp_connect(*socket, ec))
            {
                LOG_ERROR("connect failed {} retry in 5s", ec.message());
                co_await wait_retry();
                continue;
            }

            auto [hs_ok, hs_res] = co_await perform_reality_handshake(*socket, ec);
            if (!hs_ok)
            {
                LOG_ERROR("handshake failed {} retry in 5s", ec.message());
                co_await wait_retry();
                continue;
            }

            auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(hs_res.c_app_secret, ec);
            auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(hs_res.s_app_secret, ec);

            LOG_INFO("reality handshake success tunnel active id {}", cid);
            reality_engine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second);
            tunnel_manager_ = std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(std::move(*socket), std::move(re), true, cid);
            co_await tunnel_manager_->run();

            LOG_WARN("tunnel lost reconnecting in 5s");
            co_await wait_retry();
        }
    }

    boost::asio::awaitable<bool> tcp_connect(boost::asio::ip::tcp::socket &socket, boost::system::error_code &ec)
    {
        boost::asio::ip::tcp::resolver res(pool_.get_io_context());
        auto [er, eps] = co_await res.async_resolve(r_host_, r_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            ec = er;
            co_return false;
        }

        auto [ec_conn, ep] = co_await boost::asio::async_connect(socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_conn)
        {
            ec = ec_conn;
            co_return false;
        }

        ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        LOG_DEBUG("tcp connected {} <-> {}", socket.local_endpoint().address().to_string(), ep.address().to_string());
        co_return true;
    }

    boost::asio::awaitable<std::pair<bool, handshake_result>> perform_reality_handshake(boost::asio::ip::tcp::socket &socket,
                                                                                        boost::system::error_code &ec)
    {
        uint8_t cpub[32];
        uint8_t cpriv[32];
        reality::crypto_util::generate_x25519_keypair(cpub, cpriv);

        const transcript_t trans;
        if (!co_await generate_and_send_client_hello(socket, cpub, cpriv, trans, ec))
        {
            co_return std::make_pair(false, handshake_result{});
        }

        auto [sh_ok, hs_keys] = co_await process_server_hello(socket, cpriv, trans, ec);
        if (!sh_ok)
        {
            co_return std::make_pair(false, handshake_result{});
        }

        auto c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        auto s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

        auto [loop_ok, app_sec] = co_await handshake_read_loop(socket, s_hs_keys, hs_keys, trans, ec);
        if (!loop_ok)
        {
            co_return std::make_pair(false, handshake_result{});
        }

        if (!co_await send_client_finished(socket, c_hs_keys, hs_keys.client_handshake_traffic_secret, trans, ec))
        {
            co_return std::make_pair(false, handshake_result{});
        }

        co_return std::make_pair(true, handshake_result{.c_app_secret = app_sec.first, .s_app_secret = app_sec.second});
    }

    boost::asio::awaitable<bool> generate_and_send_client_hello(
        boost::asio::ip::tcp::socket &socket, const uint8_t *cpub, const uint8_t *cpriv, const transcript_t &trans, boost::system::error_code &ec)
    {
        auto shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(cpriv, cpriv + 32), server_pub_key_, ec);
        if (ec)
        {
            co_return false;
        }

        std::vector<uint8_t> crand(32);
        RAND_bytes(crand.data(), 32);
        const std::vector<uint8_t> salt(crand.begin(), crand.begin() + 20);
        auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459", ec);
        auto prk = reality::crypto_util::hkdf_extract(salt, shared, ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 32, ec);

        std::vector<uint8_t> payload(16);
        payload[0] = 1;
        payload[1] = 8;
        auto now = static_cast<uint32_t>(time(nullptr));
        payload[4] = (now >> 24) & 0xFF;
        payload[5] = (now >> 16) & 0xFF;
        payload[6] = (now >> 8) & 0xFF;
        payload[7] = now & 0xFF;
        RAND_bytes(payload.data() + 8, 8);

        auto hello_aad = reality::construct_client_hello(crand, std::vector<uint8_t>(32, 0), std::vector<uint8_t>(cpub, cpub + 32), sni_);
        auto sid = reality::crypto_util::aes_gcm_encrypt(auth_key, std::vector<uint8_t>(crand.begin() + 20, crand.end()), payload, hello_aad, ec);

        std::vector<uint8_t> ch = hello_aad;
        std::memcpy(ch.data() + 39, sid.data(), 32);
        auto ch_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, static_cast<uint16_t>(ch.size()));
        ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());

        LOG_DEBUG("sending client hello record size {}", ch_rec.size());
        auto [we, wn] = co_await boost::asio::async_write(socket, boost::asio::buffer(ch_rec), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return false;
        }

        trans.update(ch);
        co_return true;
    }

    static boost::asio::awaitable<std::pair<bool, reality::handshake_keys>> process_server_hello(boost::asio::ip::tcp::socket &socket,
                                                                                                 const uint8_t *cpriv,
                                                                                                 const transcript_t &trans,
                                                                                                 boost::system::error_code &ec)
    {
        uint8_t hbuf[5];
        auto [re1, rn1] = co_await boost::asio::async_read(socket, boost::asio::buffer(hbuf, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re1)
        {
            ec = re1;
            co_return std::make_pair(false, reality::handshake_keys{});
        }

        auto sh_len = static_cast<uint16_t>((hbuf[3] << 8) | hbuf[4]);
        std::vector<uint8_t> sh_data(sh_len);
        auto [re2, rn2] = co_await boost::asio::async_read(socket, boost::asio::buffer(sh_data), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re2)
        {
            ec = re2;
            co_return std::make_pair(false, reality::handshake_keys{});
        }
        LOG_DEBUG("server hello received size {}", sh_len);

        trans.update(sh_data);
        auto spub = reality::extract_server_public_key(sh_data);
        if (spub.empty())
        {
            ec = boost::asio::error::invalid_argument;
            co_return std::make_pair(false, reality::handshake_keys{});
        }

        auto hs_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(cpriv, cpriv + 32), spub, ec);
        auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(hs_shared, trans.finish(), ec);
        co_return std::make_pair(true, hs_keys);
    }

    static boost::asio::awaitable<std::pair<bool, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>> handshake_read_loop(
        boost::asio::ip::tcp::socket &socket,
        const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &s_hs_keys,
        const reality::handshake_keys &hs_keys,
        const transcript_t &trans,
        boost::system::error_code &ec)
    {
        bool handshake_fin = false;
        uint64_t seq = 0;
        std::vector<uint8_t> handshake_buffer;

        while (!handshake_fin)
        {
            uint8_t rh[5];
            auto [re3, rn3] = co_await boost::asio::async_read(socket, boost::asio::buffer(rh, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re3)
            {
                ec = re3;
                co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
            }
            auto rlen = static_cast<uint16_t>((rh[3] << 8) | rh[4]);
            std::vector<uint8_t> rec(rlen);
            co_await boost::asio::async_read(socket, boost::asio::buffer(rec), boost::asio::as_tuple(boost::asio::use_awaitable));

            if (rh[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                continue;
            }

            std::vector<uint8_t> cth(5 + rlen);
            std::memcpy(cth.data(), rh, 5);
            std::memcpy(cth.data() + 5, rec.data(), rlen);
            uint8_t type;
            auto pt = reality::tls_record_layer::decrypt_record(s_hs_keys.first, s_hs_keys.second, seq++, cth, type, ec);
            if (ec)
            {
                co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
            }

            if (type == reality::CONTENT_TYPE_HANDSHAKE)
            {
                handshake_buffer.insert(handshake_buffer.end(), pt.begin(), pt.end());
                uint32_t offset = 0;
                while (offset + 4 <= handshake_buffer.size())
                {
                    uint8_t msg_type = handshake_buffer[offset];
                    uint32_t msg_len = (handshake_buffer[offset + 1] << 16) | (handshake_buffer[offset + 2] << 8) | handshake_buffer[offset + 3];
                    if (offset + 4 + msg_len > handshake_buffer.size())
                    {
                        break;
                    }

                    trans.update(std::vector<uint8_t>(handshake_buffer.begin() + offset, handshake_buffer.begin() + offset + 4 + msg_len));
                    if (msg_type == 0x14)
                    {
                        handshake_fin = true;
                    }
                    offset += 4 + msg_len;
                }
                handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + offset);
            }
        }

        auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
        co_return std::make_pair(true, app_sec);
    }

    static boost::asio::awaitable<bool> send_client_finished(boost::asio::ip::tcp::socket &socket,
                                                             const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &c_hs_keys,
                                                             const std::vector<uint8_t> &c_hs_secret,
                                                             const transcript_t &trans,
                                                             boost::system::error_code &ec)
    {
        auto c_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), ec);
        auto c_fin_msg = reality::construct_finished(c_fin_verify);
        auto c_fin_rec =
            reality::tls_record_layer::encrypt_record(c_hs_keys.first, c_hs_keys.second, 0, c_fin_msg, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        out_flight.insert(out_flight.end(), c_fin_rec.begin(), c_fin_rec.end());

        LOG_DEBUG("sending client finished flight size {}", out_flight.size());
        auto [we, wn] = co_await boost::asio::async_write(socket, boost::asio::buffer(out_flight), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return false;
        }
        co_return true;
    }

    boost::asio::awaitable<void> wait_retry() const
    {
        boost::asio::steady_timer timer(pool_.get_io_context());
        timer.expires_after(std::chrono::seconds(5));
        auto [ec] = co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        (void)ec;
    }

    boost::asio::awaitable<void> accept_local_loop()
    {
        auto ex = pool_.get_io_context().get_executor();
        boost::asio::ip::tcp::acceptor acceptor(ex, {boost::asio::ip::tcp::v4(), l_port_});
        LOG_INFO("local socks5 listening on {}", l_port_);
        for (;;)
        {
            boost::asio::ip::tcp::socket s(ex);
            auto [e] = co_await acceptor.async_accept(s, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!e)
            {
                boost::system::error_code ec;
                ec = s.set_option(boost::asio::ip::tcp::no_delay(true), ec);
                (void)ec;

                if (tunnel_manager_ != nullptr && tunnel_manager_->get_connection()->is_open())
                {
                    const uint32_t sid = next_session_id_.fetch_add(1, std::memory_order_relaxed);
                    std::make_shared<socks_session>(std::move(s), tunnel_manager_, sid)->start();
                }
                else
                {
                    LOG_WARN("rejecting local connection tunnel not ready");
                    boost::system::error_code ignore_ec;
                    ignore_ec = s.close(ignore_ec);
                    (void)ignore_ec;
                }
            }
        }
    }

   private:
    std::string r_host_;
    std::string r_port_;
    uint16_t l_port_;
    std::string sni_;
    io_context_pool &pool_;
    std::vector<uint8_t> server_pub_key_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
    std::atomic<uint32_t> next_session_id_{1};
};

}    // namespace mux

#endif
