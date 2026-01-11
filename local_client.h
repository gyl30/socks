#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <boost/asio.hpp>
#include <vector>
#include <array>
#include <iomanip>
#include <atomic>

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
            LOG_ERROR("socks {} invalid version or read error {}", sid_, e1.message());
            co_return false;
        }

        std::vector<uint8_t> methods(ver_nmethods[1]);
        auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::as_tuple(boost::asio::use_awaitable));

        if (e2)
        {
            LOG_ERROR("socks {} methods read error {}", sid_, e2.message());
            co_return false;
        }

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

    [[nodiscard]] boost::asio::awaitable<request_info_t> read_request_header()
    {
        uint8_t head[4];
        auto [e4, n4] = co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::as_tuple(boost::asio::use_awaitable));

        if (e4)
        {
            LOG_ERROR("socks {} request header read error {}", sid_, e4.message());
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        std::string host;
        if (head[3] == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type b;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
            {
                co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
            }
            host = boost::asio::ip::address_v4(b).to_string();
        }
        else if (head[3] == socks::ATYP_DOMAIN)
        {
            uint8_t len;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
            {
                co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
            }
            host.resize(len);
            auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(host), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
            {
                co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
            }
        }
        else if (head[3] == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type b;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
            {
                co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
            }
            host = boost::asio::ip::address_v6(b).to_string();
        }
        else
        {
            LOG_WARN("socks {} address type not supported", sid_);
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        uint16_t port_n;
        auto [e5, n5] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&port_n, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e5)
        {
            co_return request_info_t{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        const uint16_t port = ntohs(port_n);
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
            LOG_WARN("socks {} cmd not supported", sid_);
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

        const syn_payload syn{.socks_cmd_ = socks::CMD_CONNECT, .addr_ = host, .port_ = port};
        if (auto ec = co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_SYN, syn.encode()))
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
        if (!ack_payload::decode(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep_ != socks::REP_SUCCESS)
        {
            LOG_WARN("socks {} stream remote rejected connection", sid_);
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
        for (;;)
        {
            boost::system::error_code e;
            auto n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, e));
            if (e || n == 0)
            {
                break;
            }
            e = co_await stream->async_write_some(buf.data(), n);
            if (e)
            {
                break;
            }
        }
        co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_FIN, {});
    }

    boost::asio::awaitable<void> downstream_tcp(std::shared_ptr<mux_stream> stream)
    {
        for (;;)
        {
            auto [e, data] = co_await stream->async_read_some();
            if (e || data.empty())
            {
                boost::system::error_code ignore;
                ignore = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
                break;
            }
            auto [we, wn] = co_await boost::asio::async_write(socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
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
            LOG_ERROR("socks {} udp bind failed {}", sid_, ec.message());
            uint8_t err[] = {socks::VER, socks::REP_GEN_FAIL, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_return;
        }

        auto local_ep = udp_sock.local_endpoint(ec);
        auto stream = tunnel_manager_->create_stream();
        if (stream == nullptr)
        {
            co_return;
        }

        const syn_payload syn{.socks_cmd_ = socks::CMD_UDP_ASSOCIATE, .addr_ = "0.0.0.0", .port_ = 0};
        ec = co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_SYN, syn.encode());
        if (ec)
        {
            co_await stream->close();
            co_return;
        }

        auto [ack_ec, ack_data] = co_await stream->async_read_some();
        if (ack_ec)
        {
            co_await stream->close();
            co_return;
        }

        LOG_INFO("socks {} stream {} udp associate ready", sid_, stream->id());

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
        co_await (udp_sock_to_stream(udp_sock, stream, client_ep_ptr) || stream_to_udp_sock(udp_sock, stream, client_ep_ptr) || keep_tcp_alive());

        co_await stream->close();
    }

    static boost::asio::awaitable<void> udp_sock_to_stream(boost::asio::ip::udp::socket& udp_sock,
                                                           std::shared_ptr<mux_stream> stream,
                                                           std::shared_ptr<boost::asio::ip::udp::endpoint> client_ep)
    {
        std::vector<uint8_t> buf(65535);
        boost::asio::ip::udp::endpoint sender;
        for (;;)
        {
            auto [ec, n] = co_await udp_sock.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                break;
            }
            *client_ep = sender;
            ec = co_await stream->async_write_some(buf.data(), n);
            if (ec)
            {
                break;
            }
        }
    }

    static boost::asio::awaitable<void> stream_to_udp_sock(boost::asio::ip::udp::socket& udp_sock,
                                                           std::shared_ptr<mux_stream> stream,
                                                           std::shared_ptr<boost::asio::ip::udp::endpoint> client_ep)
    {
        for (;;)
        {
            auto [ec, data] = co_await stream->async_read_some();
            if (ec || data.empty())
            {
                break;
            }
            if (client_ep->port() == 0)
            {
                continue;
            }
            co_await udp_sock.async_send_to(boost::asio::buffer(data), *client_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
        }
    }

    boost::asio::awaitable<void> keep_tcp_alive()
    {
        char b[1];
        co_await socket_.async_read_some(boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    uint32_t sid_;
};

class local_client
{
   public:
    local_client(io_context_pool& pool,
                 std::string host,
                 std::string port,
                 uint16_t l_port,
                 const std::string& key_hex,
                 std::string sni,
                 boost::system::error_code& ec)
        : pool_(pool), r_host_(std::move(host)), r_port_(std::move(port)), l_port_(l_port), sni_(std::move(sni))
    {
        server_pub_key_ = reality::crypto_util::hex_to_bytes(key_hex, ec);
    }

    void start()
    {
        LOG_INFO("client starting target {} port {} listening {}", r_host_, r_port_, l_port_);
        boost::asio::co_spawn(
            pool_.get_io_context(), [this]() { return connect_remote_loop(); }, boost::asio::detached);
        boost::asio::co_spawn(
            pool_.get_io_context(), [this]() { return accept_local_loop(); }, boost::asio::detached);
    }

   private:
    class transcript_t
    {
       public:
        transcript_t() : ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { EVP_DigestInit(ctx_.get(), EVP_sha256()); }
        void update(const std::vector<uint8_t>& data) const { EVP_DigestUpdate(ctx_.get(), data.data(), data.size()); }
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

    boost::asio::awaitable<void> connect_remote_loop()
    {
        for (;;)
        {
            uint32_t cid = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
            LOG_INFO("reality handshake initiating conn_id {}", cid);
            boost::system::error_code ec;
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool_.get_io_context());
            boost::asio::ip::tcp::resolver res(pool_.get_io_context());
            auto [er, eps] = co_await res.async_resolve(r_host_, r_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (er)
            {
                LOG_ERROR("resolve failed {} retry in 5s", er.message());
                co_await wait_retry();
                continue;
            }

            auto [ec_conn, ep] = co_await boost::asio::async_connect(*socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_conn)
            {
                LOG_ERROR("connect failed {} retry in 5s", ec_conn.message());
                co_await wait_retry();
                continue;
            }

            ec = socket->set_option(boost::asio::ip::tcp::no_delay(true), ec);

            LOG_DEBUG("tcp connected sending client hello");
            uint8_t cpub[32];
            uint8_t cpriv[32];
            X25519_keypair(cpub, cpriv);
            auto shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(cpriv, cpriv + 32), server_pub_key_, ec);
            if (ec)
            {
                LOG_ERROR("x25519 shared secret error");
                co_await wait_retry();
                continue;
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
            co_await boost::asio::async_write(*socket, boost::asio::buffer(ch_rec), boost::asio::as_tuple(boost::asio::use_awaitable));

            const transcript_t trans;
            trans.update(ch);
            uint8_t hbuf[5];
            auto [re1, rn1] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(hbuf, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re1)
            {
                LOG_ERROR("read sh header error {}", re1.message());
                co_await wait_retry();
                continue;
            }

            auto sh_len = static_cast<uint16_t>((hbuf[3] << 8) | hbuf[4]);
            std::vector<uint8_t> sh_data(sh_len);
            auto [re2, rn2] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(sh_data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re2)
            {
                LOG_ERROR("read sh body error {}", re2.message());
                co_await wait_retry();
                continue;
            }
            LOG_DEBUG("server hello received size {}", sh_len);

            trans.update(sh_data);
            auto spub = reality::extract_server_public_key(sh_data);
            if (spub.empty())
            {
                LOG_ERROR("failed to extract server pubkey");
                co_await wait_retry();
                continue;
            }

            auto hs_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(cpriv, cpriv + 32), spub, ec);
            auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(hs_shared, trans.finish(), ec);
            auto c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
            auto s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

            bool handshake_fin = false;
            uint64_t seq = 0;
            std::vector<uint8_t> handshake_buffer;

            while (!handshake_fin)
            {
                uint8_t rh[5];
                auto [re3, rn3] =
                    co_await boost::asio::async_read(*socket, boost::asio::buffer(rh, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (re3)
                {
                    break;
                }
                auto rlen = static_cast<uint16_t>((rh[3] << 8) | rh[4]);
                std::vector<uint8_t> rec(rlen);
                co_await boost::asio::async_read(*socket, boost::asio::buffer(rec), boost::asio::as_tuple(boost::asio::use_awaitable));

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
                    LOG_ERROR("decrypt failed {}", ec.message());
                    break;
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
                        LOG_DEBUG("received handshake message type {} length {}", static_cast<int>(msg_type), msg_len);
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

            if (!handshake_fin)
            {
                LOG_ERROR("handshake incomplete");
                co_await wait_retry();
                continue;
            }

            auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
            auto c_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), ec);
            auto c_fin_msg = reality::construct_finished(c_fin_verify);
            auto c_fin_rec =
                reality::tls_record_layer::encrypt_record(c_hs_keys.first, c_hs_keys.second, 0, c_fin_msg, reality::CONTENT_TYPE_HANDSHAKE, ec);

            std::vector<uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
            out_flight.insert(out_flight.end(), c_fin_rec.begin(), c_fin_rec.end());
            co_await boost::asio::async_write(*socket, boost::asio::buffer(out_flight), boost::asio::as_tuple(boost::asio::use_awaitable));

            auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec);
            auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec);

            LOG_INFO("reality handshake success tunnel active id {}", cid);
            reality_engine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second);
            tunnel_manager_ = std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(std::move(*socket), std::move(re), true, cid);
            co_await tunnel_manager_->run();

            LOG_WARN("tunnel lost reconnecting in 5s");
            co_await wait_retry();
        }
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
                }
            }
        }
    }

    io_context_pool& pool_;
    std::string r_host_, r_port_;
    uint16_t l_port_;
    std::string sni_;
    std::vector<uint8_t> server_pub_key_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
    std::atomic<uint32_t> next_session_id_{1};
};

}    // namespace mux

#endif
