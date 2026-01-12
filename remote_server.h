#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include "mux_tunnel.h"
#include "protocol.h"
#include "context_pool.h"
#include "reality_messages.h"

namespace mux
{

struct client_hello_info_t
{
    std::vector<uint8_t> session_id, random, x25519_pub;
    std::string sni;
    bool is_tls13 = false;
    uint32_t sid_offset = 0;
};

class ch_parser
{
   public:
    [[nodiscard]] static client_hello_info_t parse(const std::vector<uint8_t> &buf)
    {
        client_hello_info_t info;
        reader r(buf);

        if (r.remaining() >= 5 && r.peek(0) == 0x16 && r.peek(1) == 0x03)
        {
            r.skip(5);
        }

        uint8_t type;
        if (!r.read_u8(type) || type != 0x01)
        {
            return info;
        }
        if (!r.skip(3 + 2))
        {
            return info;
        }

        if (!r.read_vector(info.random, 32))
        {
            return info;
        }

        uint8_t sid_len;

        const size_t sid_start_offset = r.offset() + 1;

        if (!r.read_u8(sid_len))
        {
            return info;
        }

        info.sid_offset = static_cast<uint32_t>(sid_start_offset);

        if (sid_len > 0)
        {
            if (!r.read_vector(info.session_id, sid_len))
            {
                return info;
            }
        }

        uint16_t cs_len;
        if (!r.read_u16(cs_len))
        {
            return info;
        }
        if (!r.skip(cs_len))
        {
            return info;
        }

        uint8_t comp_len;
        if (!r.read_u8(comp_len))
        {
            return info;
        }
        if (!r.skip(comp_len))
        {
            return info;
        }

        uint16_t ext_len;
        if (!r.read_u16(ext_len))
        {
            return info;
        }

        reader ext_r = r.slice(ext_len);
        if (ext_r.valid())
        {
            parse_extensions(ext_r, info);
        }

        return info;
    }

   private:
    struct reader
    {
        const uint8_t *ptr;
        const uint8_t *end;
        const uint8_t *start;

        explicit reader(const std::vector<uint8_t> &buf) : ptr(buf.data()), end(buf.data() + buf.size()), start(buf.data()) {}
        reader(const uint8_t *p, size_t len, const uint8_t *s) : ptr(p), end(p + len), start(s) {}

        [[nodiscard]] bool valid() const { return ptr != nullptr; }
        [[nodiscard]] bool has(size_t n) const { return ptr + n <= end; }
        [[nodiscard]] size_t remaining() const { return end - ptr; }
        [[nodiscard]] size_t offset() const { return ptr - start; }
        [[nodiscard]] uint8_t peek(size_t off) const { return ptr[off]; }

        bool skip(size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            ptr += n;
            return true;
        }

        bool read_u8(uint8_t &out)
        {
            if (!has(1))
            {
                return false;
            }
            out = *ptr++;
            return true;
        }

        bool read_u16(uint16_t &out)
        {
            if (!has(2))
            {
                return false;
            }
            out = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
            ptr += 2;
            return true;
        }

        bool read_vector(std::vector<uint8_t> &out, size_t n)
        {
            if (!has(n))
            {
                return false;
            }
            out.assign(ptr, ptr + n);
            ptr += n;
            return true;
        }

        reader slice(size_t n)
        {
            if (!has(n))
            {
                return {nullptr, 0, nullptr};
            }
            reader s(ptr, n, start);
            ptr += n;
            return s;
        }
    };

    static void parse_extensions(reader &r, client_hello_info_t &info)
    {
        while (r.remaining() >= 4)
        {
            uint16_t type;
            uint16_t len;
            if (!r.read_u16(type) || !r.read_u16(len))
            {
                break;
            }

            reader val = r.slice(len);
            if (!val.valid())
            {
                break;
            }

            if (type == 0x0000)
            {
                parse_sni(val, info);
            }
            else if (type == 0x0033)
            {
                parse_key_share(val, info);
            }
        }
    }

    static void parse_sni(reader &r, client_hello_info_t &info)
    {
        uint16_t list_len;
        if (!r.read_u16(list_len) || r.remaining() < list_len)
        {
            return;
        }

        while (r.remaining() >= 3)
        {
            uint8_t type = 0;
            uint16_t len = 0;
            r.read_u8(type);
            r.read_u16(len);

            if (type == 0x00 && r.has(len))
            {
                info.sni.assign(reinterpret_cast<const char *>(r.ptr), len);
                return;
            }
            r.skip(len);
        }
    }

    static void parse_key_share(reader &r, client_hello_info_t &info)
    {
        uint16_t share_len;
        if (!r.read_u16(share_len))
        {
            return;
        }

        while (r.remaining() >= 4)
        {
            uint16_t group = 0;
            uint16_t key_len = 0;
            r.read_u16(group);
            r.read_u16(key_len);

            if (group == 0x001d && key_len == 32)
            {
                if (r.has(32))
                {
                    info.x25519_pub.assign(r.ptr, r.ptr + 32);
                    info.is_tls13 = true;
                }
                return;
            }
            r.skip(key_len);
        }
    }
};

class remote_session : public mux_stream_interface, public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_connection> connection, uint32_t id, const boost::asio::any_io_executor &ex)
        : connection_(std::move(connection)), id_(id), resolver_(ex), target_socket_(ex), recv_channel_(ex, 128)
    {
    }

    boost::asio::awaitable<void> start(std::vector<uint8_t> syn_data)
    {
        syn_payload syn;
        if (!mux_codec::decode_syn(syn_data.data(), syn_data.size(), syn))
        {
            LOG_WARN("remote tcp {} failed to decode syn", id_);
            co_await connection_->send_async(id_, CMD_RST, {});
            co_return;
        }

        LOG_INFO("remote tcp {} connect target {} port {}", id_, syn.addr, syn.port);
        auto [er, eps] = co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            LOG_ERROR("remote tcp {} resolve failed {}", id_, er.message());
            const ack_payload ack{.socks_rep = socks::REP_HOST_UNREACH, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }

        auto [ec_conn, ep_conn] = co_await boost::asio::async_connect(target_socket_, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_conn)
        {
            LOG_ERROR("remote tcp {} connect failed {}", id_, ec_conn.message());
            const ack_payload ack{.socks_rep = socks::REP_CONN_REFUSED, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }

        boost::system::error_code ec_sock;
        ec_sock = target_socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec_sock);
        (void)ec_sock;
        LOG_DEBUG("remote tcp {} established local {} remote {}",
                  id_,
                  target_socket_.local_endpoint().address().to_string(),
                  ep_conn.address().to_string());

        const ack_payload ack_pl{.socks_rep = socks::REP_SUCCESS, .bnd_addr = ep_conn.address().to_string(), .bnd_port = ep_conn.port()};
        co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack_pl));

        using boost::asio::experimental::awaitable_operators::operator&&;
        co_await (upstream() && downstream());

        boost::system::error_code ignore;
        ignore = target_socket_.close(ignore);
        (void)ignore;
        if (manager_)
        {
            manager_->remove_stream(id_);
        }
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(boost::system::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        boost::system::error_code ec;
        ec = target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        (void)ec;
    }
    void on_reset() override
    {
        recv_channel_.close();
        target_socket_.close();
    }
    void set_manager(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> &m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> upstream()
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec || data.empty())
            {
                boost::system::error_code ignore;
                ignore = target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
                (void)ignore;
                break;
            }
            auto [we, wn] =
                co_await boost::asio::async_write(target_socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
    }

    boost::asio::awaitable<void> downstream()
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            boost::system::error_code re;
            const uint32_t n =
                co_await target_socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, re));
            if (re || n == 0)
            {
                break;
            }
            if (co_await connection_->send_async(id_, CMD_DAT, std::vector<uint8_t>(buf.begin(), buf.begin() + n)))
            {
                break;
            }
        }
        co_await connection_->send_async(id_, CMD_FIN, {});
    }

    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket target_socket_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager_;
};

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection, uint32_t id, const boost::asio::any_io_executor &ex)
        : connection_(std::move(connection)), id_(id), udp_socket_(ex), udp_resolver_(ex), recv_channel_(ex, 128)
    {
    }

    boost::asio::awaitable<void> start()
    {
        uint32_t cid = connection_->id();
        boost::system::error_code ec;
        ec = udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (!ec)
        {
            ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        }

        if (ec)
        {
            LOG_ERROR("srv {} stream {} udp open/bind failed {}", cid, id_, ec.message());
            ack_payload const ack{.socks_rep = socks::REP_GEN_FAIL, .bnd_addr = "", .bnd_port = 0};
            co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack));
            co_return;
        }

        auto local_ep = udp_socket_.local_endpoint(ec);
        LOG_INFO("srv {} stream {} udp session started, bound at {}", cid, id_, local_ep.address().to_string());

        const ack_payload ack_pl{.socks_rep = socks::REP_SUCCESS, .bnd_addr = "0.0.0.0", .bnd_port = 0};
        co_await connection_->send_async(id_, CMD_ACK, mux_codec::encode_ack(ack_pl));

        using boost::asio::experimental::awaitable_operators::operator&&;
        co_await (mux_to_udp() && udp_to_mux());

        if (manager_)
        {
            manager_->remove_stream(id_);
        }
        LOG_INFO("srv {} stream {} udp session finished", cid, id_);
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(boost::system::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        boost::system::error_code ignore;
        ignore = udp_socket_.close(ignore);
        (void)ignore;
    }
    void on_reset() override { on_close(); }
    void set_manager(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> &m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> mux_to_udp()
    {
        uint32_t cid = connection_->id();
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec || data.empty())
            {
                break;
            }
            socks_udp_header h;
            if (!socks_codec::decode_udp_header(data.data(), data.size(), h))
            {
                LOG_WARN("srv {} stream {} udp failed to decode header", cid, id_);
                continue;
            }

            auto [er, eps] = co_await udp_resolver_.async_resolve(h.addr, std::to_string(h.port), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!er)
            {
                auto target_ep = *eps.begin();
                LOG_DEBUG("srv {} stream {} udp forwarding {} bytes -> {}",
                          cid,
                          id_,
                          data.size() - h.header_len,
                          target_ep.endpoint().address().to_string());

                auto [se, sn] = co_await udp_socket_.async_send_to(boost::asio::buffer(data.data() + h.header_len, data.size() - h.header_len),
                                                                   target_ep,
                                                                   boost::asio::as_tuple(boost::asio::use_awaitable));
                if (se)
                {
                    LOG_WARN("srv {} stream {} udp send error {}", cid, id_, se.message());
                }
            }
            else
            {
                LOG_WARN("srv {} stream {} udp resolve error for {}", cid, id_, h.addr);
            }
        }
    }

    boost::asio::awaitable<void> udp_to_mux()
    {
        uint32_t cid = connection_->id();
        std::vector<uint8_t> buf(65535);
        boost::asio::ip::udp::endpoint ep;
        for (;;)
        {
            auto [re, n] = co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), ep, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re)
            {
                if (re != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("srv {} stream {} udp receive error {}", cid, id_, re.message());
                }
                break;
            }

            LOG_DEBUG("srv {} stream {} udp recv {} bytes from {}", cid, id_, n, ep.address().to_string());

            socks_udp_header h;
            h.addr = ep.address().to_string();
            h.port = ep.port();
            std::vector<uint8_t> pkt = socks_codec::encode_udp_header(h);
            pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<uint32_t>(n));
            if (co_await connection_->send_async(id_, CMD_DAT, std::move(pkt)))
            {
                break;
            }
        }
    }

    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager_;
};

class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    remote_server(io_context_pool &pool, uint16_t port, std::string fb_h, std::string fb_p, const std::string &key, boost::system::error_code &ec)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          fb_host_(std::move(fb_h)),
          fb_port_(std::move(fb_p))
    {
        priv_key_ = reality::crypto_util::hex_to_bytes(key, ec);
        if (!ec)
        {
            boost::system::error_code ignore;
            auto pub = reality::crypto_util::extract_public_key(priv_key_, ignore);
            LOG_INFO("server public key {}", reality::crypto_util::bytes_to_hex(pub));
        }
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached); }

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

    boost::asio::awaitable<void> accept_loop()
    {
        LOG_INFO("remote server listening for connections");
        for (;;)
        {
            auto s = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [e] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!e)
            {
                boost::system::error_code ec;
                ec = s->set_option(boost::asio::ip::tcp::no_delay(true), ec);
                (void)ec;
                const uint32_t conn_id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);

                boost::asio::co_spawn(
                    pool_.get_io_context(),
                    [this, s, self = shared_from_this(), conn_id = conn_id]() { return handle(s, conn_id); },
                    boost::asio::detached);
            }
        }
    }

    boost::asio::awaitable<void> handle(std::shared_ptr<boost::asio::ip::tcp::socket> s, uint32_t conn_id) const
    {
        auto [ok, buf] = co_await read_initial_and_validate(s, conn_id);
        if (!ok)
        {
            co_await handle_fallback(s, buf, conn_id);
            co_return;
        }

        auto info = ch_parser::parse(buf);
        auto [auth_ok, auth_key] = authenticate_client(info, buf, conn_id);

        if (!auth_ok)
        {
            co_await handle_fallback(s, buf, conn_id);
            co_return;
        }

        LOG_INFO("srv {} authorized proceeding sni {}", conn_id, info.sni);
        transcript_t const trans;

        if (buf.size() > 5)
        {
            trans.update(std::vector<uint8_t>(buf.begin() + 5, buf.end()));
        }
        else
        {
            LOG_ERROR("srv {} buffer too short for transcript", conn_id);
            co_return;
        }

        boost::system::error_code ec;
        auto [handshake_ok, hs_keys, s_hs_keys, c_hs_keys] = co_await perform_handshake_response(s, info, trans, auth_key, conn_id, ec);

        if (!handshake_ok)
        {
            LOG_ERROR("srv {} handshake response error {}", conn_id, ec.message());
            co_return;
        }

        if (!co_await verify_client_finished(s, c_hs_keys, hs_keys, trans, conn_id, ec))
        {
            co_return;
        }

        auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
        auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec);
        auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec);

        LOG_INFO("srv {} tunnel start", conn_id);
        reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second);
        auto tunnel = std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(std::move(*s), std::move(engine), false, conn_id);

        tunnel->get_connection()->set_syn_callback(
            [this, tunnel, conn_id](uint32_t id, const std::vector<uint8_t> &p)
            {
                boost::asio::co_spawn(
                    pool_.get_io_context(),
                    [this, tunnel, conn_id, id, p = p]() { return process_stream_request(tunnel, conn_id, id, p); },
                    boost::asio::detached);
            });

        co_await tunnel->run();
    }

    boost::asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel,
                                                        uint32_t conn_id,
                                                        uint32_t stream_id,
                                                        std::vector<uint8_t> payload) const
    {
        syn_payload syn;
        if (!mux_codec::decode_syn(payload.data(), payload.size(), syn))
        {
            LOG_WARN("srv {} stream {} invalid syn", conn_id, stream_id);
            co_return;
        }

        if (syn.socks_cmd == socks::CMD_CONNECT)
        {
            LOG_INFO("srv {} stream {} type TCP_CONNECT target {}:{}", conn_id, stream_id, syn.addr, syn.port);
            auto sess = std::make_shared<remote_session>(tunnel->get_connection(), stream_id, pool_.get_io_context().get_executor());
            sess->set_manager(tunnel);
            tunnel->register_stream(stream_id, sess);
            co_await sess->start(payload);
        }
        else if (syn.socks_cmd == socks::CMD_UDP_ASSOCIATE)
        {
            LOG_INFO("srv {} stream {} type UDP_ASSOCIATE associated via tcp", conn_id, stream_id);
            auto sess = std::make_shared<remote_udp_session>(tunnel->get_connection(), stream_id, pool_.get_io_context().get_executor());
            sess->set_manager(tunnel);
            tunnel->register_stream(stream_id, sess);
            co_await sess->start();
        }
        else
        {
            LOG_WARN("srv {} stream {} unknown cmd {}", conn_id, stream_id, syn.socks_cmd);
        }
    }

    static boost::asio::awaitable<std::pair<bool, std::vector<uint8_t>>> read_initial_and_validate(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                                                   uint32_t conn_id)
    {
        std::vector<uint8_t> buf(4096);
        auto [re, n] = co_await s->async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re)
        {
            LOG_ERROR("srv {} initial read error {}", conn_id, re.message());
            co_return std::make_pair(false, std::vector<uint8_t>{});
        }
        buf.resize(n);

        if (n < 5 || buf[0] != 0x16)
        {
            LOG_WARN("srv {} invalid tls header 0x{:02x}", conn_id, buf[0]);
            co_return std::make_pair(false, buf);
        }

        const size_t rlen = static_cast<uint16_t>((buf[3] << 8) | buf[4]);
        while (buf.size() < 5 + rlen)
        {
            std::vector<uint8_t> tmp(5 + rlen - buf.size());
            auto [re2, n2] = co_await boost::asio::async_read(*s, boost::asio::buffer(tmp), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re2)
            {
                co_return std::make_pair(false, buf);
            }
            buf.insert(buf.end(), tmp.begin(), tmp.end());
        }
        LOG_DEBUG("srv {} received client hello record size {}", conn_id, buf.size());
        co_return std::make_pair(true, buf);
    }

    std::pair<bool, std::vector<uint8_t>> authenticate_client(const client_hello_info_t &info,
                                                              const std::vector<uint8_t> &buf,
                                                              uint32_t conn_id) const
    {
        if (!info.is_tls13 || info.session_id.size() != 32)
        {
            LOG_WARN("srv {} not tls1.3 or invalid session id len {}", conn_id, info.session_id.size());
            return {false, {}};
        }

        boost::system::error_code ec;
        auto shared = reality::crypto_util::x25519_derive(priv_key_, info.x25519_pub, ec);
        if (ec)
        {
            LOG_ERROR("srv {} x25519 derive failed", conn_id);
            return {false, {}};
        }

        auto salt = std::vector<uint8_t>(info.random.begin(), info.random.begin() + 20);
        auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459", ec);
        auto prk = reality::crypto_util::hkdf_extract(salt, shared, ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 32, ec);

        auto aad = std::vector<uint8_t>(buf.begin() + 5, buf.end());

        if (info.sid_offset < 5)
        {
            return {false, {}};
        }
        const uint32_t aad_sid_offset = info.sid_offset - 5;

        if (aad_sid_offset + 32 > aad.size())
        {
            return {false, {}};
        }

        std::fill_n(aad.begin() + aad_sid_offset, 32, 0);

        auto pt = reality::crypto_util::aes_gcm_decrypt(
            auth_key, std::vector<uint8_t>(info.random.begin() + 20, info.random.end()), info.session_id, aad, ec);

        if (ec || pt.size() != 16)
        {
            LOG_WARN("srv {} auth decryption failed or bad size", conn_id);
            return {false, {}};
        }

        const uint32_t timestamp = (static_cast<uint32_t>(pt[4]) << 24) | (static_cast<uint32_t>(pt[5]) << 16) | (static_cast<uint32_t>(pt[6]) << 8) |
                                   static_cast<uint32_t>(pt[7]);
        auto now = static_cast<uint32_t>(time(nullptr));
        if (timestamp > now + 120 || timestamp < now - 120)
        {
            LOG_WARN("srv {} auth failed replay check ts {} now {}", conn_id, timestamp, now);
            return {false, {}};
        }

        return {true, auth_key};
    }

    struct server_handshake_res
    {
        bool ok;
        reality::handshake_keys hs_keys;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> s_hs_keys;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_hs_keys;
    };

    boost::asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                            const client_hello_info_t &info,
                                                                            const transcript_t &trans,
                                                                            const std::vector<uint8_t> &auth_key,
                                                                            uint32_t conn_id,
                                                                            boost::system::error_code &ec) const
    {
        uint8_t spub[32];
        uint8_t spriv[32];
        reality::crypto_util::generate_x25519_keypair(spub, spriv);
        std::vector<uint8_t> srand(32);
        RAND_bytes(srand.data(), 32);

        LOG_TRACE("srv {} generated ephemeral key {}", conn_id, reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(spub, spub + 32)));

        auto sh_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(spriv, spriv + 32), info.x25519_pub, ec);
        auto sh_msg = reality::construct_server_hello(srand, info.session_id, 0x1301, std::vector<uint8_t>(spub, spub + 32));
        trans.update(sh_msg);

        auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(sh_shared, trans.finish(), ec);
        auto c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        auto s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

        auto enc_ext = reality::construct_encrypted_extensions();
        trans.update(enc_ext);
        auto cert_der = cert_manager_.generate_reality_cert(auth_key);
        auto cert = reality::construct_certificate(cert_der);
        trans.update(cert);
        auto cv = reality::construct_certificate_verify(cert_manager_.get_key(), trans.finish());
        trans.update(cv);
        auto s_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), ec);
        auto s_fin = reality::construct_finished(s_fin_verify);
        trans.update(s_fin);

        std::vector<uint8_t> flight2_plain;
        flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
        flight2_plain.insert(flight2_plain.end(), cert.begin(), cert.end());
        flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
        flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

        auto flight2_enc =
            reality::tls_record_layer::encrypt_record(s_hs_keys.first, s_hs_keys.second, 0, flight2_plain, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> out_sh;
        auto sh_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, static_cast<uint16_t>(sh_msg.size()));
        out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
        out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
        out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
        out_sh.insert(out_sh.end(), flight2_enc.begin(), flight2_enc.end());

        LOG_DEBUG("srv {} sending server hello flight size {}", conn_id, out_sh.size());
        auto [we, wn] = co_await boost::asio::async_write(*s, boost::asio::buffer(out_sh), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return server_handshake_res{.ok = false, .hs_keys = {}, .s_hs_keys = {}, .c_hs_keys = {}};
        }

        co_return server_handshake_res{.ok = true, .hs_keys = hs_keys, .s_hs_keys = s_hs_keys, .c_hs_keys = c_hs_keys};
    }

    static boost::asio::awaitable<bool> verify_client_finished(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                               const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &c_hs_keys,
                                                               const reality::handshake_keys &hs_keys,
                                                               const transcript_t &trans,
                                                               uint32_t conn_id,
                                                               boost::system::error_code &ec)
    {
        uint8_t h[5];
        auto [re3, rn3] = co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re3)
        {
            LOG_ERROR("srv {} read client finished header error {}", conn_id, re3.message());
            co_return false;
        }

        if (h[0] == 0x14)
        {
            uint8_t dummy[1];
            co_await boost::asio::async_read(*s, boost::asio::buffer(dummy, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        }

        auto flen = static_cast<uint16_t>((h[3] << 8) | h[4]);
        std::vector<uint8_t> frec(flen);
        auto [re4, rn4] = co_await boost::asio::async_read(*s, boost::asio::buffer(frec), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re4)
        {
            LOG_ERROR("srv {} read client finished body error {}", conn_id, re4.message());
            co_return false;
        }

        std::vector<uint8_t> cth(5 + flen);
        std::memcpy(cth.data(), h, 5);
        std::memcpy(cth.data() + 5, frec.data(), flen);
        uint8_t ctype;
        auto pt = reality::tls_record_layer::decrypt_record(c_hs_keys.first, c_hs_keys.second, 0, cth, ctype, ec);

        if (ec || ctype != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("srv {} client finished verification failed type {}", conn_id, static_cast<int>(ctype));
            co_return false;
        }

        auto expected_fin_verify =
            reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), ec);
        if (pt.size() < expected_fin_verify.size() + 4 || std::memcmp(pt.data() + 4, expected_fin_verify.data(), expected_fin_verify.size()) != 0)
        {
            LOG_ERROR("srv {} client finished hmac verification failed", conn_id);
            co_return false;
        }
        co_return true;
    }

    boost::asio::awaitable<void> handle_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> s, std::vector<uint8_t> buf, uint32_t conn_id) const
    {
        boost::asio::ip::tcp::socket t(s->get_executor());
        boost::asio::ip::tcp::resolver r(s->get_executor());
        auto [er, eps] = co_await r.async_resolve(fb_host_, fb_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            LOG_ERROR("srv {} fallback resolve failed {}", conn_id, er.message());
            co_return;
        }

        auto [ec_c, ep_c] = co_await boost::asio::async_connect(t, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_c)
        {
            LOG_ERROR("srv {} fallback connect failed {}", conn_id, ec_c.message());
            co_return;
        }

        LOG_INFO("srv {} fallback proxying to {}:{}", conn_id, fb_host_, fb_port_);
        co_await boost::asio::async_write(t, boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));

        auto xfer = [](auto &f, auto &t) -> boost::asio::awaitable<void>
        {
            char d[4096];
            for (;;)
            {
                auto [re, n] = co_await f.async_read_some(boost::asio::buffer(d), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (re || n == 0)
                {
                    break;
                }
                auto [we, wn] = co_await boost::asio::async_write(t, boost::asio::buffer(d, n), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (we)
                {
                    break;
                }
            }
            boost::system::error_code ignore;
            f.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ignore);
            t.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
        };
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (xfer(*s, t) || xfer(t, *s));
    }

   private:
    io_context_pool &pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string fb_host_, fb_port_;
    std::vector<uint8_t> priv_key_;
    reality::cert_manager cert_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
};

}    // namespace mux

#endif
