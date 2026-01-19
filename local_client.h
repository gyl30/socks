#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <vector>
#include <memory>
#include <asio.hpp>

#include "log.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "context_pool.h"
#include "reality_core.h"
#include "socks_session.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"

namespace mux
{

class local_client : public std::enable_shared_from_this<local_client>
{
   public:
    local_client(io_context_pool &pool, std::string host, std::string port, uint16_t l_port, const std::string &key_hex, std::string sni)
        : remote_host_(std::move(host)),
          remote_port_(std::move(port)),
          listen_port_(l_port),
          sni_(std::move(sni)),
          pool_(pool),
          remote_timer_(pool.get_io_context()),
          acceptor_(remote_timer_.get_executor()),
          stop_channel_(remote_timer_.get_executor(), 1)
    {
        server_pub_key_ = reality::crypto_util::hex_to_bytes(key_hex);
    }

    void start()
    {
        LOG_INFO("client starting target {} port {} listening {}", remote_host_, remote_port_, listen_port_);
        asio::co_spawn(
            remote_timer_.get_executor(),
            [this, self = shared_from_this()]() -> asio::awaitable<void>
            {
                using asio::experimental::awaitable_operators::operator||;
                co_await (connect_remote_loop() || accept_local_loop() || wait_stop());
            },
            asio::detached);
    }

    void stop()
    {
        LOG_INFO("client stopping, closing resources");
        std::error_code ignore;
        ignore = acceptor_.close(ignore);
        (void)ignore;
        stop_channel_.cancel();
        remote_timer_.cancel();

        if (tunnel_manager_ && tunnel_manager_->get_connection())
        {
            tunnel_manager_->get_connection()->stop();
        }
    }

   private:
    struct handshake_result
    {
        std::vector<uint8_t> c_app_secret;
        std::vector<uint8_t> s_app_secret;
    };

    asio::awaitable<void> connect_remote_loop()
    {
        while (!stop_)
        {
            uint32_t cid = next_conn_id_++;
            LOG_INFO("reality handshake initiating conn_id {}", cid);

            std::error_code ec;
            auto socket = std::make_shared<asio::ip::tcp::socket>(pool_.get_io_context());

            if (!co_await tcp_connect(*socket, ec))
            {
                LOG_ERROR("connect failed {} retry in 5s", ec.message());
                co_await wait_remote_retry();
                continue;
            }

            auto [hs_ok, hs_res] = co_await perform_reality_handshake(*socket, ec);
            if (!hs_ok)
            {
                LOG_ERROR("handshake failed {} retry in 5s", ec.message());
                co_await wait_remote_retry();
                continue;
            }

            auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(hs_res.c_app_secret, ec);
            auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(hs_res.s_app_secret, ec);

            LOG_INFO("reality handshake success tunnel active id {}", cid);
            reality_engine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second);
            tunnel_manager_ = std::make_shared<mux_tunnel_impl<asio::ip::tcp::socket>>(std::move(*socket), std::move(re), true, cid);

            co_await tunnel_manager_->run();

            co_await wait_remote_retry();
        }
        LOG_INFO("connect_remote_loop exited");
    }

    asio::awaitable<bool> tcp_connect(asio::ip::tcp::socket &socket, std::error_code &ec) const
    {
        asio::ip::tcp::resolver res(pool_.get_io_context());
        auto [er, eps] = co_await res.async_resolve(remote_host_, remote_port_, asio::as_tuple(asio::use_awaitable));
        if (er)
        {
            ec = er;
            co_return false;
        }

        auto [ec_conn, ep] = co_await asio::async_connect(socket, eps, asio::as_tuple(asio::use_awaitable));
        if (ec_conn)
        {
            ec = ec_conn;
            co_return false;
        }

        ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
        LOG_DEBUG("tcp connected {} <-> {}", socket.local_endpoint().address().to_string(), ep.address().to_string());
        co_return true;
    }

    asio::awaitable<std::pair<bool, handshake_result>> perform_reality_handshake(asio::ip::tcp::socket &socket, std::error_code &ec) const
    {
        uint8_t public_key[32];
        uint8_t private_key[32];
        reality::crypto_util::generate_x25519_keypair(public_key, private_key);

        const reality::transcript trans;
        if (!co_await generate_and_send_client_hello(socket, public_key, private_key, trans, ec))
        {
            co_return std::make_pair(false, handshake_result{});
        }

        auto [sh_ok, hs_keys] = co_await process_server_hello(socket, private_key, trans, ec);
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

    asio::awaitable<bool> generate_and_send_client_hello(asio::ip::tcp::socket &socket,
                                                         const uint8_t *public_key,
                                                         const uint8_t *private_key,
                                                         const reality::transcript &trans,
                                                         std::error_code &ec) const
    {
        auto shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), server_pub_key_, ec);
        if (ec)
        {
            co_return false;
        }

        std::vector<uint8_t> client_random(32);
        RAND_bytes(client_random.data(), 32);
        const std::vector<uint8_t> salt(client_random.begin(), client_random.begin() + 20);
        auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
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

        auto hello_aad =
            reality::construct_client_hello(client_random, std::vector<uint8_t>(32, 0), std::vector<uint8_t>(public_key, public_key + 32), sni_);
        auto sid = reality::crypto_util::aes_gcm_encrypt(
            auth_key, std::vector<uint8_t>(client_random.begin() + 20, client_random.end()), payload, hello_aad, ec);

        std::vector<uint8_t> ch = hello_aad;
        std::memcpy(ch.data() + 39, sid.data(), 32);
        auto ch_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, static_cast<uint16_t>(ch.size()));
        ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());

        LOG_DEBUG("sending client hello record size {}", ch_rec.size());
        auto [we, wn] = co_await asio::async_write(socket, asio::buffer(ch_rec), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return false;
        }

        trans.update(ch);
        co_return true;
    }

    static asio::awaitable<std::pair<bool, reality::handshake_keys>> process_server_hello(asio::ip::tcp::socket &socket,
                                                                                          const uint8_t *private_key,
                                                                                          const reality::transcript &trans,
                                                                                          std::error_code &ec)
    {
        uint8_t data[5];
        auto [re1, rn1] = co_await asio::async_read(socket, asio::buffer(data, 5), asio::as_tuple(asio::use_awaitable));
        if (re1)
        {
            ec = re1;
            co_return std::make_pair(false, reality::handshake_keys{});
        }

        auto sh_len = static_cast<uint16_t>((data[3] << 8) | data[4]);
        std::vector<uint8_t> sh_data(sh_len);
        auto [re2, rn2] = co_await asio::async_read(socket, asio::buffer(sh_data), asio::as_tuple(asio::use_awaitable));
        if (re2)
        {
            ec = re2;
            co_return std::make_pair(false, reality::handshake_keys{});
        }
        LOG_DEBUG("server hello received size {}", sh_len);

        trans.update(sh_data);
        auto public_key = reality::extract_server_public_key(sh_data);
        if (public_key.empty())
        {
            ec = asio::error::invalid_argument;
            co_return std::make_pair(false, reality::handshake_keys{});
        }

        auto hs_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), public_key, ec);

        auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(hs_shared, trans.finish(), ec);
        co_return std::make_pair(true, hs_keys);
    }

    static asio::awaitable<std::pair<bool, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>> handshake_read_loop(
        asio::ip::tcp::socket &socket,
        const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &s_hs_keys,
        const reality::handshake_keys &hs_keys,
        const reality::transcript &trans,
        std::error_code &ec)
    {
        bool handshake_fin = false;
        uint64_t seq = 0;
        std::vector<uint8_t> handshake_buffer;

        reality::openssl_ptrs::evp_pkey_ptr server_pub_key(nullptr);

        while (!handshake_fin)
        {
            uint8_t rh[5];
            auto [re3, rn3] = co_await asio::async_read(socket, asio::buffer(rh, 5), asio::as_tuple(asio::use_awaitable));
            if (re3)
            {
                ec = re3;
                co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
            }
            const auto n = static_cast<uint16_t>((rh[3] << 8) | rh[4]);
            std::vector<uint8_t> rec(n);
            co_await asio::async_read(socket, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));

            if (rh[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                continue;
            }

            std::vector<uint8_t> cth(5 + n);
            std::memcpy(cth.data(), rh, 5);
            std::memcpy(cth.data() + 5, rec.data(), n);
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
                    const uint8_t msg_type = handshake_buffer[offset];
                    const uint32_t msg_len =
                        (handshake_buffer[offset + 1] << 16) | (handshake_buffer[offset + 2] << 8) | handshake_buffer[offset + 3];
                    if (offset + 4 + msg_len > handshake_buffer.size())
                    {
                        break;
                    }

                    std::vector<uint8_t> msg_data(handshake_buffer.begin() + offset, handshake_buffer.begin() + offset + 4 + msg_len);

                    if (msg_type == 0x0b)
                    {
                        if (msg_data.size() > 10)
                        {
                            uint32_t ptr = 4;
                            uint8_t ctx_len = msg_data[ptr];
                            ptr += 1 + ctx_len;

                            if (ptr + 3 <= msg_data.size())
                            {
                                ptr += 3;
                                if (ptr + 3 <= msg_data.size())
                                {
                                    uint32_t cert_len = (msg_data[ptr] << 16) | (msg_data[ptr + 1] << 8) | msg_data[ptr + 2];
                                    ptr += 3;
                                    if (ptr + cert_len <= msg_data.size())
                                    {
                                        std::vector<uint8_t> cert_der(msg_data.begin() + ptr, msg_data.begin() + ptr + cert_len);
                                        server_pub_key = reality::crypto_util::extract_pubkey_from_cert(cert_der, ec);
                                        if (ec)
                                        {
                                            LOG_ERROR("failed to extract public key from certificate");
                                            co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
                                        }
                                        LOG_DEBUG("extracted server public key from certificate message");
                                    }
                                }
                            }
                        }

                        trans.update(msg_data);
                    }
                    else if (msg_type == 0x0f)
                    {
                        if (!server_pub_key)
                        {
                            LOG_ERROR("received certificate verify but no public key found");
                            ec = asio::error::no_permission;
                            co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
                        }

                        if (msg_data.size() > 8)
                        {
                            uint32_t sig_len = (msg_data[6] << 8) | msg_data[7];
                            if (4 + 2 + 2 + sig_len == msg_data.size())
                            {
                                std::vector<uint8_t> signature(msg_data.begin() + 8, msg_data.end());

                                auto transcript_hash = trans.finish();

                                if (!reality::crypto_util::verify_tls13_signature(server_pub_key.get(), transcript_hash, signature, ec))
                                {
                                    LOG_ERROR("certificateVerify signature verification failed");
                                    co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
                                }
                                LOG_INFO("certificateVerify signature verified successfully");
                            }
                            else
                            {
                                ec = asio::error::message_size;
                                co_return std::make_pair(false, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>{});
                            }
                        }

                        trans.update(msg_data);
                    }
                    else
                    {
                        trans.update(msg_data);
                    }

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

    static asio::awaitable<bool> send_client_finished(asio::ip::tcp::socket &socket,
                                                      const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &c_hs_keys,
                                                      const std::vector<uint8_t> &c_hs_secret,
                                                      const reality::transcript &trans,
                                                      std::error_code &ec)
    {
        auto c_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), ec);
        auto c_fin_msg = reality::construct_finished(c_fin_verify);
        auto c_fin_rec =
            reality::tls_record_layer::encrypt_record(c_hs_keys.first, c_hs_keys.second, 0, c_fin_msg, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        out_flight.insert(out_flight.end(), c_fin_rec.begin(), c_fin_rec.end());

        LOG_DEBUG("sending client finished flight size {}", out_flight.size());
        auto [we, wn] = co_await asio::async_write(socket, asio::buffer(out_flight), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return false;
        }
        co_return true;
    }

    asio::awaitable<void> wait_remote_retry()
    {
        if (stop_)
        {
            co_return;
        }
        remote_timer_.expires_after(std::chrono::seconds(5));
        auto [ec] = co_await remote_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("remote retry timer error {}", ec.message());
        }
    }

    asio::awaitable<void> wait_stop()
    {
        auto [ec, msg] = co_await stop_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("stop error {}", ec.message());
        }
        stop_ = true;
        LOG_INFO("stop channel received");
    }

    asio::awaitable<void> accept_local_loop()
    {
        asio::ip::tcp::endpoint ep{asio::ip::tcp::v4(), listen_port_};
        std::error_code ec;
        ec = acceptor_.open(ep.protocol(), ec);
        if (ec)
        {
            LOG_ERROR("local acceptor open failed {}", ec.message());
            co_return;
        }
        ec = acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
        if (ec)
        {
            LOG_ERROR("local acceptor set reuse_address failed {}", ec.message());
            co_return;
        }
        ec = acceptor_.bind(ep, ec);
        if (ec)
        {
            LOG_ERROR("local acceptor bind failed {}", ec.message());
            co_return;
        }
        ec = acceptor_.listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERROR("local acceptor listen failed {}", ec.message());
            co_return;
        }

        LOG_INFO("local socks5 listening on {}", listen_port_);
        while (!stop_)
        {
            asio::ip::tcp::socket s(pool_.get_io_context().get_executor());
            auto [e] = co_await acceptor_.async_accept(s, asio::as_tuple(asio::use_awaitable));
            if (e)
            {
                LOG_ERROR("local accept failed {}", e.message());
                break;
            }

            ec = s.set_option(asio::ip::tcp::no_delay(true), ec);
            if (ec)
            {
                LOG_WARN("failed to set no_delay on local socket {}", ec.message());
            }

            if (tunnel_manager_ != nullptr && tunnel_manager_->get_connection()->is_open())
            {
                const uint32_t sid = next_session_id_++;
                std::make_shared<socks_session>(std::move(s), tunnel_manager_, sid)->start();
            }
            else
            {
                LOG_WARN("rejecting local connection tunnel not ready");
                std::error_code ignore_ec;
                ignore_ec = s.close(ignore_ec);
                (void)ignore_ec;
            }
        }
        LOG_INFO("accept_local_loop exited");
    }

   private:
    bool stop_ = false;
    std::string remote_host_;
    std::string remote_port_;
    uint16_t listen_port_;
    std::string sni_;
    io_context_pool &pool_;
    std::vector<uint8_t> server_pub_key_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
    uint32_t next_conn_id_{1};
    uint32_t next_session_id_{1};
    asio::steady_timer remote_timer_;
    asio::ip::tcp::acceptor acceptor_;
    asio::experimental::concurrent_channel<void(std::error_code, int)> stop_channel_;
};

}    // namespace mux

#endif
