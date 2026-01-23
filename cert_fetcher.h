#ifndef CERT_FETCHER_H
#define CERT_FETCHER_H

#include <vector>
#include <string>
#include <asio.hpp>
#include <sstream>
#include "log.h"
#include "transcript.h"
#include "reality_core.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"

namespace reality
{

class cert_fetcher
{
   public:
    static std::string hex(const std::vector<uint8_t>& data) { return crypto_util::bytes_to_hex(data); }
    static std::string hex(const uint8_t* data, size_t len) { return crypto_util::bytes_to_hex(std::vector<uint8_t>(data, data + len)); }

    static asio::awaitable<std::vector<uint8_t>> fetch(asio::any_io_executor ex, std::string host, uint16_t port, std::string sni)
    {
        LOG_INFO("starting fetch for {}:{} sni {}", host, port, sni);

        asio::ip::tcp::socket socket(ex);
        asio::ip::tcp::resolver resolver(ex);

        auto [res_ec, eps] = co_await resolver.async_resolve(host, std::to_string(port), asio::as_tuple(asio::use_awaitable));
        if (res_ec)
        {
            LOG_ERROR("resolve {}:{} failed {}", host, port, res_ec.message());
            co_return std::vector<uint8_t>{};
        }

        auto [conn_ec, ep] = co_await asio::async_connect(socket, eps, asio::as_tuple(asio::use_awaitable));
        if (conn_ec)
        {
            LOG_ERROR("connect {}:{} failed {}", host, port, conn_ec.message());
            co_return std::vector<uint8_t>{};
        }
        LOG_INFO("connected local {}:{} to {}:{} sni {}",
                 socket.local_endpoint().address().to_string(),
                 socket.local_endpoint().port(),
                 ep.address().to_string(),
                 ep.port(),
                 sni);

        uint8_t client_pub[32];
        uint8_t client_priv[32];
        crypto_util::generate_x25519_keypair(client_pub, client_priv);
        std::vector<uint8_t> client_random(32);
        RAND_bytes(client_random.data(), 32);
        std::vector<uint8_t> session_id(32);
        RAND_bytes(session_id.data(), 32);

        auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);

        std::erase_if(spec.cipher_suites, [](uint16_t cs) { return cs == 0x1302 || cs == 0x1303; });

        std::ostringstream cs_log;
        for (auto cs : spec.cipher_suites)
        {
            cs_log << " " << std::hex << cs;
        }

        LOG_INFO("{}:{} sending cipher suites{}", host, port, cs_log.str());

        auto ch = ClientHelloBuilder::build(spec, session_id, client_random, std::vector<uint8_t>(client_pub, client_pub + 32), sni);

        auto ch_rec = write_record_header(CONTENT_TYPE_HANDSHAKE, static_cast<uint16_t>(ch.size()));
        ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());
        co_await asio::async_write(socket, asio::buffer(ch_rec), asio::as_tuple(asio::use_awaitable));

        transcript trans;
        trans.update(ch);

        uint8_t head[5];
        auto [read_ec1, n1] = co_await asio::async_read(socket, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
        if (read_ec1)
        {
            LOG_ERROR("{}:{} read header failed", host, port);
            co_return std::vector<uint8_t>{};
        }

        uint16_t sh_rec_len = (head[3] << 8) | head[4];
        std::vector<uint8_t> sh_body(sh_rec_len);
        auto [read_ec2, n2] = co_await asio::async_read(socket, asio::buffer(sh_body), asio::as_tuple(asio::use_awaitable));
        if (read_ec2)
        {
            LOG_ERROR("{}:{} read body failed", host, port);
            co_return std::vector<uint8_t>{};
        }

        if (head[0] != CONTENT_TYPE_HANDSHAKE)
        {
            LOG_ERROR("{}:{} expected handshake type {}", host, port, head[0]);
            co_return std::vector<uint8_t>{};
        }
        if (sh_body.size() < 4)
        {
            LOG_ERROR("{}:{} server hello body too short", host, port);
            co_return std::vector<uint8_t>{};
        }

        uint32_t msg_len = (sh_body[1] << 16) | (sh_body[2] << 8) | sh_body[3];
        uint32_t full_msg_len = msg_len + 4;

        if (sh_body.size() < full_msg_len)
        {
            LOG_ERROR("{}:{} server hello incomplete", host, port);
            co_return std::vector<uint8_t>{};
        }

        std::vector<uint8_t> sh_real(sh_body.begin(), sh_body.begin() + full_msg_len);
        trans.update(sh_real);

        size_t cipher_offset = 39;
        if (sh_real.size() <= cipher_offset)
        {
            LOG_ERROR("{}:{} sh too short", host, port);
            co_return std::vector<uint8_t>{};
        }

        uint8_t sid_len_val = sh_real[38];
        cipher_offset += sid_len_val;

        if (sh_real.size() < cipher_offset + 2)
        {
            LOG_ERROR("{}:{} sh no cipher", host, port);
            co_return std::vector<uint8_t>{};
        }

        uint16_t cipher_suite = (sh_real[cipher_offset] << 8) | sh_real[cipher_offset + 1];

        const EVP_CIPHER* negotiated_cipher = EVP_aes_128_gcm();
        size_t key_len = 16;
        size_t iv_len = 12;

        if (cipher_suite == 0x1301)
        {
            LOG_INFO("{}:{} server selected aes 128 gcm perfect", host, port);
            negotiated_cipher = EVP_aes_128_gcm();
            key_len = 16;
        }
        else if (cipher_suite == 0x1303)
        {
            LOG_WARN("{}:{} server selected chacha20 unexpected", host, port);
            negotiated_cipher = EVP_chacha20_poly1305();
            key_len = 32;
        }
        else
        {
            LOG_ERROR("{}:{} unsupported cipher suite 0x{:04x}", host, port, cipher_suite);
            co_return std::vector<uint8_t>{};
        }

        auto server_pub = extract_server_public_key(sh_real);
        if (server_pub.empty())
        {
            LOG_ERROR("{}:{} failed to extract server public key", host, port);
            co_return std::vector<uint8_t>{};
        }

        std::error_code ec;
        auto shared = crypto_util::x25519_derive(std::vector<uint8_t>(client_priv, client_priv + 32), server_pub, ec);
        if (ec)
        {
            LOG_ERROR("{}:{} x25519 derive failed {}", host, port, ec.message());
            co_return std::vector<uint8_t>{};
        }

        auto hs_keys = tls_key_schedule::derive_handshake_keys(shared, trans.finish(), ec);
        if (ec)
        {
            LOG_ERROR("{}:{} {}", host, port, ec.message());
            co_return std::vector<uint8_t>{};
        }

        auto c_hs_keys = tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len);
        auto s_hs_keys = tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len);

        std::vector<uint8_t> handshake_buffer;
        uint64_t seq = 0;

        for (int i = 0; i < 100; ++i)
        {
            auto [re_h, rn_h] = co_await asio::async_read(socket, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
            if (re_h)
            {
                break;
            }

            uint16_t len = (head[3] << 8) | head[4];
            std::vector<uint8_t> rec(len);
            auto [re_b, rn_b] = co_await asio::async_read(socket, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));
            if (re_b)
            {
                break;
            }

            if (head[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                continue;
            }
            if (head[0] == CONTENT_TYPE_ALERT)
            {
                LOG_WARN("{}:{} received alert", host, port);
                break;
            }

            if (head[0] == CONTENT_TYPE_APPLICATION_DATA)
            {
                std::vector<uint8_t> cth(5 + len);
                std::memcpy(cth.data(), head, 5);
                std::memcpy(cth.data() + 5, rec.data(), len);

                uint8_t type;
                auto pt = tls_record_layer::decrypt_record(negotiated_cipher, s_hs_keys.first, s_hs_keys.second, seq++, cth, type, ec);

                if (ec)
                {
                    LOG_ERROR("{}:{} decrypt failed at record {} len {} {}", host, port, i, len, ec.message());
                    break;
                }

                if (type == CONTENT_TYPE_HANDSHAKE)
                {
                    handshake_buffer.insert(handshake_buffer.end(), pt.begin(), pt.end());

                    uint32_t offset = 0;
                    while (offset + 4 <= handshake_buffer.size())
                    {
                        uint8_t msg_type = handshake_buffer[offset];
                        uint32_t msg_len_val =
                            (handshake_buffer[offset + 1] << 16) | (handshake_buffer[offset + 2] << 8) | handshake_buffer[offset + 3];

                        if (offset + 4 + msg_len_val > handshake_buffer.size())
                        {
                            break;
                        }

                        if (msg_type == 0x08)
                        {
                            std::vector<uint8_t> msg(handshake_buffer.begin() + offset, handshake_buffer.begin() + offset + 4 + msg_len_val);
                            trans.update(msg);
                        }
                        else if (msg_type == 0x0b)
                        {
                            LOG_INFO("found certificate message len {}", msg_len_val);
                            co_return std::vector<uint8_t>(handshake_buffer.begin() + offset, handshake_buffer.begin() + offset + 4 + msg_len_val);
                        }
                        offset += 4 + msg_len_val;
                    }
                    if (offset > 0)
                    {
                        handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + offset);
                    }
                }
            }
        }

        LOG_WARN("{}:{} certificate not found after 10 records", host, port);
        co_return std::vector<uint8_t>{};
    }
};

}    // namespace reality

#endif
