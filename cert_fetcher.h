#ifndef CERT_FETCHER_H
#define CERT_FETCHER_H

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <system_error>

#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>

#include "transcript.h"
#include "log_context.h"
#include "reality_core.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"

namespace reality
{

struct fetch_result
{
    std::vector<std::uint8_t> cert_msg;
    server_fingerprint fingerprint;
};

class handshake_reassembler
{
   public:
    void append(std::span<const std::uint8_t> data);
    bool next(std::vector<std::uint8_t>& out, std::error_code& ec);

   private:
    std::vector<std::uint8_t> buffer_;
};

class cert_fetcher
{
   public:
    static std::string hex(const std::vector<std::uint8_t>& data);
    static std::string hex(const std::uint8_t* data, std::size_t len);

    static asio::awaitable<std::optional<fetch_result>> fetch(
        asio::io_context& io_context, std::string host, std::uint16_t port, std::string sni, const std::string& trace_id = "");

   private:
    class fetch_session
    {
       public:
        fetch_session(asio::io_context& io_context,
                      std::string host,
                      std::uint16_t port,
                      std::string sni,
                      const std::string& trace_id);

        asio::awaitable<std::optional<fetch_result>> run();

       private:
        asio::awaitable<std::error_code> connect();

        asio::awaitable<std::error_code> perform_handshake_start();
        bool init_handshake_material(std::vector<std::uint8_t>& client_random, std::vector<std::uint8_t>& session_id);
        asio::awaitable<std::error_code> send_client_hello_record(const std::vector<std::uint8_t>& client_hello);
        bool validate_server_hello_body(const std::vector<std::uint8_t>& sh_body) const;

        asio::awaitable<std::vector<std::uint8_t>> find_certificate();
        asio::awaitable<bool> append_next_handshake_record(handshake_reassembler& assembler,
                                                           std::vector<std::uint8_t>& pt_buf,
                                                           int record_index,
                                                           std::error_code& ec);
        bool consume_handshake_messages(handshake_reassembler& assembler,
                                        std::vector<std::uint8_t>& msg,
                                        std::vector<std::uint8_t>& cert_msg,
                                        std::error_code& ec);
        bool process_handshake_message(const std::vector<std::uint8_t>& msg, std::vector<std::uint8_t>& cert_msg);

        std::error_code process_server_hello(const std::vector<std::uint8_t>& sh_body);

        asio::awaitable<std::pair<std::error_code, std::vector<std::uint8_t>>> read_record_plaintext();

        bool validate_record_length(std::uint16_t len, std::error_code& out_ec) const;
        asio::awaitable<bool> read_record_body(std::uint16_t len, std::vector<std::uint8_t>& rec, std::error_code& out_ec);
        std::pair<std::uint8_t, std::span<std::uint8_t>> decrypt_application_record(const std::uint8_t head[5],
                                                                                      const std::vector<std::uint8_t>& rec,
                                                                                      std::vector<std::uint8_t>& pt_buf,
                                                                                      std::error_code& out_ec);
        std::pair<std::uint8_t, std::span<std::uint8_t>> handle_record_by_content_type(const std::uint8_t head[5],
                                                                                         const std::vector<std::uint8_t>& rec,
                                                                                         std::vector<std::uint8_t>& pt_buf,
                                                                                         std::error_code& out_ec);

        asio::awaitable<std::pair<std::uint8_t, std::span<std::uint8_t>>> read_record(std::vector<std::uint8_t>& pt_buf, std::error_code& out_ec);

       private:
        mux::connection_context ctx_;
        asio::io_context& io_context_;
        asio::ip::tcp::socket socket_;
        std::string host_;
        std::uint16_t port_;
        std::string sni_;
        server_fingerprint fingerprint_;

        transcript trans_;
        std::uint8_t client_public_[32] = {0};
        std::uint8_t client_private_[32] = {0};

        const EVP_CIPHER* negotiated_cipher_ = nullptr;
        std::vector<std::uint8_t> dec_key_;
        std::vector<std::uint8_t> dec_iv_;
        std::uint64_t seq_ = 0;
        const cipher_context decrypt_ctx_;
    };
};

}    // namespace reality

#endif
