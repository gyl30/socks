#ifndef CERT_FETCHER_H
#define CERT_FETCHER_H

#include <asio.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "log_context.h"
#include "reality_core.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "transcript.h"

namespace reality
{

struct fetch_result
{
    std::vector<uint8_t> cert_msg;
    server_fingerprint fingerprint;
};

class handshake_reassembler
{
   public:
    void append(std::span<const uint8_t> data);
    bool next(std::vector<uint8_t>& out, std::error_code& ec);

   private:
    std::vector<uint8_t> buffer_;
};

class cert_fetcher
{
   public:
    static std::string hex(const std::vector<uint8_t>& data);
    static std::string hex(const uint8_t* data, size_t len);

    static asio::awaitable<std::optional<fetch_result>> fetch(
        asio::any_io_executor ex, std::string host, uint16_t port, std::string sni, const std::string& trace_id = "");

   private:
    class fetch_session
    {
       public:
        fetch_session(const asio::any_io_executor& ex, std::string host, uint16_t port, std::string sni, const std::string& trace_id);

        asio::awaitable<std::optional<fetch_result>> run();

       private:
        asio::awaitable<std::error_code> connect();

        asio::awaitable<std::error_code> perform_handshake_start();

        asio::awaitable<std::vector<uint8_t>> find_certificate();

        std::error_code process_server_hello(const std::vector<uint8_t>& sh_body);

        asio::awaitable<std::pair<std::error_code, std::vector<uint8_t>>> read_record_plaintext();

        asio::awaitable<std::pair<uint8_t, std::span<uint8_t>>> read_record(std::vector<uint8_t>& pt_buf, std::error_code& out_ec);

       private:
        mux::connection_context ctx_;
        asio::ip::tcp::socket socket_;
        std::string host_;
        uint16_t port_;
        std::string sni_;
        server_fingerprint fingerprint_;

        transcript trans_;
        uint8_t client_pub_[32];
        uint8_t client_priv_[32];

        const EVP_CIPHER* negotiated_cipher_ = nullptr;
        std::vector<uint8_t> dec_key_;
        std::vector<uint8_t> dec_iv_;
        uint64_t seq_ = 0;
        const cipher_context decrypt_ctx_;
    };
};

}    // namespace reality

#endif
