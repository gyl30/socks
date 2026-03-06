#ifndef CERT_FETCHER_H
#define CERT_FETCHER_H

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <expected>
#include <optional>

#include <openssl/types.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "transcript.h"
#include "log_context.h"
#include "cipher_context.h"
#include "site_material.h"

namespace reality
{

struct fetch_error
{
    std::string stage;
    std::string reason;
};

struct fetch_result
{
    site_material material;
};

class handshake_reassembler
{
   public:
    void append(std::span<const std::uint8_t> data);
    bool next(std::vector<std::uint8_t>& out, boost::system::error_code& ec);

   private:
    std::vector<std::uint8_t> buffer_;
};

class cert_fetcher
{
   public:
    static std::string hex(const std::vector<std::uint8_t>& data);
    static std::string hex(const std::uint8_t* data, std::size_t len);

    static boost::asio::awaitable<std::expected<fetch_result, fetch_error>> fetch(boost::asio::io_context& io_context,
                                                                                  std::string host,
                                                                                  std::uint16_t port,
                                                                                  std::string sni,
                                                                                  const std::string& trace_id = "",
                                                                                  std::uint32_t connect_timeout_sec = 10,
                                                                                  std::uint32_t read_timeout_sec = 10,
                                                                                  std::uint32_t write_timeout_sec = 10);

   private:
    class fetch_session
    {
       public:
        fetch_session(boost::asio::io_context& io_context,
                      std::string host,
                      std::uint16_t port,
                      std::string sni,
                      const std::string& trace_id,
                      std::uint32_t connect_timeout_sec = 10,
                      std::uint32_t read_timeout_sec = 10,
                      std::uint32_t write_timeout_sec = 10);

        boost::asio::awaitable<std::expected<fetch_result, fetch_error>> run();

       private:
        boost::asio::awaitable<boost::system::error_code> connect();

        boost::asio::awaitable<boost::system::error_code> perform_handshake_start();
        bool init_handshake_material(std::vector<std::uint8_t>& client_random, std::vector<std::uint8_t>& session_id);
        boost::asio::awaitable<boost::system::error_code> send_client_hello_record(const std::vector<std::uint8_t>& client_hello);
        [[nodiscard]] bool validate_server_hello_body(const std::vector<std::uint8_t>& sh_body) const;

        boost::asio::awaitable<bool> collect_site_material();
        boost::asio::awaitable<void> append_next_handshake_record(handshake_reassembler& assembler,
                                                                  std::vector<std::uint8_t>& pt_buf,
                                                                  int record_index,
                                                                  boost::system::error_code& ec);
        bool consume_handshake_messages(handshake_reassembler& assembler,
                                        std::vector<std::uint8_t>& msg,
                                        boost::system::error_code& ec);
        bool process_handshake_message(const std::vector<std::uint8_t>& msg);

        boost::system::error_code process_server_hello(const std::vector<std::uint8_t>& sh_body);
        [[nodiscard]] std::expected<fetch_result, fetch_error> make_error(std::string stage, std::string reason) const;

        boost::asio::awaitable<std::pair<boost::system::error_code, std::vector<std::uint8_t>>> read_record_plaintext();

        static void validate_record_length(std::uint16_t len, boost::system::error_code& ec);
        boost::asio::awaitable<void> read_record_body(std::uint16_t len, std::vector<std::uint8_t>& rec, boost::system::error_code& ec);
        std::pair<std::uint8_t, std::span<std::uint8_t>> decrypt_application_record(const std::uint8_t head[5],
                                                                                     const std::vector<std::uint8_t>& rec,
                                                                                     std::vector<std::uint8_t>& pt_buf,
                                                                                     boost::system::error_code& ec);
        std::pair<std::uint8_t, std::span<std::uint8_t>> handle_record_by_content_type(const std::uint8_t head[5],
                                                                                        const std::vector<std::uint8_t>& rec,
                                                                                        std::vector<std::uint8_t>& pt_buf,
                                                                                        boost::system::error_code& ec);

        boost::asio::awaitable<std::pair<std::uint8_t, std::span<std::uint8_t>>> read_record(std::vector<std::uint8_t>& pt_buf,
                                                                                              boost::system::error_code& ec);

       private:
        mux::connection_context ctx_;
        boost::asio::io_context& io_context_;
        boost::asio::ip::tcp::socket socket_;
        std::string host_;
        std::uint16_t port_;
        std::string sni_;
        std::uint32_t connect_timeout_sec_ = 10;
        std::uint32_t read_timeout_sec_ = 10;
        std::uint32_t write_timeout_sec_ = 10;
        site_material observed_material_;

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
