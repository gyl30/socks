#include <span>
#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
extern "C"
{
#include <openssl/evp.h>
}

#include "config.h"
#include "tls/core.h"
#include "vision_tcp.h"
#include "proxy_reality_connection.h"
#include "proxy_stream_relay_transport.h"
#include "reality/session/record_context.h"

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

void append_u16(std::vector<uint8_t>& out, const uint16_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

void append_u24(std::vector<uint8_t>& out, const std::size_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

std::vector<uint8_t> make_tls_record(const uint8_t type, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> record;
    record.reserve(tls::kTlsRecordHeaderSize + payload.size());
    record.push_back(type);
    record.push_back(0x03);
    record.push_back(0x03);
    append_u16(record, static_cast<uint16_t>(payload.size()));
    record.insert(record.end(), payload.begin(), payload.end());
    return record;
}

std::vector<uint8_t> make_client_hello_record()
{
    return make_tls_record(tls::kContentTypeHandshake, std::vector<uint8_t>{0x01, 0x00, 0x00, 0x00});
}

std::vector<uint8_t> append_all(std::vector<uint8_t> out, const std::vector<uint8_t>& tail)
{
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

std::vector<uint8_t> make_server_hello_message(const bool tls13, const uint16_t cipher_suite)
{
    std::vector<uint8_t> body;
    append_u16(body, tls::consts::kVer12);
    body.insert(body.end(), 32, 0x11);
    body.push_back(0x00);
    append_u16(body, cipher_suite);
    body.push_back(0x00);

    std::vector<uint8_t> extensions;
    if (tls13)
    {
        append_u16(extensions, tls::consts::ext::kSupportedVersions);
        append_u16(extensions, 2);
        append_u16(extensions, tls::consts::kVer13);
    }
    append_u16(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(0x02);
    append_u24(handshake, body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<uint8_t> make_server_hello_record(const bool tls13, const uint16_t cipher_suite)
{
    const auto handshake = make_server_hello_message(tls13, cipher_suite);
    return make_tls_record(tls::kContentTypeHandshake, handshake);
}

std::vector<uint8_t> make_application_record(const std::size_t payload_size = 3U)
{
    return make_tls_record(tls::kContentTypeApplicationData, std::vector<uint8_t>(payload_size, 0x17));
}

reality::traffic_key_material make_key_material(const uint8_t key_seed, const uint8_t iv_seed)
{
    reality::traffic_key_material material;
    material.key.assign(16, key_seed);
    material.iv.assign(12, iv_seed);
    return material;
}

reality::reality_record_context make_record_context()
{
    reality::reality_record_context context;
    context.negotiated.cipher = EVP_aes_128_gcm();
    context.read_keys = make_key_material(0x11, 0x22);
    context.write_keys = make_key_material(0x11, 0x22);
    return context;
}

struct connection_pair
{
    std::shared_ptr<relay::proxy_reality_connection> client;
    std::shared_ptr<relay::proxy_reality_connection> server;
};

boost::asio::awaitable<connection_pair> make_connection_pair(const relay::config& cfg)
{
    auto executor = co_await boost::asio::this_coro::executor;
    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor acceptor(executor);
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    if (!require(!ec, "vision acceptor open failed"))
    {
        co_return connection_pair{};
    }
    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), ec);
    if (!require(!ec, "vision acceptor bind failed"))
    {
        co_return connection_pair{};
    }
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (!require(!ec, "vision acceptor listen failed"))
    {
        co_return connection_pair{};
    }

    const auto endpoint = acceptor.local_endpoint(ec);
    if (!require(!ec, "vision acceptor endpoint failed"))
    {
        co_return connection_pair{};
    }

    boost::asio::ip::tcp::socket client_socket(executor);
    co_await client_socket.async_connect(endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "vision client connect failed"))
    {
        co_return connection_pair{};
    }

    auto server_socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "vision server accept failed"))
    {
        co_return connection_pair{};
    }

    co_return connection_pair{
        .client = std::make_shared<relay::proxy_reality_connection>(std::move(client_socket), make_record_context(), cfg, 1),
        .server = std::make_shared<relay::proxy_reality_connection>(std::move(server_socket), make_record_context(), cfg, 2),
    };
}

bool test_block_codec()
{
    using relay::vision::block;
    using relay::vision::block_parser;
    using relay::vision::command;
    using relay::vision::encode_block;
    using relay::vision::encode_block_with_padding;
    using relay::vision::padding_mode;
    using relay::vision::parse_status;

    const std::vector<uint8_t> content{'h', 'e', 'l', 'l', 'o'};
    const std::vector<uint8_t> padding{0xAA, 0xBB};
    std::vector<uint8_t> encoded;
    block parsed;
    boost::system::error_code ec;

    bool ok = require(encode_block_with_padding(command::kContinue, content, padding, encoded), "fixed padding encode failed") &&
              require(encoded.size() == relay::vision::kBlockHeaderSize + content.size() + padding.size(), "encoded block size mismatch");

    block_parser parser;
    parser.append(std::span<const uint8_t>(encoded.data(), 3));
    ok = ok && require(parser.next(parsed, ec) == parse_status::kNeedMore && !ec, "partial block should need more");
    parser.append(std::span<const uint8_t>(encoded.data() + 3, encoded.size() - 3));
    ok = ok && require(parser.next(parsed, ec) == parse_status::kBlock && !ec, "complete block parse failed") &&
         require(parsed.cmd == command::kContinue, "parsed command mismatch") && require(parsed.content == content, "parsed content mismatch") &&
         require(parser.empty(), "parser should consume parsed block");

    std::vector<uint8_t> random_encoded;
    ok = ok && require(encode_block(command::kContinue, content, padding_mode::kShort, random_encoded, ec) && !ec, "random padding encode failed") &&
         require(random_encoded.size() <= relay::vision::kBlockHeaderSize + content.size() + 255U, "short padded block should stay bounded");
    ok = ok && require(encode_block(command::kContinue, content, padding_mode::kLong, random_encoded, ec) && !ec, "long padding encode failed") &&
         require(random_encoded.size() >= relay::vision::kBlockHeaderSize + 900U, "long padded block should hide small payloads") &&
         require(random_encoded.size() <= relay::vision::kBlockHeaderSize + 1399U, "long padded block should stay bounded");

    const std::vector<uint8_t> oversized(tls::kMaxTlsApplicationDataPayloadLen, 0x42);
    ok = ok && require(!encode_block(command::kContinue, oversized, padding_mode::kNone, random_encoded, ec), "oversized content should fail");

    const std::vector<uint8_t> unknown_cmd{0xFE, 0x00, 0x00, 0x00, 0x00};
    parser.append(unknown_cmd);
    ok = ok && require(parser.next(parsed, ec) == parse_status::kError && ec, "unknown command should fail");
    return ok;
}

bool test_tls_tracker_direct()
{
    using relay::vision::command;
    using relay::vision::direction;
    using relay::vision::tls_tracker;

    tls_tracker tracker;
    const auto client_hello = make_client_hello_record();
    auto segments = tracker.process(direction::kClientToServer, client_hello);
    bool ok = require(segments.size() == 1 && segments[0].cmd == command::kContinue, "client hello should continue") &&
              require(!tracker.tls13_confirmed(), "client hello alone must not confirm tls13");

    const auto server_hello = make_server_hello_record(true, tls::consts::cipher::kTlsAes128GcmSha256);
    segments = tracker.process(direction::kServerToClient, server_hello);
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kContinue, "server hello should continue") &&
         require(tracker.tls13_confirmed(), "tls13 server hello should confirm tls13");

    const auto app = make_application_record();
    segments = tracker.process(direction::kClientToServer, app);
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kDirect, "client app data should direct") &&
         require(segments[0].switch_to_raw_after, "direct segment should switch to raw") &&
         require(tracker.direct_write_mode(direction::kClientToServer), "tracker should remember client direct mode");

    segments = tracker.process(direction::kServerToClient, app);
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kDirect, "server app data should direct") &&
         require(tracker.direct_write_mode(direction::kServerToClient), "tracker should remember server direct mode");

    tls_tracker ccm_tracker;
    segments = ccm_tracker.process(direction::kClientToServer, client_hello);
    segments = ccm_tracker.process(direction::kServerToClient, make_server_hello_record(true, 0x1304));
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kContinue, "ccm tls13 should remain directable") &&
         require(ccm_tracker.tls13_confirmed(), "ccm tls13 should confirm directable tls13");
    return ok;
}

bool test_tls_tracker_direct_boundaries()
{
    using relay::vision::command;
    using relay::vision::direction;
    using relay::vision::tls_tracker;

    const auto client_hello = make_client_hello_record();
    const auto server_hello = make_server_hello_record(true, tls::consts::cipher::kTlsAes128GcmSha256);
    const auto app = make_application_record();

    tls_tracker same_chunk_tracker;
    auto segments = same_chunk_tracker.process(direction::kClientToServer, client_hello);
    bool ok = require(segments.size() == 1 && segments[0].cmd == command::kContinue, "same chunk client hello should continue");
    const auto server_with_app = append_all(server_hello, app);
    segments = same_chunk_tracker.process(direction::kServerToClient, server_with_app);
    ok = ok && require(segments.size() == 2, "server hello with app data should split into two segments") &&
         require(segments[0].cmd == command::kContinue && segments[0].content == server_hello, "server hello prefix should stay wrapped") &&
         require(segments[1].cmd == command::kDirect && segments[1].content == app, "app data tail should switch to direct") &&
         require(segments[1].switch_to_raw_after, "app data tail should switch writer to raw");

    tls_tracker partial_app_tracker;
    segments = partial_app_tracker.process(direction::kClientToServer, client_hello);
    segments = partial_app_tracker.process(direction::kServerToClient, server_hello);
    auto partial_app = make_application_record(32U);
    partial_app.resize(tls::kTlsRecordHeaderSize + 2U);
    segments = partial_app_tracker.process(direction::kClientToServer, partial_app);
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kContinue,
                       "partial app data header should stay wrapped until a full record is available") &&
         require(segments[0].content == partial_app, "partial app wrapped content mismatch") &&
         require(!segments[0].switch_to_raw_after, "partial app data should not switch writer to raw");

    tls_tracker tiny_prefix_tracker;
    segments = tiny_prefix_tracker.process(direction::kClientToServer, client_hello);
    segments = tiny_prefix_tracker.process(direction::kServerToClient, server_hello);
    const auto full_app = make_application_record(32U);
    for (std::size_t prefix_len = 1; prefix_len < tls::kTlsRecordHeaderSize; ++prefix_len)
    {
        const std::vector<uint8_t> app_prefix(full_app.begin(), full_app.begin() + static_cast<std::ptrdiff_t>(prefix_len));
        segments = tiny_prefix_tracker.process(direction::kClientToServer, app_prefix);
        ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kContinue,
                           "partial app header prefix should stay wrapped") &&
             require(segments[0].content == app_prefix, "partial app header prefix content mismatch") &&
             require(!segments[0].switch_to_raw_after, "partial app header prefix should not switch writer to raw");
        tiny_prefix_tracker = tls_tracker{};
        segments = tiny_prefix_tracker.process(direction::kClientToServer, client_hello);
        segments = tiny_prefix_tracker.process(direction::kServerToClient, server_hello);
    }

    tls_tracker same_chunk_prefix_tracker;
    segments = same_chunk_prefix_tracker.process(direction::kClientToServer, client_hello);
    const std::vector<uint8_t> app_prefix(full_app.begin(), full_app.begin() + 3);
    segments = same_chunk_prefix_tracker.process(direction::kServerToClient, append_all(server_hello, app_prefix));
    ok = ok && require(segments.size() == 1, "server hello with partial app header should stay fully wrapped") &&
         require(segments[0].cmd == command::kContinue && segments[0].content == append_all(server_hello, app_prefix),
                 "server hello with partial app header should remain wrapped as one segment") &&
         require(!segments[0].switch_to_raw_after, "partial app header tail should not switch writer to raw");

    tls_tracker trailing_partial_tracker;
    segments = trailing_partial_tracker.process(direction::kClientToServer, client_hello);
    segments = trailing_partial_tracker.process(direction::kServerToClient, server_hello);
    const auto second_partial = std::vector<uint8_t>(full_app.begin(), full_app.begin() + static_cast<std::ptrdiff_t>(tls::kTlsRecordHeaderSize + 1U));
    segments = trailing_partial_tracker.process(direction::kClientToServer, append_all(full_app, second_partial));
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kContinue,
                       "complete app record followed by partial app record should stay wrapped") &&
         require(segments[0].content == append_all(full_app, second_partial), "trailing partial app content mismatch") &&
         require(!segments[0].switch_to_raw_after, "trailing partial app should not switch writer to raw");

    tls_tracker fragmented_tracker;
    segments = fragmented_tracker.process(direction::kClientToServer, client_hello);
    const auto handshake = make_server_hello_message(true, tls::consts::cipher::kTlsAes128GcmSha256);
    const std::size_t split_pos = 8U;
    const std::vector<uint8_t> first_payload(handshake.begin(), handshake.begin() + static_cast<std::ptrdiff_t>(split_pos));
    const std::vector<uint8_t> second_payload(handshake.begin() + static_cast<std::ptrdiff_t>(split_pos), handshake.end());
    const auto first_record = make_tls_record(tls::kContentTypeHandshake, first_payload);
    const auto second_record = make_tls_record(tls::kContentTypeHandshake, second_payload);
    segments = fragmented_tracker.process(direction::kServerToClient, first_record);
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kContinue, "fragmented server hello first record should continue") &&
         require(!fragmented_tracker.tls13_confirmed(), "fragmented server hello should wait for full message");
    segments = fragmented_tracker.process(direction::kServerToClient, append_all(second_record, app));
    ok = ok && require(segments.size() == 2, "fragmented server hello tail should split app data") &&
         require(segments[0].cmd == command::kContinue && segments[0].content == second_record, "fragmented server hello tail should stay wrapped") &&
         require(segments[1].cmd == command::kDirect && segments[1].content == app, "fragmented server hello app tail should direct") &&
         require(fragmented_tracker.tls13_confirmed(), "fragmented server hello should confirm tls13");

    return ok;
}

bool test_tls_tracker_rejects()
{
    using relay::vision::command;
    using relay::vision::direction;
    using relay::vision::tls_tracker;

    tls_tracker http_tracker;
    const std::vector<uint8_t> http{'G', 'E', 'T', ' ', '/'};
    auto segments = http_tracker.process(direction::kClientToServer, http);
    bool ok = require(segments.size() == 1 && segments[0].cmd == command::kEnd, "plain http should end vision") &&
              require(segments[0].switch_to_outer_plain_after, "plain http should switch to outer plain") &&
              require(http_tracker.direct_disabled(), "plain http should disable direct");

    tls_tracker tls12_tracker;
    segments = tls12_tracker.process(direction::kClientToServer, make_client_hello_record());
    segments = tls12_tracker.process(direction::kServerToClient, make_server_hello_record(false, 0xC02F));
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kEnd, "tls12 server hello should end vision") &&
         require(tls12_tracker.direct_disabled(), "tls12 server hello should disable direct");

    tls_tracker ccm_tracker;
    segments = ccm_tracker.process(direction::kClientToServer, make_client_hello_record());
    segments = ccm_tracker.process(direction::kServerToClient, make_server_hello_record(true, 0x1305));
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kEnd, "ccm8 tls13 should end vision") &&
         require(!ccm_tracker.tls13_confirmed(), "ccm8 should not confirm directable tls13");

    tls_tracker unknown_cipher_tracker;
    segments = unknown_cipher_tracker.process(direction::kClientToServer, make_client_hello_record());
    segments = unknown_cipher_tracker.process(direction::kServerToClient, make_server_hello_record(true, 0x1306));
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kEnd, "unknown tls13 cipher should end vision") &&
         require(!unknown_cipher_tracker.tls13_confirmed(), "unknown tls13 cipher should not confirm directable tls13");

    tls_tracker server_first_tracker;
    segments = server_first_tracker.process(direction::kServerToClient, make_server_hello_record(true, tls::consts::cipher::kTlsAes128GcmSha256));
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kEnd, "server hello without client hello should end vision") &&
         require(server_first_tracker.direct_disabled(), "server first handshake should disable direct");
    return ok;
}

bool test_tls_tracker_observe()
{
    using relay::vision::command;
    using relay::vision::direction;
    using relay::vision::tls_tracker;

    tls_tracker tracker;
    tracker.observe(direction::kClientToServer, make_client_hello_record());
    bool ok = require(!tracker.tls13_confirmed(), "observed client hello alone must not confirm tls13");
    tracker.observe(direction::kServerToClient, make_server_hello_record(true, tls::consts::cipher::kTlsAes128GcmSha256));
    ok = ok && require(tracker.tls13_confirmed(), "observed server hello should confirm tls13");

    const auto app = make_application_record();
    const auto segments = tracker.process(direction::kServerToClient, app);
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kDirect, "observed tls13 state should direct app data");
    return ok;
}

boost::asio::awaitable<bool> test_vision_stream_close_aborts_stale_reads()
{
    relay::config cfg;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;

    bool ok = true;
    auto executor = co_await boost::asio::this_coro::executor;

    auto run_close_race = [&](const relay::vision::command command) -> boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>>
    {
        auto pair = co_await make_connection_pair(cfg);
        if (pair.client == nullptr || pair.server == nullptr)
        {
            co_return std::pair<boost::system::error_code, std::size_t>{boost::asio::error::not_connected, 0};
        }
        std::vector<uint8_t> block;
        boost::system::error_code write_ec;
        if (!relay::vision::encode_block(command, std::span<const uint8_t>{}, relay::vision::padding_mode::kNone, block, write_ec) || write_ec)
        {
            co_return std::pair<boost::system::error_code, std::size_t>{boost::asio::error::invalid_argument, 0};
        }
        co_await pair.server->write(block, write_ec);
        if (write_ec)
        {
            co_return std::pair<boost::system::error_code, std::size_t>{write_ec, 0};
        }

        relay::vision_connection_tcp_stream stream(pair.client,
                                                   relay::vision::direction::kClientToServer,
                                                   relay::vision::direction::kServerToClient);
        boost::asio::co_spawn(
            executor,
            [&stream]() -> boost::asio::awaitable<void>
            {
                auto timer_executor = co_await boost::asio::this_coro::executor;
                boost::asio::steady_timer timer(timer_executor);
                timer.expires_after(std::chrono::milliseconds(10));
                co_await timer.async_wait(boost::asio::use_awaitable);
                co_await stream.close();
            },
            boost::asio::detached);

        std::array<uint8_t, 16> buffer{};
        boost::system::error_code read_ec;
        const auto bytes_read = co_await stream.read(std::span<uint8_t>(buffer), cfg.timeout.read, read_ec);
        pair.server->close(write_ec);
        co_return std::pair<boost::system::error_code, std::size_t>{read_ec, bytes_read};
    };

    auto [raw_ec, raw_bytes] = co_await run_close_race(relay::vision::command::kDirect);
    ok = ok && require(raw_ec == boost::asio::error::operation_aborted && raw_bytes == 0,
                       "direct close race should abort stale raw read");

    auto [outer_ec, outer_bytes] = co_await run_close_race(relay::vision::command::kEnd);
    ok = ok && require(outer_ec == boost::asio::error::operation_aborted && outer_bytes == 0,
                       "end close race should abort stale outer read");

    co_return ok;
}

boost::asio::awaitable<bool> test_vision_stream_direct_read_merges_buffered_raw()
{
    relay::config cfg;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;

    auto pair = co_await make_connection_pair(cfg);
    if (!require(pair.client != nullptr && pair.server != nullptr, "vision direct read merge connection pair failed"))
    {
        co_return false;
    }

    const std::vector<uint8_t> direct_payload{'v', 'i', 's'};
    const std::vector<uint8_t> raw_tail{'r', 'a', 'w'};
    std::vector<uint8_t> encoded;
    boost::system::error_code ec;
    if (!require(relay::vision::encode_block(relay::vision::command::kDirect,
                                             std::span<const uint8_t>(direct_payload),
                                             relay::vision::padding_mode::kNone,
                                             encoded,
                                             ec) &&
                     !ec,
                 "vision direct read merge encode failed"))
    {
        co_return false;
    }

    co_await pair.server->write(encoded, ec);
    if (!require(!ec, "vision direct read merge write block failed"))
    {
        co_return false;
    }
    co_await pair.server->enter_raw_write_mode(ec);
    if (!require(!ec, "vision direct read merge enter raw write failed"))
    {
        co_return false;
    }
    co_await pair.server->write_raw(raw_tail, ec);
    if (!require(!ec, "vision direct read merge write raw tail failed"))
    {
        co_return false;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::milliseconds(10));
    co_await timer.async_wait(boost::asio::use_awaitable);

    relay::vision_connection_tcp_stream stream(pair.client,
                                               relay::vision::direction::kClientToServer,
                                               relay::vision::direction::kServerToClient);
    std::array<uint8_t, 16> buffer{};
    boost::system::error_code read_ec;
    const auto bytes_read = co_await stream.read(std::span<uint8_t>(buffer), cfg.timeout.read, read_ec);

    std::vector<uint8_t> expected = direct_payload;
    expected.insert(expected.end(), raw_tail.begin(), raw_tail.end());
    bool ok = require(!read_ec, "vision direct read merge read failed") &&
              require(bytes_read == expected.size(), "vision direct read merge size mismatch") &&
              require(std::equal(expected.begin(), expected.end(), buffer.begin()), "vision direct read merge content mismatch");

    co_await stream.close();
    pair.server->close(ec);
    co_return ok;
}

}    // namespace

int main()
{
    boost::asio::io_context io_context;
    auto async_ok = boost::asio::co_spawn(io_context, test_vision_stream_close_aborts_stale_reads(), boost::asio::use_future);
    auto async_merge_ok = boost::asio::co_spawn(io_context, test_vision_stream_direct_read_merges_buffered_raw(), boost::asio::use_future);
    const bool ok = test_block_codec() && test_tls_tracker_direct() && test_tls_tracker_direct_boundaries() && test_tls_tracker_rejects() &&
                    test_tls_tracker_observe();
    io_context.run();
    return ok && async_ok.get() && async_merge_ok.get() ? 0 : 1;
}
