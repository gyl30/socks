#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include <boost/system/error_code.hpp>

#include "tls/core.h"
#include "vision_tcp.h"

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
    ok = ok && require(encode_block(command::kContinue, content, padding_mode::kLong, random_encoded, ec) && !ec, "random padding encode failed") &&
         require(random_encoded.size() <= tls::kMaxTlsApplicationDataPayloadLen, "random padded block too large");

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
    ok = ok && require(segments.size() == 1 && segments[0].cmd == command::kDirect, "partial app data header should direct immediately") &&
         require(segments[0].content == partial_app, "partial app direct content mismatch") &&
         require(segments[0].switch_to_raw_after, "partial app data should switch writer to raw");

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

}    // namespace

int main()
{
    const bool ok = test_block_codec() && test_tls_tracker_direct() && test_tls_tracker_direct_boundaries() && test_tls_tracker_rejects() &&
                    test_tls_tracker_observe();
    return ok ? 0 : 1;
}
