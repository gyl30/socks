// NOLINTBEGIN(performance-unnecessary-value-param)
#include <span>
#include <vector>
#include <cstdint>
#include <utility>

#include <gtest/gtest.h>

#include "mux_protocol.h"
#include "mux_dispatcher.h"

TEST(MuxDispatcherTest, PackAndOnData)
{
    mux::mux_dispatcher dispatcher;

    mux::frame_header received_header;
    std::vector<std::uint8_t> received_payload;

    dispatcher.set_callback(
        [&](const mux::frame_header h, std::vector<std::uint8_t> p)
        {
            received_header = h;
            received_payload = std::move(p);
        });

    const std::vector<std::uint8_t> original_payload = {0xAA, 0xBB, 0xCC};
    const std::uint32_t stream_id = 0x12345678;
    const std::uint8_t cmd = mux::kCmdDat;

    const auto packed = mux::mux_dispatcher::pack(stream_id, cmd, original_payload);

    dispatcher.on_plaintext_data(std::span<const std::uint8_t>(packed.data(), 5));
    dispatcher.on_plaintext_data(std::span<const std::uint8_t>(packed.data() + 5, packed.size() - 5));

    EXPECT_EQ(received_header.stream_id, stream_id);
    EXPECT_EQ(received_header.command, cmd);
    EXPECT_EQ(received_header.length, original_payload.size());
    EXPECT_EQ(received_payload, original_payload);
}

TEST(MuxDispatcherTest, OversizedFrame)
{
    mux::mux_dispatcher dispatcher;
    int call_count = 0;
    dispatcher.set_callback([&](const mux::frame_header, std::vector<std::uint8_t>) { call_count++; });

    std::vector<std::uint8_t> bad_packed = {0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF, mux::kCmdDat};

    dispatcher.on_plaintext_data(bad_packed);
    EXPECT_EQ(call_count, 0);
}

TEST(MuxDispatcherTest, EmptyData)
{
    mux::mux_dispatcher dispatcher;
    dispatcher.on_plaintext_data({});
}

TEST(MuxDispatcherTest, BufferOverflowSetsFlagAndDropsFrame)
{
    mux::mux_dispatcher dispatcher;
    dispatcher.set_max_buffer(4);

    int call_count = 0;
    dispatcher.set_callback([&](const mux::frame_header, std::vector<std::uint8_t>) { call_count++; });

    const auto packed = mux::mux_dispatcher::pack(0x42, mux::kCmdDat, {0x01});
    ASSERT_GT(packed.size(), 4);

    dispatcher.on_plaintext_data(packed);
    EXPECT_TRUE(dispatcher.overflowed());
    EXPECT_EQ(call_count, 0);
}

TEST(MuxDispatcherTest, PartialPayloadWaitsForCompletion)
{
    mux::mux_dispatcher dispatcher;
    int call_count = 0;
    dispatcher.set_callback([&](const mux::frame_header, std::vector<std::uint8_t>) { call_count++; });

    const std::vector<std::uint8_t> payload = {0x10, 0x20, 0x30};
    const auto packed = mux::mux_dispatcher::pack(0x23, mux::kCmdDat, payload);

    ASSERT_GT(packed.size(), mux::kHeaderSize + 1);
    dispatcher.on_plaintext_data(std::span<const std::uint8_t>(packed.data(), mux::kHeaderSize + 1));
    EXPECT_EQ(call_count, 0);

    dispatcher.on_plaintext_data(std::span<const std::uint8_t>(packed.data() + mux::kHeaderSize + 1, packed.size() - (mux::kHeaderSize + 1)));
    EXPECT_EQ(call_count, 1);
}
// NOLINTEND(performance-unnecessary-value-param)
