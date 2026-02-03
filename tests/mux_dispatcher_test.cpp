#include <span>
#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mux_dispatcher.h"

TEST(MuxDispatcherTest, PackAndOnData)
{
    mux::mux_dispatcher dispatcher;

    mux::frame_header received_header;
    std::vector<uint8_t> received_payload;

    dispatcher.set_callback(
        [&](mux::frame_header h, std::vector<uint8_t> p)
        {
            received_header = h;
            received_payload = std::move(p);
        });

    const std::vector<uint8_t> original_payload = {0xAA, 0xBB, 0xCC};
    const uint32_t stream_id = 0x12345678;
    const uint8_t cmd = mux::CMD_DAT;

    auto packed = mux::mux_dispatcher::pack(stream_id, cmd, original_payload);

    dispatcher.on_plaintext_data(std::span<const uint8_t>(packed.data(), 5));
    dispatcher.on_plaintext_data(std::span<const uint8_t>(packed.data() + 5, packed.size() - 5));

    EXPECT_EQ(received_header.stream_id, stream_id);
    EXPECT_EQ(received_header.command, cmd);
    EXPECT_EQ(received_header.length, original_payload.size());
    EXPECT_EQ(received_payload, original_payload);
}
