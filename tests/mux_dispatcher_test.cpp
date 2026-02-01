#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mux_dispatcher.h"

using namespace mux;
using testing::_;
using testing::SaveArg;

TEST(MuxDispatcherTest, PackAndOnData) {
    mux_dispatcher dispatcher;
    
    mux::frame_header received_header;
    std::vector<uint8_t> received_payload;
    
    dispatcher.set_callback([&](mux::frame_header h, std::vector<uint8_t> p) {
        received_header = h;
        received_payload = std::move(p);
    });

    std::vector<uint8_t> original_payload = {0xAA, 0xBB, 0xCC};
    uint32_t stream_id = 0x12345678;
    uint8_t cmd = CMD_DAT;

    auto packed = mux_dispatcher::pack(stream_id, cmd, original_payload);
    
    // 模拟分块接收
    dispatcher.on_plaintext_data(std::span<const uint8_t>(packed.data(), 5));
    dispatcher.on_plaintext_data(std::span<const uint8_t>(packed.data() + 5, packed.size() - 5));

    EXPECT_EQ(received_header.stream_id, stream_id);
    EXPECT_EQ(received_header.command, cmd);
    EXPECT_EQ(received_header.length, original_payload.size());
    EXPECT_EQ(received_payload, original_payload);
}
