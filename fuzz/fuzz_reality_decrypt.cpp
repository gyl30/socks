#include <vector>
#include <cstdint>
#include <cstring>
#include <stddef.h>

#include <openssl/evp.h>

#include "reality_engine.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(12, 0x99);

    const EVP_CIPHER* cipher = EVP_aes_128_gcm();

    mux::reality_engine engine(key, iv, key, iv, cipher);

    auto buf = engine.read_buffer(size);
    std::memcpy(buf.data(), data, size);
    engine.commit_read(size);

    auto result = engine.process_available_records(
        [](std::uint8_t content_type, std::span<const std::uint8_t> payload)
        {
            (void)content_type;
            (void)payload;
        });
    (void)result;

    return 0;
}
