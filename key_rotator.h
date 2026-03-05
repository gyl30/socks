#ifndef KEY_ROTATOR_H
#define KEY_ROTATOR_H

#include <memory>
#include <cstdint>

namespace reality
{

struct x25519_keypair
{
    std::uint8_t public_key[32];
    std::uint8_t private_key[32];
};

class key_rotator
{
   public:
    explicit key_rotator(uint64_t interval = 60);

    [[nodiscard]] std::shared_ptr<x25519_keypair> get_current_key();

   private:
    std::mutex mutex_;
    uint64_t interval_ = 60;
    uint64_t next_rotate_time_ = 0;
    std::shared_ptr<x25519_keypair> current_key_{nullptr};
};

}    // namespace reality

#endif
