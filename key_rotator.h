#ifndef KEY_ROTATOR_H
#define KEY_ROTATOR_H

#include <atomic>
#include <chrono>
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
    explicit key_rotator(std::chrono::seconds interval = std::chrono::seconds(60));

    [[nodiscard]] std::shared_ptr<x25519_keypair> get_current_key();

   private:
    bool rotate();

   private:
    std::chrono::seconds interval_;
    std::shared_ptr<x25519_keypair> current_key_;
    std::atomic<bool> rotating_{false};
    std::atomic<std::chrono::steady_clock::time_point> next_rotate_time_{std::chrono::steady_clock::time_point::min()};
};

}    // namespace reality

#endif
