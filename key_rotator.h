#ifndef KEY_ROTATOR_H
#define KEY_ROTATOR_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>

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
    key_rotator();

    [[nodiscard]] std::shared_ptr<x25519_keypair> get_current_key();

   private:
    bool rotate();

   private:
    std::mutex mutex_;
    std::shared_ptr<x25519_keypair> current_key_;
    std::atomic<std::chrono::steady_clock::time_point> next_rotate_time_;
};

}    // namespace reality

#endif