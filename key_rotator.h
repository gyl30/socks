#ifndef KEY_ROTATOR_H
#define KEY_ROTATOR_H

#include <memory>

namespace reality
{

struct x25519_keypair
{
    uint8_t public_key[32];
    uint8_t private_key[32];
};

class key_rotator
{
   public:
    key_rotator() { rotate(); }

    std::shared_ptr<x25519_keypair> get_current_key()
    {
        if (const auto now = std::chrono::steady_clock::now(); now > next_rotate_time_.load(std::memory_order_relaxed))
        {
            const std::scoped_lock lock(mutex_);
            if (now > next_rotate_time_.load(std::memory_order_relaxed))
            {
                rotate();
            }
        }
        return std::atomic_load_explicit(&current_key_, std::memory_order_acquire);
    }

   private:
    void rotate()
    {
        auto new_key = std::make_shared<x25519_keypair>();
        reality::crypto_util::generate_x25519_keypair(new_key->public_key, new_key->private_key);
        std::atomic_store_explicit(&current_key_, new_key, std::memory_order_release);
        next_rotate_time_.store(std::chrono::steady_clock::now() + std::chrono::seconds(60), std::memory_order_relaxed);
    }

   private:
    std::mutex mutex_;
    std::shared_ptr<x25519_keypair> current_key_;
    std::atomic<std::chrono::steady_clock::time_point> next_rotate_time_;
};
}    // namespace reality
#endif
