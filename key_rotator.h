#ifndef KEY_ROTATOR_H
#define KEY_ROTATOR_H

#include <memory>
#include "log.h"
#include "crypto_util.h"

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
    key_rotator()
    {
        if (!rotate())
        {
            LOG_ERROR("key_rotator initial key generation failed");
        }
    }

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
    bool rotate()
    {
        auto deleter = [](x25519_keypair* kp)
        {
            if (kp)
            {
                OPENSSL_cleanse(kp->private_key, 32);
                delete kp;
            }
        };
        auto new_key = std::shared_ptr<x25519_keypair>(new x25519_keypair(), deleter);
        if (!reality::crypto_util::generate_x25519_keypair(new_key->public_key, new_key->private_key))
        {
            LOG_ERROR("key_rotator generate key failed");
            return false;
        }
        std::atomic_store_explicit(&current_key_, new_key, std::memory_order_release);
        next_rotate_time_.store(std::chrono::steady_clock::now() + std::chrono::seconds(60), std::memory_order_relaxed);
        return true;
    }

   private:
    std::mutex mutex_;
    std::shared_ptr<x25519_keypair> current_key_;
    std::atomic<std::chrono::steady_clock::time_point> next_rotate_time_;
};
}    // namespace reality
#endif
