#include <atomic>
#include <chrono>
#include <memory>
#include <new>

extern "C"
{
#include <openssl/crypto.h>
}

#include "log.h"
#include "crypto_util.h"
#include "key_rotator.h"

namespace reality
{

key_rotator::key_rotator(std::chrono::seconds interval) : interval_(interval)
{
    if (!rotate())
    {
        LOG_ERROR("key_rotator initial key generation failed");
    }
}

std::shared_ptr<x25519_keypair> key_rotator::get_current_key()
{
    const auto now = std::chrono::steady_clock::now();
    if (now > next_rotate_time_.load(std::memory_order_relaxed))
    {
        bool expected = false;
        if (rotating_.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_relaxed))
        {
            if (now > next_rotate_time_.load(std::memory_order_relaxed))
            {
                (void)rotate();
            }
            rotating_.store(false, std::memory_order_release);
        }
    }

    auto key = std::atomic_load_explicit(&current_key_, std::memory_order_acquire);
    if (key != nullptr)
    {
        return key;
    }

    bool expected = false;
    if (rotating_.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_relaxed))
    {
        (void)rotate();
        rotating_.store(false, std::memory_order_release);
    }
    return std::atomic_load_explicit(&current_key_, std::memory_order_acquire);
}

bool key_rotator::rotate()
{
    auto deleter = [](x25519_keypair* kp)
    {
        if (kp != nullptr)
        {
            OPENSSL_cleanse(kp->private_key, 32);
            delete kp;
        }
    };

    auto* raw_key = new (std::nothrow) x25519_keypair();
    if (raw_key == nullptr)
    {
        LOG_ERROR("key_rotator allocate key failed");
        return false;
    }

    const auto new_key = std::shared_ptr<x25519_keypair>(raw_key, deleter);
    if (!reality::crypto_util::generate_x25519_keypair(new_key->public_key, new_key->private_key))
    {
        LOG_ERROR("key_rotator generate key failed");
        return false;
    }

    std::atomic_store_explicit(&current_key_, new_key, std::memory_order_release);
    next_rotate_time_.store(std::chrono::steady_clock::now() + interval_, std::memory_order_relaxed);
    return true;
}

}    // namespace reality
