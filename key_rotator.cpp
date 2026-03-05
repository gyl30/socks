#include <new>
#include <atomic>
#include <chrono>
#include <memory>

extern "C"
{
#include <openssl/crypto.h>
}

#include "log.h"
#include "timeout_io.h"
#include "crypto_util.h"
#include "key_rotator.h"

namespace reality
{
static std::shared_ptr<x25519_keypair> rotator_next_key()
{
    auto deleter = [](x25519_keypair* kp)
    {
        if (kp != nullptr)
        {
            OPENSSL_cleanse(kp->private_key, 32);
            kp->~x25519_keypair();
            ::operator delete(static_cast<void*>(kp), std::nothrow);
        }
    };

    auto* raw_key = new (std::nothrow) x25519_keypair();
    if (raw_key == nullptr)
    {
        LOG_ERROR("key_rotator allocate key failed");
        return nullptr;
    }

    auto new_key = std::shared_ptr<x25519_keypair>(raw_key, deleter);
    if (!reality::crypto_util::generate_x25519_keypair(new_key->public_key, new_key->private_key))
    {
        LOG_ERROR("key_rotator generate key failed");
        return nullptr;
    }
    return new_key;
}

key_rotator::key_rotator(uint64_t interval) : interval_(interval)
{
    current_key_ = rotator_next_key();
    if (current_key_ == nullptr)
    {
        LOG_ERROR("key_rotator initial key generation failed");
    }
}

std::shared_ptr<x25519_keypair> key_rotator::get_current_key()
{
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = mux::timeout_io::now_second();
    if (now > next_rotate_time_)
    {
        current_key_ = rotator_next_key();
        next_rotate_time_ = now + interval_;
    }
    return current_key_;
}

}    // namespace reality
