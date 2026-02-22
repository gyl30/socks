#include <memory>
#include <vector>
#include <utility>
#include <cstdint>
#include <cstddef>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/types.h>
}

#include "log.h"
#include "transcript.h"
#include "crypto_util.h"

namespace reality
{

namespace
{

const EVP_MD* default_digest()
{
    ensure_openssl_initialized();
    return EVP_sha256();
}

EVP_MD_CTX* create_digest_context()
{
    ensure_openssl_initialized();
    return EVP_MD_CTX_new();
}

}    // namespace

transcript::transcript() : md_(default_digest()), ctx_(create_digest_context(), EVP_MD_CTX_free)
{
    if (ctx_ == nullptr || EVP_DigestInit_ex(ctx_.get(), md_, nullptr) != 1)
    {
        LOG_ERROR("transcript digest init failed");
        valid_ = false;
        return;
    }
    valid_ = true;
}

void transcript::set_protocol_hash(const EVP_MD* new_md)
{
    ensure_openssl_initialized();
    if (new_md == nullptr)
    {
        LOG_ERROR("transcript protocol hash is null");
        valid_ = false;
        return;
    }
    if (new_md == md_ && valid_)
    {
        return;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> new_ctx(create_digest_context(), EVP_MD_CTX_free);
    if (new_ctx == nullptr)
    {
        LOG_ERROR("transcript digest context create failed");
        valid_ = false;
        return;
    }
    if (EVP_DigestInit_ex(new_ctx.get(), new_md, nullptr) != 1)
    {
        LOG_ERROR("transcript digest reinit failed");
        valid_ = false;
        return;
    }
    if (!buffer_.empty() && EVP_DigestUpdate(new_ctx.get(), buffer_.data(), buffer_.size()) != 1)
    {
        LOG_ERROR("transcript digest replay failed");
        valid_ = false;
        return;
    }
    md_ = new_md;
    ctx_ = std::move(new_ctx);
    valid_ = true;
}

void transcript::update(const std::vector<std::uint8_t>& data)
{
    buffer_.insert(buffer_.end(), data.begin(), data.end());
    if (!valid_ || data.empty())
    {
        return;
    }
    if (EVP_DigestUpdate(ctx_.get(), data.data(), data.size()) != 1)
    {
        LOG_ERROR("transcript digest update failed");
        valid_ = false;
    }
}

std::vector<std::uint8_t> transcript::finish() const
{
    if (!valid_ || ctx_ == nullptr || md_ == nullptr)
    {
        return {};
    }

    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(create_digest_context(), EVP_MD_CTX_free);
    if (c == nullptr || EVP_MD_CTX_copy(c.get(), ctx_.get()) != 1)
    {
        return {};
    }

    const int hash_len = EVP_MD_size(md_);
    if (hash_len <= 0)
    {
        return {};
    }
    std::vector<std::uint8_t> h(static_cast<std::size_t>(hash_len));
    unsigned int l = 0;
    if (EVP_DigestFinal_ex(c.get(), h.data(), &l) != 1 || l != h.size())
    {
        return {};
    }
    return h;
}

}    // namespace reality
