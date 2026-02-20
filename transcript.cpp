#include <openssl/types.h>
#include <memory>
#include <vector>
#include <cstdint>

extern "C"
{
#include <openssl/evp.h>
}

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
    (void)EVP_DigestInit_ex(ctx_.get(), md_, nullptr);
}

void transcript::set_protocol_hash(const EVP_MD* new_md)
{
    ensure_openssl_initialized();
    if (new_md == md_)
    {
        return;
    }
    md_ = new_md;
    ctx_ = {create_digest_context(), EVP_MD_CTX_free};
    (void)EVP_DigestInit_ex(ctx_.get(), md_, nullptr);
    (void)EVP_DigestUpdate(ctx_.get(), buffer_.data(), buffer_.size());
}

void transcript::update(const std::vector<std::uint8_t>& data)
{
    (void)EVP_DigestUpdate(ctx_.get(), data.data(), data.size());
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

std::vector<std::uint8_t> transcript::finish() const
{
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(create_digest_context(), EVP_MD_CTX_free);
    (void)EVP_MD_CTX_copy(c.get(), ctx_.get());
    const int hash_len = EVP_MD_size(md_);
    if (hash_len <= 0)
    {
        return {};
    }
    std::vector<std::uint8_t> h(static_cast<std::size_t>(hash_len));
    unsigned int l;
    (void)EVP_DigestFinal_ex(c.get(), h.data(), &l);
    return h;
}

}    // namespace reality
