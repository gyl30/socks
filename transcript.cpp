#include <memory>
#include <vector>
#include <cstdint>

extern "C"
{
#include <openssl/evp.h>
}

#include "transcript.h"

namespace reality
{

transcript::transcript() : md_(EVP_sha256()), ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { (void)EVP_DigestInit_ex(ctx_.get(), md_, nullptr); }

void transcript::set_protocol_hash(const EVP_MD* new_md)
{
    if (new_md == md_)
    {
        return;
    }
    md_ = new_md;
    ctx_ = {EVP_MD_CTX_new(), EVP_MD_CTX_free};
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
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    (void)EVP_MD_CTX_copy(c.get(), ctx_.get());
    std::vector<std::uint8_t> h(EVP_MD_size(md_));
    unsigned int l;
    (void)EVP_DigestFinal_ex(c.get(), h.data(), &l);
    return h;
}

}    // namespace reality
