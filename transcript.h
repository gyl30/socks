#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H

#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/ssl.h>

namespace reality
{
class transcript
{
   public:
    transcript() : md_(EVP_sha256()), ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { EVP_DigestInit_ex(ctx_.get(), md_, nullptr); }

    void set_protocol_hash(const EVP_MD* new_md)
    {
        if (new_md == md_)
        {
            return;
        }
        md_ = new_md;
        ctx_ = {EVP_MD_CTX_new(), EVP_MD_CTX_free};
        EVP_DigestInit_ex(ctx_.get(), md_, nullptr);
        EVP_DigestUpdate(ctx_.get(), buffer_.data(), buffer_.size());
    }

    void update(const std::vector<uint8_t>& data)
    {
        EVP_DigestUpdate(ctx_.get(), data.data(), data.size());
        buffer_.insert(buffer_.end(), data.begin(), data.end());
    }

    [[nodiscard]] std::vector<uint8_t> finish() const
    {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        EVP_MD_CTX_copy(c.get(), ctx_.get());
        std::vector<uint8_t> h(EVP_MD_size(md_));
        unsigned int l;
        EVP_DigestFinal_ex(c.get(), h.data(), &l);
        return h;
    }

   private:
    const EVP_MD* md_;
    std::vector<uint8_t> buffer_;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
};
}    // namespace reality
#endif
