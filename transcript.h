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
    transcript() : ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { EVP_DigestInit(ctx_.get(), EVP_sha256()); }
    void update(const std::vector<uint8_t>& data) const { EVP_DigestUpdate(ctx_.get(), data.data(), data.size()); }
    [[nodiscard]] std::vector<uint8_t> finish() const
    {
        const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        EVP_MD_CTX_copy(c.get(), ctx_.get());
        std::vector<uint8_t> h(EVP_MD_size(EVP_sha256()));
        unsigned int l;
        EVP_DigestFinal(c.get(), h.data(), &l);
        h.resize(l);
        return h;
    }

   private:
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
};

}    // namespace reality
#endif
