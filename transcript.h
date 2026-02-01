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
    transcript();

    void set_protocol_hash(const EVP_MD* new_md);

    void update(const std::vector<uint8_t>& data);

    [[nodiscard]] std::vector<uint8_t> finish() const;

   private:
    const EVP_MD* md_;
    std::vector<uint8_t> buffer_;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
};
}    // namespace reality
#endif
