#ifndef TLS_TRANSCRIPT_H
#define TLS_TRANSCRIPT_H

#include <memory>
#include <vector>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/types.h>
}

namespace tls
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
    bool valid_ = false;
};

}    // namespace tls

#endif
