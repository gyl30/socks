#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H

#include <memory>
#include <vector>
#include <cstdint>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/types.h>
}

namespace reality
{

class transcript
{
   public:
    transcript();

    void set_protocol_hash(const EVP_MD* new_md);

    void update(const std::vector<std::uint8_t>& data);

    [[nodiscard]] std::vector<std::uint8_t> finish() const;

   private:
    const EVP_MD* md_;
    std::vector<std::uint8_t> buffer_;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
    bool valid_ = false;
};

}    // namespace reality

#endif
