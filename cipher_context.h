#ifndef CIPHER_CONTEXT_H
#define CIPHER_CONTEXT_H

#include "reality_core.h"

namespace reality
{
class cipher_context
{
   public:
    cipher_context() : ctx_(EVP_CIPHER_CTX_new()) {}

    cipher_context(const cipher_context&) = delete;
    cipher_context& operator=(const cipher_context&) = delete;
    cipher_context(cipher_context&&) = default;

    [[nodiscard]] EVP_CIPHER_CTX* get() const { return ctx_.get(); }
    [[nodiscard]] bool valid() const { return ctx_ != nullptr; }

    [[nodiscard]] bool init(bool encrypt, const EVP_CIPHER* cipher, const uint8_t* key, const uint8_t* iv, size_t iv_len) const
    {
        if (!valid())
        {
            return false;
        }

        if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
        {
            int res;
            if (encrypt)
            {
                res = EVP_EncryptInit_ex(ctx_.get(), cipher, nullptr, nullptr, nullptr);
            }
            else
            {
                res = EVP_DecryptInit_ex(ctx_.get(), cipher, nullptr, nullptr, nullptr);
            }

            if (res != 1)
            {
                return false;
            }

            res = EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv_len), nullptr);
            if (res != 1)
            {
                return false;
            }

            if (encrypt)
            {
                res = EVP_EncryptInit_ex(ctx_.get(), nullptr, nullptr, key, iv);
            }
            else
            {
                res = EVP_DecryptInit_ex(ctx_.get(), nullptr, nullptr, key, iv);
            }

            return res == 1;
        }
        int res;
        if (encrypt)
        {
            res = EVP_EncryptInit_ex(ctx_.get(), cipher, nullptr, key, iv);
        }
        else
        {
            res = EVP_DecryptInit_ex(ctx_.get(), cipher, nullptr, key, iv);
        }

        return res == 1;
    }

   private:
    openssl_ptrs::evp_cipher_ctx_ptr ctx_;
};

}    // namespace reality

#endif
